package blocklist

// Tests for the RPZ slave (SPEC §7.7). A fake RPZ master runs on a random localhost TCP
// port with miekg/dns; the panel pulls SOA then AXFR/IXFR and writes the transferred
// domains into the paired source's content, which the normal build then turns into a CDB.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const (
	rpzZone  = "rpz.example."
	tsigName = "sync.key."
	tsigB64  = "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0MTI=" // 32 bytes, base64
)

// fakeRPZ is a minimal RPZ master: it answers the zone SOA and serves AXFR (and answers
// IXFR with a full AXFR, which RFC 1995 permits). TSIG is enforced when tsigKey is set.
type fakeRPZ struct {
	mu       sync.Mutex
	serial   uint32
	domains  []string // blocked owners, no trailing dot
	tsigKey  string
	axfrHit  int
	ixfrSeen *uint32 // the client serial from the last IXFR request
	tcp      *dns.Server
	udp      *dns.Server
	addr     string
}

func newFakeRPZ(t *testing.T) *fakeRPZ {
	t.Helper()
	m := &fakeRPZ{serial: 1, domains: []string{"a.com", "b.com"}}
	// Reserve a free port, then serve UDP (SOA) and TCP (transfer) on it.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	m.addr = fmt.Sprintf("127.0.0.1:%d", port)
	mux := dns.NewServeMux()
	mux.HandleFunc(rpzZone, m.handle)
	mux.HandleFunc(".", m.handle)
	m.udp = &dns.Server{PacketConn: pc, Net: "udp", Handler: mux, TsigSecret: m.tsigSecrets()}
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		t.Fatal(err)
	}
	m.tcp = &dns.Server{Listener: ln, Net: "tcp", Handler: mux, TsigSecret: m.tsigSecrets()}
	go m.tcp.ActivateAndServe()
	go m.udp.ActivateAndServe()
	t.Cleanup(func() { _ = m.tcp.Shutdown(); _ = m.udp.Shutdown() })
	return m
}

func (m *fakeRPZ) set(serial uint32, domains ...string) {
	m.mu.Lock()
	m.serial, m.domains = serial, domains
	m.mu.Unlock()
}

// tsigSecrets is the server's TSIG keyring; empty until a test enables TSIG (the servers
// read it per request, so setting m.tsigKey before the first sync is enough).
func (m *fakeRPZ) tsigSecrets() map[string]string {
	return map[string]string{dns.Fqdn(tsigName): tsigB64}
}

func (m *fakeRPZ) handle(w dns.ResponseWriter, req *dns.Msg) {
	if m.tsigKey != "" {
		if err := w.TsigStatus(); err != nil {
			mm := new(dns.Msg)
			mm.SetRcode(req, dns.RcodeNotAuth)
			_ = w.WriteMsg(mm)
			return
		}
	}
	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	switch q.Qtype {
	case dns.TypeSOA:
		out := new(dns.Msg)
		out.SetReply(req)
		out.Authoritative = true
		out.Answer = []dns.RR{m.soa()}
		_ = w.WriteMsg(out)
	case dns.TypeAXFR, dns.TypeIXFR:
		if q.Qtype == dns.TypeIXFR && len(req.Question) == 1 {
			// Record the client serial for assertions; serve a full transfer anyway.
			if soa, ok := soaOf(req); ok {
				m.mu.Lock()
				m.ixfrSeen = &soa
				m.mu.Unlock()
			}
		}
		m.serveTransfer(w, req)
	default:
		out := new(dns.Msg)
		out.SetReply(req)
		_ = w.WriteMsg(out)
	}
}

func soaOf(req *dns.Msg) (uint32, bool) {
	// The IXFR request's authority section carries the client's SOA.
	for _, rr := range req.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

func (m *fakeRPZ) soa() *dns.SOA {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.soaLocked()
}

// soaLocked builds the SOA; the caller holds m.mu.
func (m *fakeRPZ) soaLocked() *dns.SOA {
	return &dns.SOA{Hdr: dns.RR_Header{Name: rpzZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns: "ns1." + rpzZone, Mbox: "hostmaster." + rpzZone, Serial: m.serial,
		Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60}
}

func (m *fakeRPZ) records() []dns.RR {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recordsLocked()
}

// recordsLocked builds the zone RRs; the caller holds m.mu.
func (m *fakeRPZ) recordsLocked() []dns.RR {
	rrs := []dns.RR{m.soaLocked()}
	for _, d := range m.domains {
		rrs = append(rrs, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: d + "." + rpzZone, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: "block.example.",
		})
	}
	rrs = append(rrs, m.soaLocked())
	return rrs
}

// serveTransfer streams a full zone (SOA ... SOA) over the transfer channel.
func (m *fakeRPZ) serveTransfer(w dns.ResponseWriter, req *dns.Msg) {
	m.mu.Lock()
	m.axfrHit++
	recs := m.recordsLocked()
	m.mu.Unlock()
	ch := make(chan *dns.Envelope)
	go func() {
		ch <- &dns.Envelope{RR: recs}
		close(ch)
	}()
	t := &dns.Transfer{}
	if err := t.Out(w, req, ch); err != nil {
		// Out cannot report over the wire; nothing else to do in a fake.
		_ = err
	}
}

// startFakeRPZ builds a fake master and returns it with the host:port clients dial.
func startFakeRPZ(t *testing.T) *fakeRPZ { return newFakeRPZ(t) }

// insertUpstream creates a source of kind rpz_domains plus the paired upstream row and
// returns their ids and the upstream struct the sync uses.
func insertUpstream(t *testing.T, s *Service, master *fakeRPZ, tsig bool) (srcID, upID string) {
	t.Helper()
	ctx := context.Background()
	srcID = addSource(t, s.d.Pool, "komdigi", api.SourceRPZDomains, "", "")
	key, secret := "", ""
	if tsig {
		key, secret = tsigName, tsigB64
	}
	if err := s.d.Pool.QueryRow(ctx, `INSERT INTO rpz_upstreams
		(name, upstream, zone, tsig_key, tsig_secret, interval_s, source_id)
		VALUES ('komdigi', $1, $2, $3, $4, 900, $5) RETURNING id::text`,
		master.addr, rpzZone, key, secret, srcID).Scan(&upID); err != nil {
		t.Fatal(err)
	}
	return srcID, upID
}

// loadUpstream reads the rpzUpstream the sync needs for one id.
func loadUpstream(t *testing.T, s *Service, id string) rpzUpstream {
	t.Helper()
	up, err := scanRPZUpstream(s.d.Pool.QueryRow(context.Background(),
		"SELECT "+rpzCols+" FROM rpz_upstreams u JOIN blocklist_sources s ON s.id = u.source_id WHERE u.id = $1", id))
	if err != nil {
		t.Fatal(err)
	}
	return up
}

// A first sync (serial 0) does a full AXFR and writes the transferred domains into the
// source content; a build then blocks exactly those domains.
func TestRPZSlaveFullTransferFillsSource(t *testing.T) {
	s, pool := newProfileSvc(t)
	master := startFakeRPZ(t)
	master.set(7, "ads.example", "track.example")

	srcID, upID := insertUpstream(t, s, master, false)
	up := loadUpstream(t, s, upID)
	if up.Serial != 0 {
		t.Fatalf("fresh upstream serial = %d, want 0", up.Serial)
	}
	if err := s.rpzSyncUpstream(context.Background(), up, true); err != nil {
		t.Fatal(err)
	}

	var content string
	var serial uint32
	var total int
	if err := pool.QueryRow(context.Background(),
		"SELECT s.content, u.serial, u.total_domains FROM blocklist_sources s JOIN rpz_upstreams u ON u.source_id = s.id WHERE s.id = $1",
		srcID).Scan(&content, &serial, &total); err != nil {
		t.Fatal(err)
	}
	if serial != 7 {
		t.Fatalf("serial = %d, want 7", serial)
	}
	if total != 2 {
		t.Fatalf("total_domains = %d, want 2", total)
	}
	for _, d := range []string{"ads.example", "track.example"} {
		if !strings.Contains(content, d) {
			t.Fatalf("content missing %q:\n%s", d, content)
		}
	}
	if master.axfrHit == 0 {
		t.Fatal("master saw no AXFR")
	}

	// The build treats the slave source like any manual one.
	b := buildScope(t, s, "")
	if cur, err := Current(context.Background(), pool, ""); err != nil || cur == nil || cur.ID != b.ID {
		t.Fatalf("current after RPZ sync/build = %+v, err=%v", cur, err)
	}
	if !blockedIn(t, s, b, "ads.example") || !blockedIn(t, s, b, "track.example") {
		t.Fatalf("build did not block the transferred domains")
	}
}

// When the upstream serial is unchanged, the sync is a no-op: it must not rewrite content
// or bump the sync time again.
func TestRPZSlaveSkipsUnchangedSerial(t *testing.T) {
	s, pool := newProfileSvc(t)
	master := startFakeRPZ(t)
	master.set(5, "keep.example")
	_, upID := insertUpstream(t, s, master, false)

	up := loadUpstream(t, s, upID)
	if err := s.rpzSyncUpstream(context.Background(), up, true); err != nil {
		t.Fatal(err)
	}
	var lastSync1, lastSync2 *string
	if err := pool.QueryRow(context.Background(), "SELECT last_sync_at::text FROM rpz_upstreams WHERE id = $1", upID).Scan(&lastSync1); err != nil {
		t.Fatal(err)
	}

	// Second sync with the same upstream serial: transferRPZ still runs but nothing changes.
	up = loadUpstream(t, s, upID)
	if err := s.rpzSyncUpstream(context.Background(), up, true); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), "SELECT last_sync_at::text FROM rpz_upstreams WHERE id = $1", upID).Scan(&lastSync2); err != nil {
		t.Fatal(err)
	}
	if lastSync1 == nil || lastSync2 == nil || *lastSync1 != *lastSync2 {
		t.Fatalf("last_sync_at moved on an unchanged serial: %v -> %v", lastSync1, lastSync2)
	}
}

// A serial bump uses IXFR (client sends its serial) and replaces the content with the new
// domain set.
func TestRPZSlaveIncrementalUpdate(t *testing.T) {
	s, pool := newProfileSvc(t)
	master := startFakeRPZ(t)
	master.set(1, "old.example")
	_, upID := insertUpstream(t, s, master, false)

	up := loadUpstream(t, s, upID)
	if err := s.rpzSyncUpstream(context.Background(), up, true); err != nil {
		t.Fatal(err)
	}

	master.set(2, "old.example", "new.example")
	up = loadUpstream(t, s, upID)
	if err := s.rpzSyncUpstream(context.Background(), up, true); err != nil {
		t.Fatal(err)
	}

	// The second transfer must have been an IXFR carrying the local serial 1.
	if master.ixfrSeen == nil || *master.ixfrSeen != 1 {
		t.Fatalf("IXFR client serial = %v, want 1", master.ixfrSeen)
	}
	var content string
	var serial uint32
	if err := pool.QueryRow(context.Background(),
		"SELECT s.content, u.serial FROM blocklist_sources s JOIN rpz_upstreams u ON u.source_id = s.id WHERE u.id = $1",
		upID).Scan(&content, &serial); err != nil {
		t.Fatal(err)
	}
	if serial != 2 {
		t.Fatalf("serial = %d, want 2", serial)
	}
	if !strings.Contains(content, "new.example") || !strings.Contains(content, "old.example") {
		t.Fatalf("content after update = %q", content)
	}
}

// A transfer failure is recorded on the upstream's last_error and returned to the caller.
func TestRPZSlaveErrorRecorded(t *testing.T) {
	s, pool := newProfileSvc(t)
	// An upstream pointing at a closed port fails to reach the master.
	srcID := addSource(t, pool, "komdigi", api.SourceRPZDomains, "", "")
	var upID string
	if err := pool.QueryRow(context.Background(), `INSERT INTO rpz_upstreams
		(name, upstream, zone, interval_s, source_id) VALUES ('komdigi', '127.0.0.1:1', $1, 900, $2) RETURNING id::text`,
		rpzZone, srcID).Scan(&upID); err != nil {
		t.Fatal(err)
	}
	up := loadUpstream(t, s, upID)
	if err := s.rpzSyncUpstream(context.Background(), up, true); err == nil {
		t.Fatal("sync against a dead master succeeded")
	}
	var lastErr string
	if err := pool.QueryRow(context.Background(), "SELECT last_error FROM rpz_upstreams WHERE id = $1", upID).Scan(&lastErr); err != nil {
		t.Fatal(err)
	}
	if lastErr == "" {
		t.Fatal("last_error was not recorded")
	}
}

// A failed transfer must never wipe the known-good content: the source keeps its
// old domains, the serial does not advance, and the error is recorded.
func TestRPZSlaveFailedTransferPreservesContent(t *testing.T) {
	s, pool := newProfileSvc(t)
	// Point the upstream at a dead port so the transfer fails.
	srcID := addSource(t, pool, "preserve", api.SourceRPZDomains, "keep.example\n", "")
	var upID string
	if err := pool.QueryRow(context.Background(), `INSERT INTO rpz_upstreams
		(name, upstream, zone, interval_s, source_id) VALUES ('preserve', '127.0.0.1:1', $1, 900, $2) RETURNING id::text`,
		rpzZone, srcID).Scan(&upID); err != nil {
		t.Fatal(err)
	}
	up := loadUpstream(t, s, upID)
	if err := s.rpzSyncUpstream(context.Background(), up, true); err == nil {
		t.Fatal("sync against a dead master succeeded")
	}
	var content string
	var serial uint32
	if err := pool.QueryRow(context.Background(),
		"SELECT s.content, u.serial FROM blocklist_sources s JOIN rpz_upstreams u ON u.source_id = s.id WHERE s.id = $1",
		srcID).Scan(&content, &serial); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "keep.example") {
		t.Fatalf("failed sync wiped content = %q", content)
	}
	if serial != 0 {
		t.Fatalf("failed sync advanced serial to %d", serial)
	}
}

// With TSIG configured, a correctly signed transfer succeeds and a wrong secret fails.
func TestRPZSlaveTSIG(t *testing.T) {
	s, _ := newProfileSvc(t)
	master := startFakeRPZ(t)
	master.tsigKey = tsigName
	master.set(3, "signed.example")

	// Correct secret: the sync succeeds.
	_, upID := insertUpstream(t, s, master, true)
	up := loadUpstream(t, s, upID)
	if err := s.rpzSyncUpstream(context.Background(), up, true); err != nil {
		t.Fatalf("TSIG sync failed: %v", err)
	}
	if !masterSignedOK(t, s) {
		t.Fatal("signed sync did not land")
	}

	// Wrong secret: the transfer must fail.
	bad := rpzUpstream{ID: up.ID, Upstream: master.addr, Zone: rpzZone,
		TSIGKey: tsigName, TSIGSecret: base64.StdEncoding.EncodeToString([]byte("wrongsecretwrongsecretwrongsecret1"))}
	if err := s.rpzSyncUpstream(context.Background(), bad, true); err == nil {
		t.Fatal("sync with a wrong TSIG secret succeeded")
	}
}

func masterSignedOK(t *testing.T, s *Service) bool {
	t.Helper()
	var n int
	if err := s.d.Pool.QueryRow(context.Background(), "SELECT count(*) FROM blocklist_sources WHERE content LIKE '%signed.example%'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// The CRUD HTTP handlers: create pairs a source + upstream, list reads them back, patch
// renames and clears the serial, and delete cascades to the source.
func TestRPZUpstreamCRUDHTTP(t *testing.T) {
	_, pool, call := newHandlerSvc(t)

	var created api.RPZUpstream
	call("POST", "/api/v1/rpz/upstreams",
		`{"name":"komdigi","upstream":"192.0.2.1:53","zone":"rpz.example","interval_s":600,"tsig_key":"sync.key.","tsig_secret":"`+tsigB64+`"}`,
		201, &created)
	if created.ID == "" || !created.HasTSIG || created.Zone != rpzZone || created.IntervalS != 600 {
		t.Fatalf("created upstream = %+v", created)
	}
	if created.SourceID == "" {
		t.Fatal("create did not pair a source")
	}

	var list api.List[api.RPZUpstream]
	call("GET", "/api/v1/rpz/upstreams", "", 200, &list)
	if list.Total != 1 || list.Items[0].Name != "komdigi" {
		t.Fatalf("list = %+v", list)
	}

	// Patch renames and clears TSIG (key "" with no secret).
	var patched api.RPZUpstream
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID, `{"name":"komdigi-2","tsig_key":""}`, 200, &patched)
	if patched.Name != "komdigi-2" || patched.HasTSIG {
		t.Fatalf("patched = %+v", patched)
	}

	// The paired source is renamed in step.
	var srcName string
	if err := pool.QueryRow(context.Background(), "SELECT name FROM blocklist_sources WHERE id = $1", created.SourceID).Scan(&srcName); err != nil {
		t.Fatal(err)
	}
	if srcName != "komdigi-2" {
		t.Fatalf("paired source name = %q, want komdigi-2", srcName)
	}

	// Delete cascades to the source.
	call("DELETE", "/api/v1/rpz/upstreams/"+created.ID, "", 204, nil)
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM blocklist_sources WHERE id = $1", created.SourceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("delete did not cascade to the source")
	}
	call("GET", "/api/v1/rpz/upstreams", "", 200, &list)
	if list.Total != 0 {
		t.Fatalf("upstream survived delete: %+v", list)
	}
}

// Validation: a TSIG secret without a key, and a bad interval, are rejected up front.
func TestRPZUpstreamCreateValidation(t *testing.T) {
	_, _, call := newHandlerSvc(t)
	call("POST", "/api/v1/rpz/upstreams", `{"name":"x","upstream":"h:53","zone":"z.","tsig_secret":"abc"}`, 400, nil)
	call("POST", "/api/v1/rpz/upstreams", `{"name":"x","upstream":"h:53","zone":"z.","interval_s":5}`, 400, nil)
	call("POST", "/api/v1/rpz/upstreams", `{"name":"","upstream":"h:53","zone":"z."}`, 400, nil)
}

// PATCH treats TSIG as a pair: setting key+secret works, clearing with tsig_key:"" works,
// but a lone key or lone secret is a 400 (it would leave the upstream signing with no
// secret and fail every transfer).
func TestRPZUpstreamPatchTSIGPair(t *testing.T) {
	_, _, call := newHandlerSvc(t)
	var created api.RPZUpstream
	call("POST", "/api/v1/rpz/upstreams", `{"name":"k","upstream":"h:53","zone":"z."}`, 201, &created)

	// Lone key without secret: 400.
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID, `{"tsig_key":"k."}`, 400, nil)
	// Non-empty secret without key: 400.
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID, `{"tsig_secret":"abc"}`, 400, nil)
	// Key with an empty secret: 400 (must send tsig_key:"" to clear).
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID, `{"tsig_key":"k.","tsig_secret":""}`, 400, nil)
	// Empty key with a non-empty secret: 400. It must not silently clear TSIG (a typo'd
	// key would otherwise disable signing and the browser dialog would report success).
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID, `{"tsig_key":"","tsig_secret":"abc"}`, 400, nil)

	// Setting the pair works and shows has_tsig.
	var setTSIG api.RPZUpstream
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID, `{"tsig_key":"k.","tsig_secret":"`+tsigB64+`"}`, 200, &setTSIG)
	if !setTSIG.HasTSIG {
		t.Fatalf("has_tsig = false after setting key+secret: %+v", setTSIG)
	}

	// Clearing with tsig_key:"" drops it.
	var cleared api.RPZUpstream
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID, `{"tsig_key":""}`, 200, &cleared)
	if cleared.HasTSIG {
		t.Fatalf("has_tsig = true after clearing: %+v", cleared)
	}
}

// An RPZ master can feed several profiles at once: create with profile_ids writes the join
// rows on the paired source, the listing reports the whole set, and a patch replaces it
// (which also clears the transferred content so the next sync rebuilds from scratch).
func TestRPZUpstreamProfileSetHTTP(t *testing.T) {
	_, pool, call := newHandlerSvc(t)
	a, b, c := newProfile(t, pool, "A"), newProfile(t, pool, "B"), newProfile(t, pool, "C")

	var created api.RPZUpstream
	call("POST", "/api/v1/rpz/upstreams",
		`{"name":"shared","upstream":"192.0.2.1:53","zone":"rpz.example","profile_ids":["`+a+`","`+b+`"]}`,
		201, &created)
	if len(created.ProfileIDs) != 2 || !contains(created.ProfileIDs, a) || !contains(created.ProfileIDs, b) {
		t.Fatalf("created profile_ids = %v, want {%s,%s}", created.ProfileIDs, a, b)
	}
	if len(created.ProfileNames) != 2 || created.ProfileID != created.ProfileIDs[0] {
		t.Fatalf("names/first mirror = %v / %q", created.ProfileNames, created.ProfileID)
	}
	if rows := joinCount(t, pool, created.SourceID); rows != 2 {
		t.Fatalf("paired source join rows = %d, want 2", rows)
	}

	// A patch moves the set to {B,C}: the stale transfer is dropped so the next sync is full.
	exec(t, pool, `UPDATE blocklist_sources SET content = 'stale.example' WHERE id = $1`, created.SourceID)
	var patched api.RPZUpstream
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID, `{"profile_ids":["`+b+`","`+c+`"]}`, 200, &patched)
	if len(patched.ProfileIDs) != 2 || !contains(patched.ProfileIDs, b) || !contains(patched.ProfileIDs, c) || contains(patched.ProfileIDs, a) {
		t.Fatalf("patched profile_ids = %v", patched.ProfileIDs)
	}
	var content, legacy string
	if err := pool.QueryRow(context.Background(),
		`SELECT content, coalesce(profile_id::text, '') FROM blocklist_sources WHERE id = $1`, created.SourceID).
		Scan(&content, &legacy); err != nil {
		t.Fatal(err)
	}
	if content != "" {
		t.Fatalf("profile move kept stale content %q", content)
	}
	if legacy != b {
		t.Fatalf("legacy profile_id = %q, want the first profile %q", legacy, b)
	}

	// Empty set returns it to global on the paired source.
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID, `{"profile_ids":[]}`, 200, &patched)
	if len(patched.ProfileIDs) != 0 || patched.ProfileID != "" {
		t.Fatalf("global master = %+v", patched)
	}
	if rows := joinCount(t, pool, created.SourceID); rows != 0 {
		t.Fatalf("join rows after global = %d, want 0", rows)
	}

	// An unknown profile id is a 400 and leaves the (now empty) set untouched.
	call("PATCH", "/api/v1/rpz/upstreams/"+created.ID,
		`{"profile_ids":["00000000-0000-0000-0000-000000000000"]}`, 400, nil)
	if rows := joinCount(t, pool, created.SourceID); rows != 0 {
		t.Fatalf("failed patch changed the set: %d join rows", rows)
	}
}
