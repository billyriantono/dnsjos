package dnsconf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cdbw "github.com/colinmarc/cdb"
	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/cdb"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type liveDnsdist struct {
	dir, conf, listen, web string
	hits                   sync.Map // qname → *atomic.Int32 (backend queries)
	query                  func(name string, qt uint16) *dns.Msg
	console                func(cmd string) string
}

// startDnsdist runs the rendered config (blocking + response IPs, CDB: blocked.example
// and 192.0.2.1) in a real dnsdist against a backend answering the A records in ips;
// it skips when dnsdist is not on PATH.
func startDnsdist(t *testing.T, ips map[string][]string) *liveDnsdist {
	bin, err := exec.LookPath("dnsdist")
	if err != nil {
		t.Skip("dnsdist not on PATH")
	}
	d := &liveDnsdist{dir: t.TempDir()}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		n, _ := d.hits.LoadOrStore(q.Name, new(atomic.Int32))
		n.(*atomic.Int32).Add(1)
		name := q.Name
		for v := ips[name]; len(v) == 1 && strings.HasPrefix(v[0], "cname:"); v = ips[name] { // "cname:target." values
			rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN CNAME %s", name, v[0][6:]))
			m.Answer, name = append(m.Answer, rr), v[0][6:]
		}
		for _, ip := range ips[name] {
			a := netip.MustParseAddr(ip)
			if q.Qtype == dns.TypeA && a.Is4() || q.Qtype == dns.TypeAAAA && a.Is6() {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN %s %s", name, dns.TypeToString[q.Qtype], ip))
				m.Answer = append(m.Answer, rr)
			}
		}
		if o := r.IsEdns0(); o != nil {
			m.SetEdns0(o.UDPSize(), false)
		}
		w.WriteMsg(m)
	})}
	go backend.ActivateAndServe()
	t.Cleanup(func() { backend.Shutdown() })

	cdbPath := filepath.Join(d.dir, "bl.cdb")
	f, _ := os.Create(cdbPath)
	cw, err := cdbw.NewWriter(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	cw.Put(cdb.IPv4Key(netip.MustParseAddr("192.0.2.1")), nil)
	cw.Put(cdb.DomainKey("blocked.example"), nil)
	if _, err := cw.Freeze(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	spec := api.DefaultConfigSpec()
	d.listen = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	d.web = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	spec.Listen.Do53.Addresses = []string{d.listen}
	spec.Webserver.Listen = d.web
	spec.Upstreams.Servers = []api.Upstream{{Address: pc.LocalAddr().String(), Weight: 1, Order: 1, Sockets: 1}}
	spec.Abuse.Enabled, spec.CGK.Enabled, spec.Blocking.LogBlocked = false, false, false
	spec.Blocking.BlockResponseIPs = true // opt-in since it became off by default
	spec.DualStack.Enabled = true
	spec.SpeedCheck.FastestIP = true
	spec.Analytics.StreamAddr = fmt.Sprintf("127.0.0.1:%d", freePort(t)) // nobody listens; fine
	rt := testRT
	rt.BaseDir, rt.CDBPath = d.dir, cdbPath
	files, err := Render(spec, rt)
	if err != nil {
		t.Fatal(err)
	}
	for rel, b := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(d.dir, rel)), 0o755)
		os.WriteFile(filepath.Join(d.dir, rel), b, 0o644)
	}
	d.conf = filepath.Join(d.dir, FileConf)
	cmd := exec.Command(bin, "--supervised", "--disable-syslog", "-C", d.conf)
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	go io.Copy(&log, bufio.NewReader(out))
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	c := &dns.Client{Timeout: time.Second}
	d.query = func(name string, qt uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qt)
		for range 50 {
			if r, _, err := c.Exchange(m, d.listen); err == nil && r.Rcode != dns.RcodeServerFailure {
				return r
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("no answer for %s from dnsdist:\n%s", name, log.String())
		return nil
	}
	d.console = func(command string) string {
		out, err := exec.Command(bin, "-C", d.conf, "-c", "-e", command).CombinedOutput()
		if err != nil {
			t.Fatalf("console %s: %v: %s", command, err, out)
		}
		return string(out)
	}
	return d
}

// TestLiveBlocking checks the response-IP rewrite, its counting on repeated queries
// (cache) and the per-rule hit counters / metric names.
func TestLiveBlocking(t *testing.T) {
	// mixed.example has one listed and one unlisted address.
	d := startDnsdist(t, map[string][]string{"mixed.example.": {"192.0.2.1", "198.51.100.1"}, "clean.example.": {"198.51.100.2"}})
	query, web := d.query, d.web

	for i := range 3 {
		r := query("mixed.example.", dns.TypeA)
		if len(r.Answer) != 2 {
			t.Fatalf("mixed #%d: %v", i, r.Answer)
		}
		for _, rr := range r.Answer {
			a := rr.(*dns.A)
			if a.A.String() != "192.0.2.10" || a.Hdr.Ttl > 60 {
				t.Errorf("mixed #%d: want every A = blockpage with ttl<=60, got %v", i, rr)
			}
		}
	}
	if r := query("clean.example.", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "198.51.100.2" {
		t.Errorf("clean rewritten: %v", r.Answer)
	}
	query("blocked.example.", dns.TypeA)
	query("blocked.example.", dns.TypeMX)

	req, _ := http.NewRequest("GET", "http://"+web+"/metrics", nil)
	req.Header.Set("X-API-Key", testRT.WebAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	series := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		k, v, ok := strings.Cut(line, " ")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		if _, dup := series[k]; dup {
			t.Errorf("duplicate series %s", k)
		}
		series[k] = v
	}
	for k, want := range map[string]string{
		"dnsdist_dnsjos_response_ip_blocked":                "3", // every answer counted, none from cache
		`dnsdist_rule_hits{id="dnsjos-blocked-count"}`:      "2",
		`dnsdist_rule_hits{id="dnsjos-block-a"}`:            "1",
		`dnsdist_rule_hits{id="dnsjos-block-nodata"}`:       "1",
		`dnsdist_rule_hits{id="dnsjos-analytics-response"}`: "4",
		`dnsdist_rule_hits{id="dnsjos-analytics-self"}`:     "2",
	} {
		if series[k] != want {
			t.Errorf("%s = %q, want %s", k, series[k], want)
		}
	}
}

// TestLiveAllowlist: dnsjosAllowReload() applies the agent's allowlist files without a
// restart: an allowed name and its subdomains resolve, siblings stay blocked, cached
// answers of changed names are flushed, and allowed addresses skip the response-IP block.
func TestLiveAllowlist(t *testing.T) {
	d := startDnsdist(t, map[string][]string{
		"a.blocked.example.": {"198.51.100.4"}, "x.a.blocked.example.": {"198.51.100.5"}, "b.blocked.example.": {"198.51.100.6"},
		"mixed.example.": {"192.0.2.1", "198.51.100.1"}, "clean.example.": {"198.51.100.2"},
	})
	a := func(name string) string {
		var ips []string
		for _, rr := range d.query(name, dns.TypeA).Answer {
			ips = append(ips, rr.(*dns.A).A.String())
		}
		return strings.Join(ips, ",")
	}
	allow := func(domains, ips string) string {
		for f, v := range map[string]string{FileAllowDomains: domains, FileAllowIPs: ips} {
			if err := os.WriteFile(filepath.Join(d.dir, f), []byte(v), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return d.console("dnsjosAllowReload()")
	}
	check := func(want map[string]string) {
		t.Helper()
		for name, ip := range want {
			if got := a(name); got != ip {
				t.Errorf("%s = %q, want %q", name, got, ip)
			}
		}
	}
	const bp = "192.0.2.10"
	check(map[string]string{"a.blocked.example.": bp, "mixed.example.": bp + "," + bp, "clean.example.": "198.51.100.2"})
	a("clean.example.") // cached
	hits := func(name string) int32 { n, _ := d.hits.Load(name); return n.(*atomic.Int32).Load() }
	if hits("clean.example.") != 1 {
		t.Fatalf("clean.example not cached: %d backend queries", hits("clean.example."))
	}

	if out := allow("# emergency unblocks\na.blocked.example\nclean.example\nnot a name..\n", ""); !strings.Contains(out, "allowlist: 2 domains, 0 ips, 1 invalid") {
		t.Fatalf("reload: %s", out)
	}
	check(map[string]string{"a.blocked.example.": "198.51.100.4", "x.a.blocked.example.": "198.51.100.5",
		"b.blocked.example.": bp, "blocked.example.": bp})
	if a("clean.example."); hits("clean.example.") != 2 {
		t.Errorf("cached answer of a newly allowed name not flushed")
	}

	allow("", "") // removed: blocked again although the real answer is cached
	check(map[string]string{"a.blocked.example.": bp, "x.a.blocked.example.": bp})

	allow("", "192.0.2.0/24\n")
	check(map[string]string{"mixed.example.": "192.0.2.1,198.51.100.1"}) // now cached
	allow("", "")
	check(map[string]string{"mixed.example.": bp + "," + bp}) // cache flushed on removal
	allow("mixed.example\n", "")
	check(map[string]string{"mixed.example.": "192.0.2.1,198.51.100.1"}) // allowed name skips the IP block too

	os.Remove(filepath.Join(d.dir, FileAllowDomains))
	os.Remove(filepath.Join(d.dir, FileAllowIPs))
	if out := d.console("dnsjosAllowReload()"); !strings.Contains(out, "allowlist: 0 domains, 0 ips, 0 invalid") {
		t.Fatalf("missing files: %s", out)
	}
	check(map[string]string{"mixed.example.": bp + "," + bp})
}

// TestLiveDualStack: dsSeen() reports names with AAAA answers; after dsReload() listed
// names get smartdns' reply for the dropped family (NODATA, SOA for the name in the
// authority section with the listed TTL), from cache too, while the other family is untouched.
func TestLiveDualStack(t *testing.T) {
	d := startDnsdist(t, map[string][]string{
		"dns.google.": {"8.8.8.8", "2001:4860:4860::8888"}, "v6.example.": {"198.51.100.8", "2001:db8::8"},
		"v4only.example.": {"198.51.100.7"},
	})
	count := func(name string, qt uint16) int { return len(d.query(name, qt).Answer) }
	if count("dns.google.", dns.TypeAAAA) != 1 || count("v6.example.", dns.TypeA) != 1 {
		t.Fatal("answers dropped before the lists exist")
	}
	count("v4only.example.", dns.TypeAAAA) // NODATA: not reported
	if out := strings.TrimSpace(d.console("dsSeen()")); out != "dns.google 1" {
		t.Fatalf("dsSeen() = %q", out)
	}

	write := func(v4, v6 string) string {
		os.WriteFile(filepath.Join(d.dir, FileDualStackPreferV4), []byte(v4), 0o644)
		os.WriteFile(filepath.Join(d.dir, FileDualStackPreferV6), []byte(v6), 0o644)
		return d.console("dsReload()")
	}
	if out := write("# test\nDNS.google 42\nbroken-line\n", "v6.example 77\n"); !strings.Contains(out, "dualstack: 1 names prefer IPv4, 1 prefer IPv6") {
		t.Fatalf("dsReload() = %s", out)
	}
	nodata := func(name string, qt uint16, ttl uint32) {
		t.Helper()
		r := d.query(name, qt)
		soa, ok := func() (*dns.SOA, bool) {
			if len(r.Ns) != 1 {
				return nil, false
			}
			s, ok := r.Ns[0].(*dns.SOA)
			return s, ok
		}()
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || !ok || soa.Hdr.Name != name || soa.Hdr.Ttl != ttl ||
			soa.Ns != "a.gtld-servers.net." || soa.Mbox != "nstld.verisign-grs.com." || soa.Serial != 1800 ||
			soa.Refresh != 1800 || soa.Retry != 900 || soa.Expire != 604800 || soa.Minttl != 86400 || r.Id == 0 || !r.Response {
			t.Errorf("%s %s: want NODATA + smartdns SOA ttl %d, got %v", name, dns.TypeToString[qt], ttl, r)
		}
	}
	nodata("dns.google.", dns.TypeAAAA, 42) // cached upstream answer, still dropped
	nodata("v6.example.", dns.TypeA, 77)
	if a := d.query("dns.google.", dns.TypeA).Answer; len(a) != 1 || a[0].(*dns.A).A.String() != "8.8.8.8" {
		t.Errorf("A changed: %v", a)
	}
	if count("v6.example.", dns.TypeAAAA) != 1 {
		t.Error("AAAA of an IPv6-preferred name dropped")
	}
	seen := strings.Split(strings.TrimSpace(d.console("dsSeen()")), "\n")
	slices.Sort(seen) // v6.example: its dropped A and its real AAAA
	if !slices.Equal(seen, []string{"dns.google 1", "v6.example 2"}) {
		t.Errorf("dropped / answered names not counted: %v", seen)
	}

	write("", "")
	if count("dns.google.", dns.TypeAAAA) != 1 || count("v6.example.", dns.TypeA) != 1 {
		t.Error("answers still dropped after the names left the lists")
	}
}

// TestLiveFastestIP: fipSeen() reports names with several addresses; after fipReload() their
// answers are smartdns' (_dns_rrs_add_all_best_ip): the fastest first, then those nearly as
// fast, unmeasured / unanswered ones dropped, a CNAME chain flattened, EDNS kept, and the
// same from the cache.
func TestLiveFastestIP(t *testing.T) {
	d := startDnsdist(t, map[string][]string{
		"multi.example.": {"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4", "198.51.100.5",
			"2001:db8::1", "2001:db8::2"},
		"alias.example.": {"cname:mid.example."}, "mid.example.": {"cname:multi.example."},
		"one.example.": {"198.51.100.9"},
	})
	addrs := func(r *dns.Msg) []string {
		var out []string
		for _, rr := range r.Answer {
			switch v := rr.(type) {
			case *dns.A:
				out = append(out, v.A.String())
			case *dns.AAAA:
				out = append(out, v.AAAA.String())
			}
		}
		return out
	}
	if got := addrs(d.query("multi.example.", dns.TypeA)); len(got) != 5 || got[0] != "198.51.100.1" {
		t.Fatalf("before the list: %v", got)
	}
	d.query("alias.example.", dns.TypeA)
	d.query("one.example.", dns.TypeA) // a single address: nothing to choose, not reported
	seen := strings.Split(strings.TrimSpace(d.console("fipSeen()")), "\n")
	slices.Sort(seen)
	if !slices.Equal(seen, []string{"alias.example 1", "multi.example 1"}) {
		t.Fatalf("fipSeen() = %q", seen)
	}

	// 0.1 ms: .2 is fastest (2 ms); .3 is < 5 ms slower; .1 (30 ms) is too slow; .4 did not
	// answer; .5 was not measured. ::2 fastest (1 ms); ::1 is 8 ms slower but itself < 10 ms.
	times := " 198.51.100.1 300 198.51.100.2 20 198.51.100.3 25 198.51.100.4 -1 2001:db8::1 90 2001:db8::2 10\n"
	os.WriteFile(filepath.Join(d.dir, FileFastestIPList), []byte("# test\nmulti.example"+times+"ALIAS.example"+times), 0o644)
	if out := d.console("fipReload()"); !strings.Contains(out, "fastest-ip: 2 names") {
		t.Fatalf("fipReload() = %s", out)
	}
	for i := range 2 { // the second time from the cache
		if got := addrs(d.query("multi.example.", dns.TypeA)); !slices.Equal(got, []string{"198.51.100.2", "198.51.100.3"}) {
			t.Errorf("A #%d = %v", i, got)
		}
		if got := addrs(d.query("multi.example.", dns.TypeAAAA)); !slices.Equal(got, []string{"2001:db8::2", "2001:db8::1"}) {
			t.Errorf("AAAA #%d = %v", i, got)
		}
	}

	m := new(dns.Msg)
	m.SetQuestion("alias.example.", dns.TypeA)
	m.SetEdns0(1232, false)
	r, _, err := (&dns.Client{Timeout: time.Second}).Exchange(m, d.listen)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Answer) != 3 || r.IsEdns0() == nil || r.Id != m.Id || !r.Response {
		t.Fatalf("alias: %v", r)
	}
	c, ok := r.Answer[0].(*dns.CNAME)
	if !ok || c.Hdr.Name != "alias.example." || c.Target != "multi.example." || r.Answer[1].Header().Name != "multi.example." ||
		!slices.Equal(addrs(r), []string{"198.51.100.2", "198.51.100.3"}) {
		t.Errorf("alias: want one CNAME to multi.example. + the 2 fastest A, got %v", r.Answer)
	}

	os.WriteFile(filepath.Join(d.dir, FileFastestIPList), nil, 0o644)
	d.console("fipReload()")
	if got := addrs(d.query("one.example.", dns.TypeA)); !slices.Equal(got, []string{"198.51.100.9"}) {
		t.Errorf("single address changed: %v", got)
	}
}
