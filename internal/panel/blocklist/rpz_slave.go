package blocklist

// RPZ slave (SPEC §7.7): the panel pulls the blocklist zone from an RPZ master over
// AXFR/IXFR and writes the transferred domain list into the linked source's content, so
// the build afterwards treats it exactly like a manual source. Only the panel needs the
// upstream's allow-IP/TSIG; nodes keep downloading the CDB from the panel.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/db"
)

// rpzMaxZoneDomains caps how many distinct blocked domains one transfer may
// produce. It bounds the in-RAM domain set, not raw DNS records: a transfer
// carries SOA/duplicate records that never become domains, so the record count
// can legitimately exceed the domain count by a wide margin.
const rpzMaxZoneDomains = 30_000_000

// rpzReadTimeout gives a 10M+ record TCP transfer room to finish. The server
// dribbles hundreds of messages; a 60s idle deadline kills a healthy but slow
// stream and surfaces as unpack/reset errors mid-transfer.
const rpzReadTimeout = 20 * time.Minute

// rpzUpstream mirrors one rpz_upstreams row joined to its source.
type rpzUpstream struct {
	ID, Name, Upstream, Zone string
	TSIGKey                  string
	TSIGSecret               string
	IntervalS                int
	Serial                   uint32
	TotalDomains             int
	LastError                string
	SourceID                 string
	ProfileIDs               []string
}

const rpzCols = `u.id, u.name, u.upstream, u.zone, u.tsig_key, u.tsig_secret,
	u.interval_s, u.serial, u.total_domains, coalesce(u.last_error, ''), u.source_id,
	array(SELECT sp.profile_id::text FROM blocklist_source_profiles sp WHERE sp.source_id = s.id ORDER BY sp.profile_id)`

func scanRPZUpstream(row pgx.Row) (rpzUpstream, error) {
	var u rpzUpstream
	err := row.Scan(&u.ID, &u.Name, &u.Upstream, &u.Zone, &u.TSIGKey, &u.TSIGSecret,
		&u.IntervalS, &u.Serial, &u.TotalDomains, &u.LastError, &u.SourceID, &u.ProfileIDs)
	if u.ProfileIDs == nil {
		u.ProfileIDs = []string{}
	}
	u.Upstream = withDefaultPort(u.Upstream)
	return u, err
}

// withDefaultPort appends DNS port 53 to a bare host or IP ("10.0.0.1", "2001:db8::1",
// "[2001:db8::1]"); miekg/dns dials need host:port. host:port passes through unchanged.
func withDefaultPort(hostport string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil || hostport == "" {
		return hostport
	}
	return net.JoinHostPort(strings.Trim(hostport, "[]"), "53")
}

// rpzSyncAll is the scheduled job: sync every upstream whose source is still enabled and
// whose interval has passed. A failing upstream must not stop the others.
func (s *Service) rpzSyncAll(ctx context.Context) error {
	rows, err := s.d.Pool.Query(ctx, `SELECT `+rpzCols+` FROM rpz_upstreams u
		JOIN blocklist_sources s ON s.id = u.source_id
		WHERE s.enabled ORDER BY u.id`)
	if err != nil {
		return err
	}
	ups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (rpzUpstream, error) { return scanRPZUpstream(row) })
	if err != nil {
		return err
	}
	var errs []error
	for _, up := range ups {
		if err := s.rpzSyncUpstream(ctx, up, false); err != nil {
			errs = append(errs, fmt.Errorf("rpz %s: %w", up.Name, err))
		}
	}
	return errors.Join(errs...)
}

// rpzSyncUpstream serves both the interval job and a manual sync. It queries the
// upstream's SOA, transfers the zone when the upstream is newer, atomically rewrites the
// source's content and bumps the serial. force skips the interval check.
func (s *Service) rpzSyncUpstream(ctx context.Context, up rpzUpstream, force bool) error {
	if !force {
		last, err := lastRPZSync(ctx, s.d.Pool, up.ID)
		if err != nil {
			return err
		}
		if last != nil && time.Since(*last) < time.Duration(up.IntervalS)*time.Second {
			return nil
		}
	}
	zone := dns.Fqdn(up.Zone)
	serial, err := s.rpzSOA(ctx, up, zone)
	if err != nil {
		s.recordRPZError(ctx, up.ID, err)
		return err
	}
	if serial == up.Serial && serial != 0 {
		// Upstream not newer: check the SOA only, never transfer, and stamp the sync
		// time so the interval gate holds until the next check is due.
		_, err := s.d.Pool.Exec(ctx, `UPDATE rpz_upstreams SET last_sync_at = now(), last_error = '' WHERE id = $1`, up.ID)
		return err
	}
	domains, err := s.transferRPZ(ctx, up, zone, serial)
	if err != nil {
		s.recordRPZError(ctx, up.ID, err)
		return err
	}
	// Never persist a zero-domain transfer over a zone that last synced non-empty: a
	// truncated/garbage response (or one with no blocking records) must not wipe the
	// known-good blocklist. ponytail: a master that truly empties a non-empty zone is
	// refused too; clear it by deleting/recreating the upstream if that ever happens.
	if len(domains) == 0 && up.TotalDomains > 0 {
		err := fmt.Errorf("ignoring empty transfer at serial %d (last sync had %d domains)", serial, up.TotalDomains)
		s.recordRPZError(ctx, up.ID, err)
		return err
	}
	content := strings.Join(domains, "\n")
	if len(domains) > 0 {
		content += "\n"
	}
	// Content and serial move together (an IXFR applies onto the content at that serial),
	// and only if no other sync wrote since this one read up.Serial: a concurrent manual
	// and scheduled sync both transfer, but only the first to commit is kept.
	stale := false
	err = pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE rpz_upstreams SET serial = $2, total_domains = $3,
			last_sync_at = now(), last_error = '' WHERE id = $1 AND serial = $4`,
			up.ID, serial, len(domains), up.Serial)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			stale = true
			return nil
		}
		_, err = tx.Exec(ctx, `UPDATE blocklist_sources SET content = $2, updated_at = now() WHERE id = $1`,
			up.SourceID, content)
		return err
	})
	if err != nil {
		s.recordRPZError(ctx, up.ID, err)
		return err
	}
	if stale {
		return nil // another sync (or an upstream edit) moved the serial first
	}
	s.markDirty(ctx, up.SourceID)
	_ = audit.Log(ctx, s.d.Pool, nil, "blocklist.rpz.sync", "rpz_upstream", up.ID,
		map[string]any{"serial": serial, "domains": len(domains)}, "")
	return nil
}

func lastRPZSync(ctx context.Context, q db.Querier, id string) (*time.Time, error) {
	var last *time.Time
	err := q.QueryRow(ctx, "SELECT last_sync_at FROM rpz_upstreams WHERE id = $1", id).Scan(&last)
	return last, err
}

func (s *Service) recordRPZError(ctx context.Context, id string, err error) {
	// last_sync_at is the last attempt: stamping failures too keeps a dead master on the
	// upstream's interval instead of re-dialing it every scheduler tick.
	_, _ = s.d.Pool.Exec(ctx, "UPDATE rpz_upstreams SET last_error = $2, last_sync_at = now() WHERE id = $1", id, err.Error())
}

// tsigSecret returns the miekg/dns TSIG map for the upstream, or nil without TSIG.
func (u rpzUpstream) tsigSecret() map[string]string {
	if u.TSIGKey == "" || u.TSIGSecret == "" {
		return nil
	}
	return map[string]string{dns.Fqdn(u.TSIGKey): u.TSIGSecret}
}

func (u rpzUpstream) sign(m *dns.Msg) {
	if u.TSIGKey != "" {
		m.SetTsig(dns.Fqdn(u.TSIGKey), dns.HmacSHA256, 300, time.Now().Unix())
	}
}

// transferRPZ pulls the zone at the given upstream serial: AXFR when there is no local
// serial, otherwise IXFR. It returns the full domain list (already normalized).
//
// An IXFR answer is a DELTA (deleted records then added records), not a full zone.
// The delta must be applied on top of the last-known full domain set; treating the
// delta itself as the whole zone would silently drop every pre-existing domain.
func (s *Service) transferRPZ(ctx context.Context, up rpzUpstream, zone string, serial uint32) ([]string, error) {
	if up.Serial != 0 {
		domains, ok, err := s.ixfrDomains(ctx, up, zone)
		if err != nil || ok {
			return domains, err
		}
		// No usable last-known set (or the master refused IXFR): fall back to a
		// full AXFR so content is always the complete zone, never a bare delta.
	}
	_, domains, err := s.axfrDomains(ctx, up, zone, serial)
	return domains, err
}

// axfrDomains pulls the full zone via AXFR and extracts the normalized domain list.
// Records are processed per envelope straight into the domain set, so a 10M+
// record zone never sits in RAM twice (raw RRs plus domains).
func (s *Service) axfrDomains(ctx context.Context, up rpzUpstream, zone string, serial uint32) (uint32, []string, error) {
	req := new(dns.Msg)
	req.SetAxfr(zone)
	up.sign(req)
	tr := &dns.Transfer{DialTimeout: 30 * time.Second, ReadTimeout: rpzReadTimeout,
		WriteTimeout: 30 * time.Second, TsigSecret: up.tsigSecret()}
	envs, err := tr.In(req, up.Upstream)
	if err != nil {
		return 0, nil, fmt.Errorf("transfer: %w", err)
	}
	seen := make(map[string]struct{})
	for env := range envs {
		if env.Error != nil {
			return 0, nil, fmt.Errorf("transfer stream: %w", env.Error)
		}
		for _, rr := range env.RR {
			names, err := ownerNames(rr, zone)
			if err != nil {
				return 0, nil, err
			}
			for _, n := range names {
				seen[n] = struct{}{}
			}
		}
		if len(seen) > rpzMaxZoneDomains {
			return 0, nil, fmt.Errorf("transfer exceeds %d domains", rpzMaxZoneDomains)
		}
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
	}
	domains := make([]string, 0, len(seen))
	for n := range seen {
		domains = append(domains, n)
	}
	sort.Strings(domains)
	return serial, domains, nil
}

// ixfrDomains applies the IXFR answer on top of the last-known full domain set taken
// from the linked source's content. It returns ok=false when there is no usable base
// set or the answer is a bare SOA (nothing to apply); the caller then falls back to AXFR.
//
// RFC 1995 answer layouts, as miekg/dns Transfer.In passes them through (first SOA
// included):
//
//	incremental: SOA(new), [SOA(old_i), deletions..., SOA(new_i), additions...]..., SOA(new)
//	full zone:   SOA(new), records..., SOA(new)
//
// The second record tells them apart: an SOA with a serial other than the first is
// the start of a difference sequence. Inside the deltas every SOA toggles between
// deleting and adding, so multi-step answers are applied in order.
func (s *Service) ixfrDomains(ctx context.Context, up rpzUpstream, zone string) ([]string, bool, error) {
	var content string
	if err := s.d.Pool.QueryRow(ctx,
		"SELECT content FROM blocklist_sources WHERE id = $1", up.SourceID).Scan(&content); err != nil {
		return nil, false, fmt.Errorf("load source content: %w", err)
	}
	base := make(map[string]struct{})
	for line := range strings.Lines(content) {
		if name, ok := normalizeDomain(stripLine(line)); ok {
			base[name] = struct{}{}
		}
	}
	if len(base) == 0 {
		return nil, false, nil // nothing to apply a delta onto: use AXFR
	}
	req := new(dns.Msg)
	req.SetIxfr(zone, up.Serial, "ns1."+zone, "hostmaster."+zone)
	up.sign(req)
	tr := &dns.Transfer{DialTimeout: 30 * time.Second, ReadTimeout: rpzReadTimeout,
		WriteTimeout: 30 * time.Second, TsigSecret: up.tsigSecret()}
	envs, err := tr.In(req, up.Upstream)
	if err != nil {
		return nil, false, fmt.Errorf("transfer: %w", err)
	}
	const (
		modeUnknown = iota // only the opening SOA seen so far
		modeFull           // the server answered with the whole zone
		modeDelta          // RFC 1995 difference sequences
	)
	mode := modeUnknown
	var newSerial uint32
	records := 0
	deleting := false
	full := make(map[string]struct{}) // modeFull: the zone is rebuilt from scratch
	for env := range envs {
		if env.Error != nil {
			return nil, false, fmt.Errorf("transfer stream: %w", env.Error)
		}
		for _, rr := range env.RR {
			records++
			soa, isSOA := rr.(*dns.SOA)
			if records == 1 {
				if !isSOA {
					return nil, false, errors.New("IXFR answer does not start with SOA")
				}
				newSerial = soa.Serial
				continue
			}
			if records == 2 {
				mode = modeFull
				if isSOA && soa.Serial != newSerial {
					mode = modeDelta
				}
			}
			if isSOA {
				if mode == modeDelta {
					deleting = !deleting // SOA(old_i) opens deletions, SOA(new_i) additions
				}
				continue
			}
			names, err := ownerNames(rr, zone)
			if err != nil {
				return nil, false, err
			}
			set := full
			if mode == modeDelta {
				set = base
			}
			for _, n := range names {
				if deleting {
					// ponytail: per-name delete; a name kept by another record of the
					// same owner (A+AAAA, *.x and x) is dropped too.
					delete(set, n)
				} else {
					set[n] = struct{}{}
				}
			}
			if len(set) > rpzMaxZoneDomains {
				return nil, false, fmt.Errorf("transfer exceeds %d domains", rpzMaxZoneDomains)
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
	}
	switch mode {
	case modeUnknown:
		return nil, false, nil // bare SOA: no usable answer
	case modeFull:
		base = full
	case modeDelta:
		// A complete answer ends on the closing SOA(new) right after additions,
		// which leaves deleting toggled on; anything else is a truncated stream.
		if !deleting {
			return nil, false, errors.New("IXFR answer truncated mid-delta")
		}
	}
	out := make([]string, 0, len(base))
	for n := range base {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, true, nil
}

// ownerNames returns the normalized blocked-domain name of a single delta record,
// or nil for records that carry no blocked domain. An owner outside the RPZ zone
// is a protocol error.
func ownerNames(rr dns.RR, zone string) ([]string, error) {
	owner := strings.ToLower(dns.Fqdn(rr.Header().Name))
	if !dns.IsSubDomain(zone, owner) {
		return nil, fmt.Errorf("owner outside RPZ zone: %s", owner)
	}
	if owner == zone {
		return nil, nil
	}
	switch rr.Header().Rrtype {
	case dns.TypeCNAME:
		if strings.EqualFold(rr.(*dns.CNAME).Target, "rpz-passthru.") {
			// ponytail: passthru is an allow rule; it is skipped, not applied as an
			// allowlist entry, so it cannot override a wildcard block in the same zone.
			return nil, nil
		}
	case dns.TypeA, dns.TypeAAAA:
	default:
		return nil, nil
	}
	domain := strings.TrimSuffix(strings.TrimSuffix(owner, zone), ".")
	labels := strings.Split(domain, ".")
	switch labels[len(labels)-1] {
	case "rpz-ip", "rpz-nsdname", "rpz-nsip", "rpz-client-ip":
		return nil, nil // response/NS/client triggers, not a QNAME to block
	}
	if name, ok := normalizeDomain(domain); ok {
		return []string{name}, nil
	}
	return nil, nil
}

func (s *Service) rpzSOA(ctx context.Context, up rpzUpstream, zone string) (uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeSOA)
	up.sign(m)
	c := &dns.Client{Timeout: 5 * time.Second, TsigSecret: up.tsigSecret()}
	r, _, err := c.ExchangeContext(ctx, m, up.Upstream)
	if err != nil {
		return 0, fmt.Errorf("SOA query: %w", err)
	}
	if r.Truncated || r.Rcode != dns.RcodeSuccess {
		return 0, fmt.Errorf("SOA unusable: truncated=%t rcode=%s", r.Truncated, dns.RcodeToString[r.Rcode])
	}
	for _, a := range r.Answer {
		if soa, ok := a.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, zone) {
			return soa.Serial, nil
		}
	}
	return 0, errors.New("no zone SOA in response")
}
