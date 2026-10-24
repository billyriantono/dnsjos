package blocklist

// RPZ slave (SPEC §7.7): the panel pulls the blocklist zone from an RPZ master over
// AXFR/IXFR and writes the transferred domain list into the linked source's content, so
// the build afterwards treats it exactly like a manual source. Only the panel needs the
// upstream's allow-IP/TSIG; nodes keep downloading the CDB from the panel.

import (
	"context"
	"errors"
	"fmt"
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
	return u, err
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
	serial, domains, err := s.transferRPZ(ctx, up)
	if err != nil {
		s.recordRPZError(ctx, up.ID, err)
		return err
	}
	if serial == up.Serial && serial != 0 {
		return nil // upstream not newer
	}
	// Never persist a zero-domain transfer for a provably non-empty zone: a
	// truncated/garbage response must not wipe the known-good blocklist.
	// Only an empty transfer that carries the zone's own apex SOA counts as a
	// genuine empty zone (normally impossible for this RPZ).
	if len(domains) == 0 && !s.rpzApexConfirmed(ctx, up) {
		err := fmt.Errorf("ignoring empty transfer for non-empty zone (serial %d)", serial)
		s.recordRPZError(ctx, up.ID, err)
		return err
	}
	content := strings.Join(domains, "\n")
	if len(domains) > 0 {
		content += "\n"
	}
	if _, err := s.d.Pool.Exec(ctx, `UPDATE blocklist_sources SET content = $2, updated_at = now() WHERE id = $1`,
		up.SourceID, content); err != nil {
		s.recordRPZError(ctx, up.ID, err)
		return err
	}
	if _, err := s.d.Pool.Exec(ctx, `UPDATE rpz_upstreams SET serial = $2, total_domains = $3,
		last_sync_at = now(), last_error = '' WHERE id = $1`, up.ID, serial, len(domains)); err != nil {
		return err
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
	_, _ = s.d.Pool.Exec(ctx, "UPDATE rpz_upstreams SET last_error = $2 WHERE id = $1", id, err.Error())
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

// rpzApexConfirmed reports whether the upstream still serves the zone's apex SOA.
// A zone that answers its own SOA cannot legitimately transfer zero records, so a
// zero-domain result without apex confirmation means a truncated/garbage response.
func (s *Service) rpzApexConfirmed(ctx context.Context, up rpzUpstream) bool {
	zone := dns.Fqdn(up.Zone)
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeSOA)
	up.sign(m)
	c := &dns.Client{Timeout: 10 * time.Second, TsigSecret: up.tsigSecret()}
	r, _, err := c.ExchangeContext(ctx, m, up.Upstream)
	if err != nil || r == nil || r.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, a := range r.Answer {
		if soa, ok := a.(*dns.SOA); ok && strings.EqualFold(soa.Hdr.Name, zone) {
			return true
		}
	}
	return false
}

// transferRPZ does the whole pull: SOA serial, then AXFR (no local serial) or IXFR.
// It returns the upstream serial and the full domain list (already normalized).
//
// An IXFR answer is a DELTA (deleted records then added records), not a full zone.
// The delta must be applied on top of the last-known full domain set; treating the
// delta itself as the whole zone would silently drop every pre-existing domain.
func (s *Service) transferRPZ(ctx context.Context, up rpzUpstream) (uint32, []string, error) {
	zone := dns.Fqdn(up.Zone)
	serial, err := s.rpzSOA(ctx, up, zone)
	if err != nil {
		return 0, nil, err
	}
	if up.Serial == 0 {
		return s.axfrDomains(ctx, up, zone, serial)
	}
	domains, ok, err := s.ixfrDomains(ctx, up, zone, serial)
	if err != nil {
		return 0, nil, err
	}
	if !ok {
		// No usable last-known set (or the master refused IXFR): fall back to a
		// full AXFR so content is always the complete zone, never a bare delta.
		return s.axfrDomains(ctx, up, zone, serial)
	}
	return serial, domains, nil
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

// ixfrDomains applies the IXFR delta on top of the last-known full domain set taken
// from the linked source's content. It returns ok=false when there is no usable
// base set or the server's answer is not an incremental update; the caller then
// falls back to AXFR.
func (s *Service) ixfrDomains(ctx context.Context, up rpzUpstream, zone string, serial uint32) ([]string, bool, error) {
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
	// Stream the delta without retaining raw records: track only SOA markers and
	// the ordered owner names (with a section tag) needed for the delete/add walk.
	type deltaRec struct {
		names   []string
		section int // section of the SOA walk the record belongs to: 1-based
	}
	var delta []deltaRec
	all := make(map[string]struct{}) // every domain seen, for the full-zone fallback
	var firstSOA, lastSOA uint32
	section := 0
	soas := 0
	for env := range envs {
		if env.Error != nil {
			return nil, false, fmt.Errorf("transfer stream: %w", env.Error)
		}
		for _, rr := range env.RR {
			if rr.Header().Rrtype == dns.TypeSOA {
				section++
				soas++
				if soa, ok := rr.(*dns.SOA); ok {
					if firstSOA == 0 {
						firstSOA = soa.Serial
					}
					lastSOA = soa.Serial
				}
				continue
			}
			names, err := ownerNames(rr, zone)
			if err != nil {
				return nil, false, err
			}
			if len(names) == 0 {
				continue
			}
			delta = append(delta, deltaRec{names, section})
			for _, n := range names {
				all[n] = struct{}{}
				if len(all) > rpzMaxZoneDomains {
					return nil, false, fmt.Errorf("transfer exceeds %d domains", rpzMaxZoneDomains)
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
	}
	if soas < 2 {
		// One SOA => the server answered with the full zone (already complete).
		// Zero => not a usable IXFR answer at all.
		if soas == 1 && len(delta) > 0 {
			domains := make([]string, 0, len(all))
			for n := range all {
				domains = append(domains, n)
			}
			sort.Strings(domains)
			return domains, true, nil
		}
		return nil, false, nil
	}
	// A genuine delta starts with SOA(oldSerial) and its second SOA carries the new
	// serial. Two SOAs with the SAME serial mean the server answered with the full
	// zone (how miekg/dns terminates a full-transfer IXFR): every seen domain stands.
	if firstSOA == lastSOA {
		domains := make([]string, 0, len(all))
		for n := range all {
			domains = append(domains, n)
		}
		sort.Strings(domains)
		return domains, true, nil
	}
	// Delta layout: SOA(oldSerial), deletions..., SOA(newSerial), additions...
	for _, rec := range delta {
		if rec.section == 1 {
			for _, n := range rec.names {
				delete(base, n)
			}
		} else if rec.section >= 2 {
			for _, n := range rec.names {
				base[n] = struct{}{}
			}
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
	case dns.TypeCNAME, dns.TypeA, dns.TypeAAAA:
	default:
		return nil, nil
	}
	domain := strings.TrimSuffix(strings.TrimSuffix(owner, zone), ".")
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

// rpzOwners extracts the blocked domains from a transfer: every owner of a CNAME/A/AAAA
// record inside the zone, minus the zone apex, normalized by the same rules the build
// uses. Duplicates are collapsed.
func rpzOwners(records []dns.RR, zone string) ([]string, error) {
	seen := make(map[string]struct{}, len(records))
	for _, rr := range records {
		owner := strings.ToLower(dns.Fqdn(rr.Header().Name))
		if !dns.IsSubDomain(zone, owner) {
			return nil, fmt.Errorf("owner outside RPZ zone: %s", owner)
		}
		if owner == zone {
			continue
		}
		switch rr.Header().Rrtype {
		case dns.TypeCNAME, dns.TypeA, dns.TypeAAAA:
		default:
			continue
		}
		domain := strings.TrimSuffix(strings.TrimSuffix(owner, zone), ".")
		if name, ok := normalizeDomain(domain); ok {
			seen[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}
