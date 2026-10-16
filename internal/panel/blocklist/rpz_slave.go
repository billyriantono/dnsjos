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

const rpzMaxTransferRecords = 10_000_000

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
func (s *Service) axfrDomains(ctx context.Context, up rpzUpstream, zone string, serial uint32) (uint32, []string, error) {
	req := new(dns.Msg)
	req.SetAxfr(zone)
	up.sign(req)
	tr := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 5 * time.Second, TsigSecret: up.tsigSecret()}
	envs, err := tr.In(req, up.Upstream)
	if err != nil {
		return 0, nil, fmt.Errorf("transfer: %w", err)
	}
	var records []dns.RR
	for env := range envs {
		if env.Error != nil {
			return 0, nil, fmt.Errorf("transfer stream: %w", env.Error)
		}
		if len(records)+len(env.RR) > rpzMaxTransferRecords {
			return 0, nil, fmt.Errorf("transfer exceeds %d records", rpzMaxTransferRecords)
		}
		records = append(records, env.RR...)
	}
	domains, err := rpzOwners(records, zone)
	if err != nil {
		return 0, nil, err
	}
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
	tr := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 5 * time.Second, TsigSecret: up.tsigSecret()}
	envs, err := tr.In(req, up.Upstream)
	if err != nil {
		return nil, false, fmt.Errorf("transfer: %w", err)
	}
	var records []dns.RR
	soas := 0
	for env := range envs {
		if env.Error != nil {
			return nil, false, fmt.Errorf("transfer stream: %w", env.Error)
		}
		for _, rr := range env.RR {
			if rr.Header().Rrtype == dns.TypeSOA {
				soas++
			}
		}
		if len(records)+len(env.RR) > rpzMaxTransferRecords {
			return nil, false, fmt.Errorf("transfer exceeds %d records", rpzMaxTransferRecords)
		}
		records = append(records, env.RR...)
	}
	if soas < 2 {
		// One SOA => the server answered with the full zone (already complete:
		// parse it directly). Zero => not a usable IXFR answer at all.
		if soas == 1 && len(records) > 1 {
			domains, err := rpzOwners(records, zone)
			if err != nil {
				return nil, false, err
			}
			return domains, true, nil
		}
		return nil, false, nil
	}
	// A genuine delta starts with SOA(oldSerial) and its second SOA carries the new
	// serial. Two SOAs with the SAME serial mean the server answered with the full
	// zone (how miekg/dns terminates a full-transfer IXFR): parse it directly.
	firstSOA, lastSOA := soaSerial(records)
	if firstSOA == lastSOA {
		domains, err := rpzOwners(records, zone)
		if err != nil {
			return nil, false, err
		}
		return domains, true, nil
	}
	// Delta layout: SOA(oldSerial), deletions..., SOA(newSerial), additions...
	section := 0
	for _, rr := range records {
		if rr.Header().Rrtype == dns.TypeSOA {
			section++
			continue
		}
		names, err := ownerNames(rr, zone)
		if err != nil {
			return nil, false, err
		}
		if section == 1 {
			for _, n := range names {
				delete(base, n)
			}
		} else if section >= 2 {
			for _, n := range names {
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

// soaSerial returns the serial of the first and last SOA in a transfer stream.
func soaSerial(records []dns.RR) (uint32, uint32) {
	var first, last uint32
	for _, rr := range records {
		if soa, ok := rr.(*dns.SOA); ok {
			if first == 0 {
				first = soa.Serial
			}
			last = soa.Serial
		}
	}
	return first, last
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
