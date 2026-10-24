package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

var (
	nameRe     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*\.?$`)
)

// Validate reports every problem in the spec, joined into one error (nil when valid).
func (s ConfigSpec) Validate() error {
	var errs []error
	bad := func(field, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", field, fmt.Sprintf(format, a...)))
	}
	addrs := func(field string, list []string, required bool) {
		if required && len(list) == 0 {
			bad(field, "at least one address required")
		}
		for i, a := range list {
			if _, err := netip.ParseAddrPort(a); err != nil {
				bad(fmt.Sprintf("%s[%d]", field, i), "%q is not ip:port", a)
			}
		}
	}
	prefixes := func(field string, list []string) {
		for i, p := range list {
			if !validPrefix(p) {
				bad(fmt.Sprintf("%s[%d]", field, i), "%q is not a CIDR", p)
			}
		}
	}
	hostnames := func(field string, list []string) {
		for i, h := range list {
			if len(h) > 253 || !hostnameRe.MatchString(h) {
				bad(fmt.Sprintf("%s[%d]", field, i), "%q is not a domain name", h)
			}
		}
	}
	between := func(field string, v, lo, hi int) {
		if v < lo || v > hi {
			bad(field, "must be %d..%d, got %d", lo, hi, v)
		}
	}
	text := func(field, v string) {
		if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			bad(field, "must not contain control characters")
		}
	}

	l := s.Listen
	if !l.Do53.Enabled && !l.DoH.Enabled && !l.DoT.Enabled {
		bad("listen", "at least one of do53, doh, dot must be enabled")
	}
	addrs("listen.do53.addresses", l.Do53.Addresses, l.Do53.Enabled)
	if l.Do53.Enabled {
		between("listen.do53.reuse_port_listeners", l.Do53.ReusePortListeners, 1, 64)
		// "[::]:53" alone does not take IPv4: dnsdist binds IPv6 sockets v6-only, so every
		// IPv4 client would get no answer (a dns3 outage once).
		if len(l.Do53.Addresses) > 0 && !slices.ContainsFunc(l.Do53.Addresses, func(a string) bool {
			ap, err := netip.ParseAddrPort(a)
			return err == nil && ap.Addr().Is4()
		}) {
			bad("listen.do53.addresses", "no IPv4 address, so IPv4 clients get no answer: add 0.0.0.0:53")
		}
	}
	addrs("listen.doh.addresses", l.DoH.Addresses, l.DoH.Enabled)
	if l.DoH.Enabled && !strings.HasPrefix(l.DoH.Path, "/") {
		bad("listen.doh.path", "must start with /")
	}
	text("listen.doh.path", l.DoH.Path)
	addrs("listen.dot.addresses", l.DoT.Addresses, l.DoT.Enabled)
	if l.DoH.Enabled || l.DoT.Enabled {
		if !strings.HasPrefix(l.TLS.CertFile, "/") {
			bad("listen.tls.cert_file", "absolute path required when DoH/DoT is enabled")
		}
		if !strings.HasPrefix(l.TLS.KeyFile, "/") {
			bad("listen.tls.key_file", "absolute path required when DoH/DoT is enabled")
		}
	}
	text("listen.tls.cert_file", l.TLS.CertFile)
	text("listen.tls.key_file", l.TLS.KeyFile)

	if len(s.ACL) == 0 {
		bad("acl", "at least one CIDR required")
	}
	prefixes("acl", s.ACL)

	u := s.Upstreams
	if !slices.Contains(Policies, u.Policy) {
		bad("upstreams.policy", "must be one of %s", strings.Join(Policies, ", "))
	}
	if len(u.Servers) == 0 {
		bad("upstreams.servers", "at least one server required")
	}
	for i, srv := range u.Servers {
		f := fmt.Sprintf("upstreams.servers[%d]", i)
		addrs(f+".address", []string{srv.Address}, true)
		between(f+".weight", srv.Weight, 1, 1000)
		between(f+".order", srv.Order, 1, 1000)
		between(f+".sockets", srv.Sockets, 1, 64)
		if srv.Name != "" && !nameRe.MatchString(srv.Name) {
			bad(f+".name", "only letters, digits, '.', '_' and '-' (max 64)")
		}
	}
	between("upstreams.health_check_interval_s", u.HealthCheckIntervalS, 1, 3600)
	between("upstreams.latency_floor_ms", u.LatencyFloorMs, 0, 10_000)
	between("upstreams.ecs_prefix_v4", u.ECSPrefixV4, 0, 32)
	between("upstreams.ecs_prefix_v6", u.ECSPrefixV6, 0, 128)

	c := s.Cache
	if c.Enabled {
		between("cache.max_entries", c.MaxEntries, 1, 100_000_000)
	}
	between("cache.min_ttl", c.MinTTL, 0, 604800)
	between("cache.max_ttl", c.MaxTTL, c.MinTTL, 604800)
	between("cache.stale_ttl", c.StaleTTL, 0, 604800)

	b := s.Blocking
	for _, f := range strings.FieldsFunc(b.BlockpageIPv4, func(r rune) bool { return r == ',' || r == ' ' }) {
		if a, err := netip.ParseAddr(f); b.Enabled && (err != nil || a.Zone() != "" || !a.Is4()) {
			bad("blocking.blockpage_ipv4", "%q is not an IPv4 address", f)
			break
		}
	}
	for _, f := range strings.FieldsFunc(b.BlockpageIPv6, func(r rune) bool { return r == ',' || r == ' ' }) {
		if a, err := netip.ParseAddr(f); b.Enabled && (err != nil || a.Zone() != "" || !a.Is6() || a.Is4In6()) {
			bad("blocking.blockpage_ipv6", "%q is not an IPv6 address", f)
			break
		}
	}
	if b.Enabled && len(strings.FieldsFunc(b.BlockpageIPv4, func(r rune) bool { return r == ',' || r == ' ' })) > 8 {
		bad("blocking.blockpage_ipv4", "max 8 addresses, comma-separated")
	}
	if b.Enabled && len(strings.FieldsFunc(b.BlockpageIPv6, func(r rune) bool { return r == ',' || r == ' ' })) > 8 {
		bad("blocking.blockpage_ipv6", "max 8 addresses, comma-separated")
	}
	if len(b.TXT) > 255 {
		bad("blocking.txt", "max 255 characters")
	}
	text("blocking.txt", b.TXT)
	if f := strings.Fields(b.SOA); b.Enabled && len(f) != 7 {
		bad("blocking.soa", "must be 'mname rname serial refresh retry expire minimum'")
	}
	text("blocking.soa", b.SOA)
	if b.Enabled && !hostnameRe.MatchString(b.NS) {
		bad("blocking.ns", "%q is not a domain name", b.NS)
	}

	a := s.Abuse
	if a.Enabled {
		between("abuse.per_client_qps", a.PerClientQPS, 1, 1_000_000)
		between("abuse.per_client_burst", a.PerClientBurst, a.PerClientQPS, 10_000_000)
		between("abuse.dyn_query_rate", a.DynQueryRate, 1, 1_000_000)
		between("abuse.dyn_nxdomain_rate", a.DynNXDomainRate, 1, 1_000_000)
		between("abuse.dyn_servfail_rate", a.DynServfailRate, 1, 1_000_000)
		between("abuse.dyn_window_s", a.DynWindowS, 1, 3600)
		between("abuse.dyn_block_s", a.DynBlockS, 1, 86400)
		if !slices.Contains(DynActions, a.DynAction) {
			bad("abuse.dyn_action", "must be one of %s", strings.Join(DynActions, ", "))
		}
	}
	prefixes("abuse.trusted", a.Trusted)

	g := s.CGK
	if g.Enabled {
		if len(g.RewritePools) == 0 {
			bad("cgk.rewrite_pools", "at least one CIDR required")
		}
		if len(g.AliasPools) == 0 {
			bad("cgk.alias_pools", "at least one CIDR required")
		}
		between("cgk.aliases_wanted", g.AliasesWanted, 1, 256)
		between("cgk.min_ok", g.MinOK, 1, max(len(g.TestSites), 1))
		between("cgk.refresh_interval_h", g.RefreshIntervalH, 1, 168)
	}
	prefixes("cgk.rewrite_pools", g.RewritePools)
	prefixes("cgk.alias_pools", g.AliasPools)
	hostnames("cgk.test_sites", g.TestSites)
	hostnames("cgk.exclude", g.Exclude)

	if _, err := ParseSpeedCheckMode(s.SpeedCheck.Mode); err != nil {
		bad("speed_check.mode", "%v", err)
	}
	if m := s.SpeedCheck.AnswerMode; m != "" && m != AnswerModeFastestIP && m != AnswerModeFastestResponse {
		bad("speed_check.answer_mode", "must be %s or %s", AnswerModeFastestIP, AnswerModeFastestResponse)
	}
	between("speed_check.max_reply_ip_num", s.SpeedCheck.MaxReplyIPNum, 0, 64)
	between("speed_check.max_response", s.SpeedCheck.MaxResponse, 0, 64)
	hostnames("speed_check.exclude", s.SpeedCheck.Exclude)
	for i, r := range s.CName.Rules {
		if !hostnameRe.MatchString(strings.TrimSuffix(r.Name, ".")) {
			bad(fmt.Sprintf("cname.rules[%d].name", i), "%q is not a domain name", r.Name)
		}
		if !hostnameRe.MatchString(strings.TrimSuffix(r.Target, ".")) {
			bad(fmt.Sprintf("cname.rules[%d].target", i), "%q is not a domain name", r.Target)
		}
	}
	between("dualstack.threshold_ms", s.DualStack.ThresholdMs, 0, 1000)
	hostnames("dualstack.exclude", s.DualStack.Exclude)
	if ia := s.IPAlias; ia.Enabled {
		for i, r := range ia.Rules {
			field := fmt.Sprintf("ip_alias.rules[%d]", i)
			if strings.TrimSpace(r.Name) == "" {
				bad(field+".name", "required")
			}
			prefixes(field+".match_pools", r.MatchPools)
			if len(r.MatchPools) == 0 {
				bad(field+".match_pools", "at least one CIDR required")
			}
			if len(r.Targets) == 0 {
				bad(field+".targets", "at least one address required")
			}
			ipv6 := false
			for j, t := range r.Targets {
				f := fmt.Sprintf("%s.targets[%d]", field, j)
				a, err := netip.ParseAddr(t)
				if err != nil {
					bad(f, "%q is not an IP address", t)
					continue
				}
				// dnsdist and the Lua target encoder silently drop zoned, IPv4-mapped and
				// dotted-tail forms (a rule whose targets all drop is dead): reject them.
				switch {
				case a.Zone() != "":
					bad(f, "%q carries a zone; zones are not supported", t)
				case a.Is4In6():
					bad(f, "%q is an IPv4-mapped IPv6 address; write its IPv4 form", t)
				case a.Is6() && strings.Contains(t, "."):
					bad(f, "%q has a dotted tail; write the IPv6 address in hex", t)
				}
				if j == 0 {
					ipv6 = a.Is6() && !a.Is4In6()
					continue
				}
				if is6 := a.Is6() && !a.Is4In6(); is6 != ipv6 {
					bad(f, "must be the same address family as targets[0]")
				}
			}
			// dnsdist's NetmaskGroup matches nothing for an IPv4-mapped pool, and a pool
			// of the other family than the targets can never match either: dead rules.
			for j, p := range r.MatchPools {
				f := fmt.Sprintf("%s.match_pools[%d]", field, j)
				pa, err := netip.ParsePrefix(p)
				if err != nil {
					a, aerr := netip.ParseAddr(p)
					if aerr != nil {
						continue // the syntax error is already reported by prefixes()
					}
					pa = netip.PrefixFrom(a, a.BitLen())
				}
				switch {
				case pa.Addr().Zone() != "":
					bad(f, "zones are not supported in match_pools")
				case pa.Addr().Is4In6():
					bad(f, "%q is an IPv4-mapped IPv6 prefix; write its IPv4 form", p)
				case pa.Addr().Is6() != ipv6:
					bad(f, "must be the same address family as targets[0]")
				}
			}
			hostnames(field+".exclude", r.Exclude)
		}
	}
	hostnames("dnssec.exclude", s.DNSSEC.Exclude)

	between("tuning.udp_buffer_bytes", s.Tuning.UDPBufferBytes, 0, 1<<30)
	between("tuning.tcp_workers", s.Tuning.TCPWorkers, 0, 1024)

	addrs("webserver.listen", []string{s.Webserver.Listen}, true)
	prefixes("webserver.prometheus_acl", s.Webserver.PrometheusACL)

	if an := s.Analytics; an.Enabled {
		between("analytics.sample_rate", an.SampleRate, 1, 1000)
		between("analytics.top_k", an.TopK, 100, 50000)
		addrs("analytics.stream_addr", []string{an.StreamAddr}, true)
	}

	return errors.Join(errs...)
}

// validPrefix accepts a CIDR or a bare address (dnsdist treats it as a /32 or /128).
func validPrefix(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil && !strings.Contains(s, "%")
}

// MergeSpec applies an RFC 7396 JSON merge patch to base. An empty or null patch
// returns base unchanged. The result is not validated.
func MergeSpec(base ConfigSpec, patch json.RawMessage) (ConfigSpec, error) {
	if p := strings.TrimSpace(string(patch)); p == "" || p == "null" || p == "{}" {
		return base, nil
	}
	var p any
	if err := unmarshalNumber(patch, &p); err != nil {
		return ConfigSpec{}, fmt.Errorf("overrides: %w", err)
	}
	if _, ok := p.(map[string]any); !ok {
		return ConfigSpec{}, errors.New("overrides: must be a JSON object")
	}
	raw, err := json.Marshal(base)
	if err != nil {
		return ConfigSpec{}, err
	}
	var target any
	if err := unmarshalNumber(raw, &target); err != nil {
		return ConfigSpec{}, err
	}
	merged, err := json.Marshal(mergePatch(target, p))
	if err != nil {
		return ConfigSpec{}, err
	}
	var out ConfigSpec
	if err := json.Unmarshal(merged, &out); err != nil {
		return ConfigSpec{}, fmt.Errorf("overrides: %w", err)
	}
	return out, nil
}

func mergePatch(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok {
		t = map[string]any{}
	}
	for k, v := range p {
		if v == nil {
			delete(t, k)
		} else {
			t[k] = mergePatch(t[k], v)
		}
	}
	return t
}

func unmarshalNumber(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	return d.Decode(v)
}
