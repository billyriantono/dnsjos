package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultsValidate(t *testing.T) {
	if err := DefaultConfigSpec().Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestIPAliasValid checks a well-formed ip-alias spec (IPv4 and IPv6 rules) validates.
func TestIPAliasValid(t *testing.T) {
	s := DefaultConfigSpec()
	s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{
		{Name: "cf", MatchPools: []string{"104.16.0.0/13", "172.64.0.0/13"},
			Targets: []string{"172.64.52.159", "172.64.87.224"}, Exclude: []string{"cftunnel.com"}},
		{Name: "cf6", MatchPools: []string{"2606:4700::/32"},
			Targets: []string{"2606:4700:3030::1", "2606:4700:3030::2"}},
		// Dotted-tail pools are accepted: dnsdist's NetmaskGroup matches them against
		// the hex wire form (CIDR and bare alike). Targets must stay plain, though.
		{Name: "nat64", MatchPools: []string{"64:ff9b::1.2.3.0/120", "64:ff9b::5.6.7.8"},
			Targets: []string{"64:ff9b::909:909"}},
	}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*ConfigSpec){
		"acl":             func(s *ConfigSpec) { s.ACL = []string{"10.0.0.0/33"} },
		"empty acl":       func(s *ConfigSpec) { s.ACL = nil },
		"do53 addr":       func(s *ConfigSpec) { s.Listen.Do53.Addresses = []string{"0.0.0.0"} },
		"do53 ipv6 only":  func(s *ConfigSpec) { s.Listen.Do53.Addresses = []string{"[::]:53"} },
		"weight 0":        func(s *ConfigSpec) { s.Upstreams.Servers[0].Weight = 0 },
		"weight 1001":     func(s *ConfigSpec) { s.Upstreams.Servers[0].Weight = 1001 },
		"upstream addr":   func(s *ConfigSpec) { s.Upstreams.Servers[0].Address = "dns.google:53" },
		"policy":          func(s *ConfigSpec) { s.Upstreams.Policy = "random" },
		"no servers":      func(s *ConfigSpec) { s.Upstreams.Servers = nil },
		"cache":           func(s *ConfigSpec) { s.Cache.MaxEntries = 0 },
		"ttl order":       func(s *ConfigSpec) { s.Cache.MinTTL, s.Cache.MaxTTL = 100, 10 },
		"blockpage v4":    func(s *ConfigSpec) { s.Blocking.BlockpageIPv4 = "::1" },
		"blockpage v6":    func(s *ConfigSpec) { s.Blocking.BlockpageIPv6 = "1.2.3.4" },
		"blockpage multi": func(s *ConfigSpec) { s.Blocking.BlockpageIPv4 = "192.0.2.10, nope" },
		"blockpage too many": func(s *ConfigSpec) {
			s.Blocking.BlockpageIPv4 = "192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, 192.0.2.5, 192.0.2.6, 192.0.2.7, 192.0.2.8, 192.0.2.9"
		},
		"soa":              func(s *ConfigSpec) { s.Blocking.SOA = "x" },
		"txt newline":      func(s *ConfigSpec) { s.Blocking.TXT = "a\nb" },
		"qps":              func(s *ConfigSpec) { s.Abuse.PerClientQPS = -1 },
		"dyn action":       func(s *ConfigSpec) { s.Abuse.DynAction = "nuke" },
		"trusted":          func(s *ConfigSpec) { s.Abuse.Trusted = []string{"nope"} },
		"rewrite pool":     func(s *ConfigSpec) { s.CGK.RewritePools = append(s.CGK.RewritePools, "1.2.3.0/40") },
		"alias pool":       func(s *ConfigSpec) { s.CGK.AliasPools = []string{"x"} },
		"min_ok":           func(s *ConfigSpec) { s.CGK.MinOK = 99 },
		"aliases_wanted":   func(s *ConfigSpec) { s.CGK.AliasesWanted = 0 },
		"doh without tls":  func(s *ConfigSpec) { s.Listen.DoH.Enabled = true; s.Listen.TLS.CertFile = "" },
		"nothing enabled":  func(s *ConfigSpec) { s.Listen.Do53.Enabled = false },
		"upstream name":    func(s *ConfigSpec) { s.Upstreams.Servers[0].Name = `a"b` },
		"webserver listen": func(s *ConfigSpec) { s.Webserver.Listen = "localhost:8083" },
		"exclude hostname": func(s *ConfigSpec) { s.CGK.Exclude = []string{"bad domain"} },
		"ip_alias no name": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{MatchPools: []string{"104.16.0.0/13"}, Targets: []string{"1.2.3.4"}}}}
		},
		"ip_alias no pools": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", Targets: []string{"1.2.3.4"}}}}
		},
		"ip_alias bad pool": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", MatchPools: []string{"104.16.0.0/40"}, Targets: []string{"1.2.3.4"}}}}
		},
		"ip_alias no targets": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", MatchPools: []string{"104.16.0.0/13"}}}}
		},
		"ip_alias bad target": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", MatchPools: []string{"104.16.0.0/13"}, Targets: []string{"nope"}}}}
		},
		"ip_alias mixed families": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", MatchPools: []string{"104.16.0.0/13"}, Targets: []string{"1.2.3.4", "2001:db8::1"}}}}
		},
		"ip_alias bad exclude": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", MatchPools: []string{"104.16.0.0/13"}, Targets: []string{"1.2.3.4"}, Exclude: []string{"bad domain"}}}}
		},
		"ip_alias zoned target": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf6", MatchPools: []string{"2606:4700::/32"}, Targets: []string{"fe80::1%eth0"}}}}
		},
		"ip_alias mapped target": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", MatchPools: []string{"104.16.0.0/13"}, Targets: []string{"::ffff:1.2.3.4"}}}}
		},
		"ip_alias mapped hex target": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", MatchPools: []string{"104.16.0.0/13"}, Targets: []string{"::ffff:102:304"}}}}
		},
		"ip_alias dotted target": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf6", MatchPools: []string{"2606:4700::/32"}, Targets: []string{"64:ff9b::1.2.3.4"}}}}
		},
		"ip_alias mapped pool": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", MatchPools: []string{"::ffff:104.16.0.0/120"}, Targets: []string{"172.64.52.159"}}}}
		},
		"ip_alias zoned pool": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf6", MatchPools: []string{"fe80::1%eth0"}, Targets: []string{"2606:4700:3030::1"}}}}
		},
		"ip_alias v6 pool v4 target": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf", MatchPools: []string{"2606:4700::/32"}, Targets: []string{"172.64.52.159"}}}}
		},
		"ip_alias v4 pool v6 target": func(s *ConfigSpec) {
			s.IPAlias = IPAlias{Enabled: true, Rules: []IPAliasRule{{Name: "cf6", MatchPools: []string{"104.16.0.0/13"}, Targets: []string{"2606:4700:3030::1"}}}}
		},
		"sample_rate": func(s *ConfigSpec) { s.Analytics.SampleRate = 1001 },
		"top_k":       func(s *ConfigSpec) { s.Analytics.TopK = 99 },
		"stream_addr": func(s *ConfigSpec) { s.Analytics.StreamAddr = "localhost:6001" },
	}
	for name, mutate := range cases {
		s := DefaultConfigSpec()
		mutate(&s)
		if s.Validate() == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestMergeSpec(t *testing.T) {
	base := DefaultConfigSpec()

	// nested objects merge, scalars replace, other fields untouched
	got, err := MergeSpec(base, json.RawMessage(`{"cache":{"max_entries":42},"abuse":{"dyn_action":"drop"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Cache.MaxEntries != 42 || !got.Cache.Enabled || got.Cache.MaxTTL != 86400 {
		t.Errorf("cache merge: %+v", got.Cache)
	}
	if got.Abuse.DynAction != "drop" || got.Abuse.PerClientQPS != 50 {
		t.Errorf("abuse merge: %+v", got.Abuse)
	}

	// arrays replace
	got, _ = MergeSpec(base, json.RawMessage(`{"acl":["192.0.2.0/24"]}`))
	if len(got.ACL) != 1 || got.ACL[0] != "192.0.2.0/24" {
		t.Errorf("acl: %v", got.ACL)
	}

	// null deletes (field falls back to its zero value)
	got, _ = MergeSpec(base, json.RawMessage(`{"tuning":{"udp_buffer_bytes":null},"acl":null}`))
	if got.Tuning.UDPBufferBytes != 0 || got.ACL != nil {
		t.Errorf("null delete: %+v %v", got.Tuning, got.ACL)
	}

	// empty patches are no-ops; base is not mutated
	for _, p := range []string{``, `null`, `{}`} {
		got, err = MergeSpec(base, json.RawMessage(p))
		if err != nil || got.Upstreams.Servers[0].Weight != base.Upstreams.Servers[0].Weight {
			t.Errorf("patch %q: %v", p, err)
		}
	}
	if base.Cache.MaxEntries != 500000 {
		t.Error("base mutated")
	}

	for _, p := range []string{`[1]`, `{"cache":{"max_entries":"x"}}`, `{`} {
		if _, err := MergeSpec(base, json.RawMessage(p)); err == nil {
			t.Errorf("patch %q: expected error", p)
		}
	}
}

func TestSpecJSONShape(t *testing.T) {
	b, _ := json.Marshal(DefaultConfigSpec())
	for _, k := range []string{`"reuse_port_listeners":1`, `"health_check_interval_s":1`, `"dyn_nxdomain_rate":15`,
		`"blockpage_ipv6":"2001:db8::10"`, `"prometheus_acl":["127.0.0.1/32"]`, `"min_ok":3`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing %s", k)
		}
	}
}

func TestCommandValidate(t *testing.T) {
	avail, series := []string{"2.0.1-1pdns.bookworm"}, []string{"20", "21"}
	ok := []CommandRequest{{Type: CmdReapply}, {Type: CmdCheckUpdates}, {Type: CmdUpgradeAgent},
		{Type: CmdUpgradeDnsdist, Version: avail[0]}, {Type: CmdSetDnsdistSeries, Series: "21"}}
	bad := []CommandRequest{{Type: "nuke"}, {Type: CmdUpgradeDnsdist}, {Type: CmdUpgradeDnsdist, Version: "9.9"},
		{Type: CmdSetDnsdistSeries, Series: "19"}, {Type: CmdSetDnsdistSeries}, {Type: CmdReapply, Version: avail[0]},
		{Type: CmdUpgradeDnsdist, Version: avail[0], Series: "21"}}
	for _, r := range ok {
		if err := r.Validate(avail, series); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	for _, r := range bad {
		if r.Validate(avail, series) == nil {
			t.Errorf("%+v: expected error", r)
		}
	}
}

func TestUpgradeRunCreateValidate(t *testing.T) {
	for _, c := range []UpgradeRunCreate{{Kind: UpgradeAgent}, {Kind: UpgradeDnsdist, TargetVersion: "2.0.1", NodeIDs: []string{"a", "b"}}} {
		if err := c.Validate(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	for _, c := range []UpgradeRunCreate{{Kind: "os"}, {Kind: UpgradeDnsdist}, {Kind: UpgradeAgent, NodeIDs: []string{"a", "a"}}} {
		if c.Validate() == nil {
			t.Errorf("%+v: expected error", c)
		}
	}
}

func TestSpecMissingAnalyticsGetsDefaults(t *testing.T) {
	raw, _ := json.Marshal(DefaultConfigSpec())
	var m map[string]any
	json.Unmarshal(raw, &m)
	delete(m, "analytics")
	raw, _ = json.Marshal(m)
	var s ConfigSpec
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if s.Analytics != DefaultAnalytics() || s.Validate() != nil {
		t.Errorf("analytics = %+v, validate = %v", s.Analytics, s.Validate())
	}
	if err := json.Unmarshal([]byte(`{"analytics":{"enabled":false}}`), &s); err != nil || s.Analytics.Enabled || s.Analytics.TopK != 5000 {
		t.Errorf("partial analytics: %+v %v", s.Analytics, err)
	}
}

func TestAnalyticsBatchValidate(t *testing.T) {
	ok := AnalyticsBatch{Day: "2026-01-02", Total: 10, SampleRate: 1,
		ByQType: map[string]int64{"A": 10}, ByRcode: map[string]int64{"NOERROR": 10},
		Tops: map[string][]AnalyticsTopItem{AnalyticsQueried: {{Name: "example.com", Count: 10, Error: 2}}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	cum := ok
	cum.TopsMode, cum.Epoch, cum.Evicted = AnalyticsTopsCumulative, "e1", map[string][]string{AnalyticsQueried: {"gone.example"}}
	if err := cum.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*AnalyticsBatch){
		"tops_mode":     func(b *AnalyticsBatch) { b.TopsMode = "absolute" },
		"no epoch":      func(b *AnalyticsBatch) { b.TopsMode = AnalyticsTopsCumulative },
		"delta evicted": func(b *AnalyticsBatch) { b.Evicted = map[string][]string{AnalyticsQueried: {"x.example"}} },
		"evicted kind": func(b *AnalyticsBatch) {
			b.TopsMode, b.Epoch, b.Evicted = AnalyticsTopsCumulative, "e", map[string][]string{"clients": nil}
		},
		"evicted bad name": func(b *AnalyticsBatch) {
			b.TopsMode, b.Epoch, b.Evicted = AnalyticsTopsCumulative, "e", map[string][]string{AnalyticsQueried: {""}}
		},
		"day":         func(b *AnalyticsBatch) { b.Day = "2026-1-2" },
		"total":       func(b *AnalyticsBatch) { b.Total = -1 },
		"sample_rate": func(b *AnalyticsBatch) { b.SampleRate = 0 },
		"qtype":       func(b *AnalyticsBatch) { b.ByQType = map[string]int64{"A": -1} },
		"kind":        func(b *AnalyticsBatch) { b.Tops = map[string][]AnalyticsTopItem{"clients": nil} },
		"error>count": func(b *AnalyticsBatch) {
			b.Tops = map[string][]AnalyticsTopItem{AnalyticsNXDomain: {{Name: "x.invalid", Count: 1, Error: 2}}}
		},
		"empty name": func(b *AnalyticsBatch) { b.Tops = map[string][]AnalyticsTopItem{AnalyticsServfail: {{Count: 1}}} },
	} {
		b := ok
		mutate(&b)
		if b.Validate() == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}
