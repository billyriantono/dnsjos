// Package api holds the JSON types shared by the panel, the agent and the web UI
// (SPEC §6, §8, §10). It is the single source of truth for wire formats.
package api

import (
	"fmt"
	"strconv"
	"strings"
)

// ConfigSpec is the desired state of a dnsdist node (SPEC §6).
type ConfigSpec struct {
	Listen     Listen     `json:"listen"`
	ACL        []string   `json:"acl"`
	Upstreams  Upstreams  `json:"upstreams"`
	Cache      Cache      `json:"cache"`
	Blocking   Blocking   `json:"blocking"`
	Abuse      Abuse      `json:"abuse"`
	CGK        CGK        `json:"cgk"`
	SpeedCheck SpeedCheck `json:"speed_check"`
	DualStack  DualStack  `json:"dualstack"`
	Tuning     Tuning     `json:"tuning"`
	Webserver  Webserver  `json:"webserver"`
	Analytics  Analytics  `json:"analytics"`
}

type Listen struct {
	Do53 Do53 `json:"do53"`
	DoH  DoH  `json:"doh"`
	DoT  DoT  `json:"dot"`
	TLS  TLS  `json:"tls"`
}

type Do53 struct {
	Enabled            bool     `json:"enabled"`
	Addresses          []string `json:"addresses"`
	ReusePortListeners int      `json:"reuse_port_listeners"`
}

type DoH struct {
	Enabled   bool     `json:"enabled"`
	Addresses []string `json:"addresses"`
	Path      string   `json:"path"`
}

type DoT struct {
	Enabled   bool     `json:"enabled"`
	Addresses []string `json:"addresses"`
}

type TLS struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type Upstreams struct {
	Policy               string     `json:"policy"`
	Servers              []Upstream `json:"servers"`
	HealthCheckIntervalS int        `json:"health_check_interval_s"`
	// PolicyLatencyAware only: upstreams answering faster than this count as equally fast
	// (0 = 20 ms), so normal jitter does not reshuffle which upstream serves a name.
	LatencyFloorMs int `json:"latency_floor_ms"`
}

type Upstream struct {
	Address string `json:"address"`
	Weight  int    `json:"weight"`
	Order   int    `json:"order"`
	Sockets int    `json:"sockets"`
	Name    string `json:"name"`
}

type Cache struct {
	Enabled    bool `json:"enabled"`
	MaxEntries int  `json:"max_entries"`
	MinTTL     int  `json:"min_ttl"`
	MaxTTL     int  `json:"max_ttl"`
	StaleTTL   int  `json:"stale_ttl"`
}

type Blocking struct {
	Enabled          bool   `json:"enabled"`
	BlockpageIPv4    string `json:"blockpage_ipv4"`
	BlockpageIPv6    string `json:"blockpage_ipv6"`
	TXT              string `json:"txt"`
	SOA              string `json:"soa"`
	NS               string `json:"ns"`
	BlockResponseIPs bool   `json:"block_response_ips"`
	LogBlocked       bool   `json:"log_blocked"`
}

type Abuse struct {
	Enabled         bool     `json:"enabled"`
	PerClientQPS    int      `json:"per_client_qps"`
	PerClientBurst  int      `json:"per_client_burst"`
	DynQueryRate    int      `json:"dyn_query_rate"`
	DynNXDomainRate int      `json:"dyn_nxdomain_rate"`
	DynServfailRate int      `json:"dyn_servfail_rate"`
	DynWindowS      int      `json:"dyn_window_s"`
	DynBlockS       int      `json:"dyn_block_s"`
	DynAction       string   `json:"dyn_action"`
	Trusted         []string `json:"trusted"`
}

type CGK struct {
	Enabled          bool     `json:"enabled"`
	RewritePools     []string `json:"rewrite_pools"`
	AliasPools       []string `json:"alias_pools"`
	TestSites        []string `json:"test_sites"`
	Exclude          []string `json:"exclude"`
	AliasesWanted    int      `json:"aliases_wanted"`
	MinOK            int      `json:"min_ok"`
	RefreshIntervalH int      `json:"refresh_interval_h"`
}

// DualStack answers AAAA queries empty (NODATA + SOA) for names whose IPv4 address is
// measurably faster from this node than their IPv6 one, so dual-stack clients connect over
// IPv4: smartdns' dualstack-ip-selection (SPEC §6.8). Only right on nodes that share their
// clients' IPv6 path.
type DualStack struct {
	Enabled bool `json:"enabled"`
	// IPv4 must be at least this much faster (0 = 10 ms) before AAAA answers are dropped
	// (dualstack-ip-selection-threshold).
	ThresholdMs int `json:"threshold_ms"`
	// Also drop A answers when IPv6 is faster (dualstack-ip-allow-force-AAAA).
	AllowForceAAAA bool `json:"allow_force_aaaa"`
	// Names (and their subdomains) never touched (domain-rules -dualstack-ip-selection no).
	Exclude []string `json:"exclude"`
}

// SpeedCheck is smartdns' speed test (SPEC §6.9): how the agent measures addresses (used by
// DualStack too) and whether A/AAAA answers are reduced to the fastest addresses, which is
// the answer smartdns caches and serves in every response-mode.
type SpeedCheck struct {
	// Probe methods (speed-check-mode; "" = DefaultSpeedCheckMode, "none" = no speed test).
	Mode string `json:"mode"`
	// Answer with the fastest address first plus the ones nearly as fast (smartdns).
	FastestIP bool `json:"fastest_ip"`
	// At most this many addresses per answer (max-reply-ip-num; 0 = 8).
	MaxReplyIPNum int `json:"max_reply_ip_num"`
	// Names (and their subdomains) whose answers are never reordered
	// (domain-rules -speed-check-mode none).
	Exclude []string `json:"exclude"`
}

// DefaultSpeedCheckMode is smartdns' default speed-check-mode.
const DefaultSpeedCheckMode = "ping,tcp:80,tcp:443"

// SpeedCheckMethod is one probe method: ICMP echo (Port 0) or a TCP connect to Port.
type SpeedCheckMethod struct{ Port int }

// ParseSpeedCheckMode parses "ping,tcp:80,tcp:443" ("" = DefaultSpeedCheckMode). "none"
// (no speed test) returns no methods: nothing is measured, so nothing is changed.
func ParseSpeedCheckMode(s string) ([]SpeedCheckMethod, error) {
	switch strings.TrimSpace(s) {
	case "":
		s = DefaultSpeedCheckMode
	case "none":
		return []SpeedCheckMethod{}, nil
	}
	var out []SpeedCheckMethod
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "ping" {
			out = append(out, SpeedCheckMethod{})
			continue
		}
		p, ok := strings.CutPrefix(f, "tcp:")
		n, err := strconv.Atoi(p)
		if !ok || err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q is not ping or tcp:<port>", f)
		}
		out = append(out, SpeedCheckMethod{Port: n})
	}
	return out, nil
}

type Tuning struct {
	UDPBufferBytes int    `json:"udp_buffer_bytes"`
	TCPWorkers     int    `json:"tcp_workers"`
	ExtraLua       string `json:"extra_lua"`
}

type Webserver struct {
	Listen        string   `json:"listen"`
	PrometheusACL []string `json:"prometheus_acl"`
}

// PolicyLatencyAware is whashed with each weight scaled down by the upstream's measured
// latency (a Lua FFI policy, SPEC §6.4): a slow upstream gets fewer names until it recovers.
const PolicyLatencyAware = "whashedLatency"

// Upstream server policies accepted by Upstreams.Policy.
var Policies = []string{"whashed", PolicyLatencyAware, "wrandom", "leastOutstanding", "roundrobin", "firstAvailable"}

// Dynamic block actions accepted by Abuse.DynAction.
var DynActions = []string{"truncate", "drop", "refused"}

// DefaultConfigSpec returns safe generic defaults (SPEC §12). Real deployments import
// their own profile (client ACL, upstreams, blockpage) through the panel.
func DefaultConfigSpec() ConfigSpec {
	up := func(addr, name string, w int) Upstream {
		return Upstream{Address: addr, Weight: w, Order: 1, Sockets: 4, Name: name}
	}
	return ConfigSpec{
		Listen: Listen{
			Do53: Do53{Enabled: true, Addresses: []string{"0.0.0.0:53", "[::]:53"}, ReusePortListeners: 1},
			DoH:  DoH{Addresses: []string{"0.0.0.0:443", "[::]:443"}, Path: "/dns-query"},
			DoT:  DoT{Addresses: []string{"0.0.0.0:853", "[::]:853"}},
			TLS:  TLS{CertFile: "/etc/dnsdist/tls/cert.pem", KeyFile: "/etc/dnsdist/tls/key.pem"},
		},
		// Private, CGNAT, loopback and link-local space only. Add your own public customer
		// prefixes in the panel (a profile or node override) — they are deployment data.
		ACL: []string{
			"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
			"192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
		},
		Upstreams: Upstreams{
			Policy: PolicyLatencyAware,
			Servers: []Upstream{
				up("1.1.1.1:53", "cloudflare1", 30),
				up("1.0.0.1:53", "cloudflare2", 30),
				up("8.8.8.8:53", "google1", 20),
				up("8.8.4.4:53", "google2", 20),
			},
			HealthCheckIntervalS: 1,
		},
		Cache: Cache{Enabled: true, MaxEntries: 500000, MinTTL: 0, MaxTTL: 86400, StaleTTL: 3600},
		Blocking: Blocking{
			Enabled: true,
			// Documentation addresses (RFC 5737 / RFC 3849): set your own blockpage server.
			BlockpageIPv4:    "192.0.2.10",
			BlockpageIPv6:    "2001:db8::10",
			TXT:              "BLOCKED. UU No 19, pasal 40 (2a dan 2b). Permen Kominfo No 5 2020",
			SOA:              "blocked.invalid. nobody.blocked.invalid. 1 3600 1200 604800 10800",
			NS:               "ns.blocked.invalid",
			BlockResponseIPs: false, // opt-in: legacy rules never altered answers (SPEC §6.4)
			LogBlocked:       true,
		},
		Abuse: Abuse{
			Enabled:      true,
			PerClientQPS: 50, PerClientBurst: 250,
			DynQueryRate: 40, DynNXDomainRate: 15, DynServfailRate: 15,
			DynWindowS: 10, DynBlockS: 300, DynAction: "truncate",
			Trusted: []string{"127.0.0.0/8", "::1/128"},
		},
		CGK: CGK{
			Enabled: true,
			RewritePools: []string{
				"104.20.0.0/16", "104.21.0.0/16", "104.24.0.0/16", "104.25.0.0/16",
				"104.26.0.0/16", "104.27.0.0/16", "172.66.0.0/16", "172.67.0.0/16", "188.114.96.0/20",
				// IPv6 shared pools (SPEC §6.7); only rewritten on nodes that measured IPv6.
				"2606:4700:3030::/44", "2606:4700:10::/48", "2606:4700:20::/48",
			},
			AliasPools: []string{"104.16.0.0/16", "104.17.0.0/16", "104.18.0.0/16", "104.19.0.0/16", "172.64.0.0/16",
				"2606:4700::6810:0/110"}, // = 104.16.0.0/14 in Cloudflare's IPv6 space, served from CGK
			TestSites: []string{"kincir.com", "suara.com", "jagoanhosting.com", "dewaweb.com"},
			Exclude: []string{
				"argotunnel.com", "cftunnel.com", "api.cloudflare.com", "cloudflareaccess.com",
				"cloudflareresearch.com", "acme-v02.api.letsencrypt.org", "engage.cloudflareclient.com",
				"time.cloudflare.com", "imap.hostinger.com", "smtp.hostinger.com", "help.stockbit.com",
				"chat.riotgames.com", "gitlab.com",
			},
			AliasesWanted: 8, MinOK: 3, RefreshIntervalH: 6,
		},
		SpeedCheck: SpeedCheck{Mode: DefaultSpeedCheckMode, MaxReplyIPNum: 8, Exclude: []string{}}, // fastest_ip opt-in
		DualStack:  DualStack{ThresholdMs: 10, Exclude: []string{}},                                // opt-in: see DualStack
		Tuning:     Tuning{UDPBufferBytes: 16777216},
		Webserver:  Webserver{Listen: "127.0.0.1:8083", PrometheusACL: []string{"127.0.0.1/32"}},
		Analytics:  DefaultAnalytics(),
	}
}
