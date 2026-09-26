// Package api holds the JSON types shared by the panel, the agent and the web UI
// (SPEC §6, §8, §10). It is the single source of truth for wire formats.
package api

// ConfigSpec is the desired state of a dnsdist node (SPEC §6).
type ConfigSpec struct {
	Listen    Listen    `json:"listen"`
	ACL       []string  `json:"acl"`
	Upstreams Upstreams `json:"upstreams"`
	Cache     Cache     `json:"cache"`
	Blocking  Blocking  `json:"blocking"`
	Abuse     Abuse     `json:"abuse"`
	CGK       CGK       `json:"cgk"`
	Tuning    Tuning    `json:"tuning"`
	Webserver Webserver `json:"webserver"`
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

type Tuning struct {
	UDPBufferBytes int    `json:"udp_buffer_bytes"`
	TCPWorkers     int    `json:"tcp_workers"`
	ExtraLua       string `json:"extra_lua"`
}

type Webserver struct {
	Listen        string   `json:"listen"`
	PrometheusACL []string `json:"prometheus_acl"`
}

// Upstream server policies accepted by Upstreams.Policy.
var Policies = []string{"whashed", "wrandom", "leastOutstanding", "roundrobin", "firstAvailable"}

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
			Policy: "whashed",
			Servers: []Upstream{
				up("1.1.1.1:53", "cloudflare1", 30),
				up("1.0.0.1:53", "cloudflare2", 30),
				up("8.8.8.8:53", "google1", 20),
				up("8.8.4.4:53", "google2", 20),
			},
			HealthCheckIntervalS: 1,
		},
		Cache: Cache{Enabled: true, MaxEntries: 500000, MinTTL: 0, MaxTTL: 86400, StaleTTL: 60},
		Blocking: Blocking{
			Enabled:          true,
			// Documentation addresses (RFC 5737 / RFC 3849): set your own blockpage server.
			BlockpageIPv4:    "192.0.2.10",
			BlockpageIPv6:    "2001:db8::10",
			TXT:              "BLOCKED. UU No 19, pasal 40 (2a dan 2b). Permen Kominfo No 5 2020",
			SOA:              "blocked.invalid. nobody.blocked.invalid. 1 3600 1200 604800 10800",
			NS:               "ns.blocked.invalid",
			BlockResponseIPs: true,
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
			},
			AliasPools: []string{"104.16.0.0/16", "104.17.0.0/16", "104.18.0.0/16", "104.19.0.0/16", "172.64.0.0/16"},
			TestSites:  []string{"kincir.com", "suara.com", "jagoanhosting.com", "dewaweb.com"},
			Exclude: []string{
				"argotunnel.com", "cftunnel.com", "api.cloudflare.com", "cloudflareaccess.com",
				"cloudflareresearch.com", "acme-v02.api.letsencrypt.org", "engage.cloudflareclient.com",
				"time.cloudflare.com", "imap.hostinger.com", "smtp.hostinger.com", "help.stockbit.com",
				"chat.riotgames.com", "gitlab.com",
			},
			AliasesWanted: 8, MinOK: 3, RefreshIntervalH: 6,
		},
		Tuning:    Tuning{UDPBufferBytes: 16777216},
		Webserver: Webserver{Listen: "127.0.0.1:8083", PrometheusACL: []string{"127.0.0.1/32"}},
	}
}
