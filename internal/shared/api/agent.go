package api

import (
	"encoding/json"
	"time"
)

// Agent protocol (SPEC §8). All /agent/v1 requests carry
// "Authorization: Bearer <node_token>" and "X-Dnsjos-Agent: <version>".

const (
	AgentHeader    = "X-Dnsjos-Agent"
	Sha256Header   = "X-Dnsjos-Sha256"
	DefaultPollS   = 15
	DefaultHeartbS = 10
)

type EnrollRequest struct {
	Token          string `json:"token"`
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	AgentVersion   string `json:"agent_version"`
	DnsdistVersion string `json:"dnsdist_version"`
	PublicIP       string `json:"public_ip"`
	// Adopt marks a live dnsdist server taken over in place (SPEC §17); AdoptOverrides is
	// a JSON merge patch (kept secrets' webserver listen/ACL) stored as the node overrides.
	Adopt          bool            `json:"adopt,omitempty"`
	AdoptOverrides json.RawMessage `json:"adopt_overrides,omitempty"`
}

type EnrollResponse struct {
	NodeID        string `json:"node_id"`
	Name          string `json:"name"`
	NodeToken     string `json:"node_token"`
	PollIntervalS int    `json:"poll_interval_s"`
}

// AgentConfig is GET /agent/v1/config; Spec is the effective (merged) spec.
type AgentConfig struct {
	Version            int          `json:"version"`
	Spec               ConfigSpec   `json:"spec"`
	Profile            string       `json:"profile"`
	Blocklist          BlocklistRef `json:"blocklist"`
	PollIntervalS      int          `json:"poll_interval_s"`
	HeartbeatIntervalS int          `json:"heartbeat_interval_s"`
	// AllowlistVersion is the ETag of GET /agent/v1/allowlist (SPEC §7.5).
	AllowlistVersion string `json:"allowlist_version"`
}

type BlocklistRef struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	URL    string `json:"url"`
}

type Heartbeat struct {
	Time                 time.Time     `json:"time"`
	AgentVersion         string        `json:"agent_version"`
	DnsdistVersion       string        `json:"dnsdist_version"`
	OS                   string        `json:"os"`
	UptimeS              int64         `json:"uptime_s"`
	DnsdistRunning       bool          `json:"dnsdist_running"`
	AppliedConfigVersion int           `json:"applied_config_version"`
	ApplyError           string        `json:"apply_error"`
	BlocklistSHA256      string        `json:"blocklist_sha256"`
	BlocklistError       string        `json:"blocklist_error"`
	System               SystemStats   `json:"system"`
	Counters             Counters      `json:"counters"`
	LatencyAvgMs         float64       `json:"latency_avg_ms"`
	Backends             []BackendStat `json:"backends"`
	DynBlocks            []DynBlock    `json:"dynblocks"`
	CGK                  CGKStatus     `json:"cgk"`
	AckedCommands        []int64       `json:"acked_commands,omitempty"`
	// Upgrade inventory (SPEC §18): refreshed every 6 h and on check_updates, repeated in
	// every heartbeat; InventoryAt is nil until the first refresh.
	DnsdistCandidate  string         `json:"dnsdist_candidate"`
	DnsdistAvailable  []string       `json:"dnsdist_available"`
	DnsdistRepoSeries string         `json:"dnsdist_repo_series"`
	InventoryAt       *time.Time     `json:"inventory_at"`
	LastUpgrade       *UpgradeResult `json:"last_upgrade"`
	UpgradeInProgress bool           `json:"upgrade_in_progress"`
	// AllowlistVersion is the allowlist the node enforces ("" = none applied yet).
	AllowlistVersion string `json:"allowlist_version"`
}

// UpgradeResult is the outcome of the node's most recent upgrade_dnsdist / upgrade_agent.
type UpgradeResult struct {
	Kind  string    `json:"kind"` // UpgradeDnsdist | UpgradeAgent
	From  string    `json:"from"`
	To    string    `json:"to"`
	OK    bool      `json:"ok"`
	Error string    `json:"error"`
	At    time.Time `json:"at"`
}

type SystemStats struct {
	Load1      float64 `json:"load1"`
	MemTotalMB int64   `json:"mem_total_mb"`
	MemAvailMB int64   `json:"mem_avail_mb"`
	DiskFreeMB int64   `json:"disk_free_mb"`
}

// Counters are raw, monotonically increasing dnsdist values; the panel computes deltas.
type Counters struct {
	Queries     int64 `json:"queries"`
	Responses   int64 `json:"responses"`
	CacheHits   int64 `json:"cache_hits"`
	CacheMisses int64 `json:"cache_misses"`
	Blocked     int64 `json:"blocked"`
	DynBlocked  int64 `json:"dyn_blocked"`
	RuleDrops   int64 `json:"rule_drops"`
	Servfail    int64 `json:"servfail"`
	NXDomain    int64 `json:"nxdomain"`
	NoError     int64 `json:"noerror"`
	CGKRewrites int64 `json:"cgk_rewrites"`
}

type BackendStat struct {
	Address   string  `json:"address"`
	Name      string  `json:"name"`
	Pool      string  `json:"pool"`
	State     string  `json:"state"`
	Weight    int     `json:"weight"`
	Order     int     `json:"order"`
	QPS       float64 `json:"qps"`
	LatencyMs float64 `json:"latency_ms"`
	Queries   int64   `json:"queries"`
	Drops     int64   `json:"drops"`
}

type DynBlock struct {
	Client      string `json:"client"`
	Reason      string `json:"reason"`
	Stage       string `json:"stage"` // warning | blocked
	SecondsLeft int    `json:"seconds_left"`
	Blocks      int64  `json:"blocks"`
}

type CGKStatus struct {
	Aliases       int        `json:"aliases"`
	Aliases6      int        `json:"aliases6"`
	RewriteRanges int        `json:"rewrite_ranges"`
	LastRefresh   *time.Time `json:"last_refresh,omitempty"`
	LastError     string     `json:"last_error"`
}

type HeartbeatAck struct {
	ConfigVersion   int       `json:"config_version"`
	BlocklistSHA256 string    `json:"blocklist_sha256"`
	Commands        []Command `json:"commands,omitempty"`
	// AllowlistVersion changes with the active allowlist; the agent re-fetches it then.
	AllowlistVersion string `json:"allowlist_version"`
}

const (
	CmdCGKRefresh     = "cgk_refresh"
	CmdRestartDnsdist = "restart_dnsdist"
	CmdReapply        = "reapply"
	// SPEC §18.
	CmdCheckUpdates     = "check_updates"
	CmdUpgradeDnsdist   = "upgrade_dnsdist"    // Version required
	CmdSetDnsdistSeries = "set_dnsdist_series" // Series required
	CmdUpgradeAgent     = "upgrade_agent"
)

var CommandTypes = []string{CmdCGKRefresh, CmdRestartDnsdist, CmdReapply,
	CmdCheckUpdates, CmdUpgradeDnsdist, CmdSetDnsdistSeries, CmdUpgradeAgent}

// Command is queued by the UI and delivered once; the agent echoes ID in AckedCommands.
// Version/Series are the params of upgrade_dnsdist / set_dnsdist_series (node_commands.params).
type Command struct {
	ID      int64  `json:"id"`
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
	Series  string `json:"series,omitempty"`
}

type BlockedBatch struct {
	Items []BlockedItem `json:"items"`
}

type BlockedItem struct {
	Day   string `json:"day"` // YYYY-MM-DD
	QName string `json:"qname"`
	QType string `json:"qtype"`
	Count int64  `json:"count"`
}

// IPv6 half of a CGK measurement (CGKReport.IPv6, SPEC §6.7).
const (
	CGKIPv6OK             = "ok"
	CGKIPv6NotConfigured  = "not_configured"  // no IPv6 rewrite or alias pools in the profile
	CGKIPv6NoConnectivity = "no_connectivity" // no IPv6 sample answered: the node has no IPv6
	CGKIPv6TooFewAliases  = "too_few_aliases" // fewer than min_ok IPv6 aliases qualified
)

type CGKReport struct {
	MeasuredAt    time.Time `json:"measured_at"`
	Aliases       []string  `json:"aliases"`
	Aliases6      []string  `json:"aliases6"`
	IPv6          string    `json:"ipv6"` // CGKIPv6*; "" from agents older than IPv6 support
	RewriteRanges []string  `json:"rewrite_ranges"`
	Pools         []CGKPool `json:"pools"`
	OK            bool      `json:"ok"`
	Message       string    `json:"message"`
}

// CGKLearned is one rewritten name the agent checked through its CGK alias (SPEC §6.6).
type CGKLearned struct {
	Name      string    `json:"name"`
	RealIP    string    `json:"real_ip"`
	AliasIP   string    `json:"alias_ip"`
	RealCode  string    `json:"real_code"`  // HTTP status via the real IP; "000" = no HTTPS answer
	AliasCode string    `json:"alias_code"` // HTTP status via the alias
	Excluded  bool      `json:"excluded"`
	Hits      int64     `json:"hits"` // rewritten answers counted since first seen
	CheckedAt time.Time `json:"checked_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// CGKLearnedReport is POST /agent/v1/cgk/learned: the node's learned exclusions.
type CGKLearnedReport struct {
	Excluded []CGKLearned `json:"excluded"`
	Checked  int          `json:"checked"` // names with a verdict (ok or excluded)
	At       time.Time    `json:"at"`
}

type CGKPool struct {
	Net   string   `json:"net"`
	Colos []string `json:"colos"`
}

// NodeRuntime carries node-local secrets and paths for dnsconf.Render (SPEC §6.4).
// It never leaves the node.
type NodeRuntime struct {
	ConsoleKey  string `json:"console_key"` // base64, 32 bytes
	WebPassword string `json:"web_password"`
	WebAPIKey   string `json:"web_api_key"`
	CDBPath     string `json:"cdb_path"`    // /var/lib/dnsjos/blocklist/current.cdb
	DnstapAddr  string `json:"dnstap_addr"` // 127.0.0.1:6000
	Hostname    string `json:"hostname"`
	BaseDir     string `json:"base_dir"` // dir the modules are dofile'd from; default /etc/dnsdist
}
