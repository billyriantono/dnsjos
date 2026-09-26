package api

import (
	"encoding/json"
	"time"
)

// Panel UI API DTOs (SPEC §10). IDs are UUID strings.

type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type List[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

type User struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Session is returned by login and GET /auth/me.
type Session struct {
	User      User      `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

type PasswordChange struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

type UserCreate struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type UserPatch struct {
	Name     *string `json:"name,omitempty"`
	Role     *string `json:"role,omitempty"`
	Disabled *bool   `json:"disabled,omitempty"`
	Password *string `json:"password,omitempty"`
}

const (
	NodePending  = "pending"
	NodeOnline   = "online"
	NodeDegraded = "degraded"
	NodeOffline  = "offline"
)

type Node struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	Hostname               string            `json:"hostname"`
	PublicIP               string            `json:"public_ip"`
	Labels                 map[string]string `json:"labels"`
	Status                 string            `json:"status"`
	ProfileID              *string           `json:"profile_id"`
	ProfileName            string            `json:"profile_name"`
	Overrides              json.RawMessage   `json:"overrides"`
	EnrolledAt             *time.Time        `json:"enrolled_at"`
	LastSeenAt             *time.Time        `json:"last_seen_at"`
	AgentVersion           string            `json:"agent_version"`
	DnsdistVersion         string            `json:"dnsdist_version"`
	OS                     string            `json:"os"`
	Arch                   string            `json:"arch"`
	AppliedConfigVersion   *int              `json:"applied_config_version"`
	AppliedBlocklistSHA256 string            `json:"applied_blocklist_sha256"`
	LastError              string            `json:"last_error"`
	CreatedAt              time.Time         `json:"created_at"`
	// Computed: desired = newest published version of the node's profile / current build.
	DesiredConfigVersion   *int   `json:"desired_config_version"`
	DesiredBlocklistSHA256 string `json:"desired_blocklist_sha256"`
	ConfigInSync           bool   `json:"config_in_sync"`
	BlocklistInSync        bool   `json:"blocklist_in_sync"`
	// Live values from the latest heartbeat (0 when none).
	QPS           float64 `json:"qps"`
	CacheHitRatio float64 `json:"cache_hit_ratio"`
	LatencyAvgMs  float64 `json:"latency_avg_ms"`
	// Upgrade inventory from the latest heartbeat (SPEC §18).
	DnsdistCandidate  string         `json:"dnsdist_candidate"`
	DnsdistAvailable  []string       `json:"dnsdist_available"`
	DnsdistRepoSeries string         `json:"dnsdist_repo_series"`
	InventoryAt       *time.Time     `json:"inventory_at"`
	LastUpgrade       *UpgradeResult `json:"last_upgrade"`
	AgentOutdated     bool           `json:"agent_outdated"` // agent_version != panel's embedded agent version
}

type NodePatch struct {
	Name      *string            `json:"name,omitempty"`
	Labels    *map[string]string `json:"labels,omitempty"`
	ProfileID *string            `json:"profile_id,omitempty"`
	Overrides json.RawMessage    `json:"overrides,omitempty"`
}

// NodeLive is GET /nodes/{id}/live; Heartbeat is nil when nothing was received yet.
type NodeLive struct {
	NodeID     string     `json:"node_id"`
	ReceivedAt *time.Time `json:"received_at"`
	Heartbeat  *Heartbeat `json:"heartbeat"`
}

// CommandRequest is POST /nodes/{id}/commands; see Validate for the param rules.
type CommandRequest struct {
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
	Series  string `json:"series,omitempty"`
}

type MetricPoint struct {
	TS           time.Time `json:"ts"`
	Queries      int64     `json:"queries"`
	Responses    int64     `json:"responses"`
	CacheHits    int64     `json:"cache_hits"`
	CacheMisses  int64     `json:"cache_misses"`
	Blocked      int64     `json:"blocked"`
	DynBlocked   int64     `json:"dyn_blocked"`
	RuleDrops    int64     `json:"rule_drops"`
	Servfail     int64     `json:"servfail"`
	NXDomain     int64     `json:"nxdomain"`
	NoError      int64     `json:"noerror"`
	CGKRewrites  int64     `json:"cgk_rewrites"`
	LatencyAvgMs float64   `json:"latency_avg_ms"`
}

type Metrics struct {
	From   time.Time     `json:"from"`
	To     time.Time     `json:"to"`
	StepS  int           `json:"step_s"`
	Points []MetricPoint `json:"points"`
}

// RenderedConfig is the effective spec plus rendered files (secrets masked).
type RenderedConfig struct {
	Spec  ConfigSpec        `json:"spec"`
	Files map[string]string `json:"files"`
}

type Profile struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	CreatedAt        time.Time `json:"created_at"`
	LatestVersion    int       `json:"latest_version"`
	PublishedVersion *int      `json:"published_version"`
	Nodes            int       `json:"nodes"`
}

type ProfileRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	// CopyFrom (create only): profile id whose newest published spec becomes version 1;
	// empty = DefaultConfigSpec().
	CopyFrom *string `json:"copy_from,omitempty"`
}

type ConfigVersion struct {
	ID          int64      `json:"id"`
	ProfileID   string     `json:"profile_id"`
	Version     int        `json:"version"`
	Spec        ConfigSpec `json:"spec"`
	Comment     string     `json:"comment"`
	CreatedBy   *string    `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	Published   bool       `json:"published"`
	PublishedAt *time.Time `json:"published_at"`
}

type VersionCreate struct {
	Spec    ConfigSpec `json:"spec"`
	Comment string     `json:"comment"`
}

type PreviewRequest struct {
	Spec ConfigSpec `json:"spec"`
}

type VersionDiff struct {
	A ConfigVersion `json:"a"`
	B ConfigVersion `json:"b"`
}

type EnrollmentToken struct {
	ID         string            `json:"id"`
	NodeName   string            `json:"node_name"`
	Labels     map[string]string `json:"labels"`
	ProfileID  *string           `json:"profile_id"`
	CreatedBy  *string           `json:"created_by"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	UsedAt     *time.Time        `json:"used_at"`
	UsedByNode *string           `json:"used_by_node"`
}

type EnrollmentTokenCreate struct {
	NodeName  string            `json:"node_name"`
	Labels    map[string]string `json:"labels"`
	ProfileID *string           `json:"profile_id"`
	TTLHours  int               `json:"ttl_hours"`
}

// EnrollmentTokenCreated is the only time the plaintext token is shown.
type EnrollmentTokenCreated struct {
	ID             string    `json:"id"`
	Token          string    `json:"token"`
	InstallCommand string    `json:"install_command"`
	ExpiresAt      time.Time `json:"expires_at"`
}

const (
	SourceTPDomains     = "trustpositif_domains"
	SourceTPIPs         = "trustpositif_ips"
	SourceURLDomains    = "url_domains"
	SourceURLIPs        = "url_ips"
	SourceManualDomains = "manual_domains"
	SourceManualIPs     = "manual_ips"
	SourceWhitelist     = "whitelist"
)

type BlocklistSource struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Kind         string     `json:"kind"`
	URL          string     `json:"url"`
	Content      string     `json:"content"`
	Enabled      bool       `json:"enabled"`
	ETag         string     `json:"etag"`
	LastModified string     `json:"last_modified"`
	LastFetchAt  *time.Time `json:"last_fetch_at"`
	LastStatus   string     `json:"last_status"`
	Entries      int        `json:"entries"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type BlocklistSourceCreate struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	URL     string `json:"url"`
	Content string `json:"content"`
	Enabled *bool  `json:"enabled,omitempty"`
}

type BlocklistSourcePatch struct {
	Name    *string `json:"name,omitempty"`
	URL     *string `json:"url,omitempty"`
	Content *string `json:"content,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
}

type BlocklistBuild struct {
	ID          int64      `json:"id"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	Status      string     `json:"status"` // running | ok | failed | skipped
	Trigger     string     `json:"trigger"`
	Domains     int        `json:"domains"`
	IPs         int        `json:"ips"`
	Whitelisted int        `json:"whitelisted"`
	Skipped     int        `json:"skipped"`
	SizeBytes   int64      `json:"size_bytes"`
	SHA256      string     `json:"sha256"`
	Error       string     `json:"error"`
}

type BlocklistLookup struct {
	Name    string `json:"name"`
	Blocked bool   `json:"blocked"`
	Match   string `json:"match"` // the entry that matched (name itself or a parent)
}

type BlockedReport struct {
	Total      int64            `json:"total"`
	ByNode     []BlockedByNode  `json:"by_node"`
	ByMonth    []BlockedByMonth `json:"by_month"`
	TopDomains []TopDomain      `json:"top_domains"`
}

type BlockedByNode struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Count    int64  `json:"count"`
}

type BlockedByMonth struct {
	Month string `json:"month"` // YYYY-MM
	Count int64  `json:"count"`
}

type TopDomain struct {
	QName string `json:"qname"`
	Count int64  `json:"count"`
}

type Offender struct {
	ID        int64     `json:"id"`
	NodeID    string    `json:"node_id"`
	NodeName  string    `json:"node_name"`
	Client    string    `json:"client"`
	Stage     string    `json:"stage"`
	Reason    string    `json:"reason"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Blocks    int64     `json:"blocks"`
	Closed    bool      `json:"closed"`
}

type AuditEntry struct {
	ID         int64           `json:"id"`
	At         time.Time       `json:"at"`
	UserID     *string         `json:"user_id"`
	UserEmail  string          `json:"user_email"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Details    json.RawMessage `json:"details"`
	IP         string          `json:"ip"`
}

// Settings are the panel-wide settings (table settings; json tag = key).
type Settings struct {
	BlocklistBuildIntervalMinutes int    `json:"blocklist_build_interval_minutes"`
	MetricsRetentionDays          int    `json:"metrics_retention_days"`
	BlockedRetentionDays          int    `json:"blocked_retention_days"`
	AgentPollIntervalS            int    `json:"agent_poll_interval_s"`
	AgentHeartbeatIntervalS       int    `json:"agent_heartbeat_interval_s"`
	PublicURL                     string `json:"public_url"` // empty = DNSJOS_PUBLIC_URL
}

type Overview struct {
	Nodes           map[string]int  `json:"nodes"` // by status
	NodesTotal      int             `json:"nodes_total"`
	QPS             float64         `json:"qps"`
	CacheHitRatio   float64         `json:"cache_hit_ratio"`
	Blocked24h      int64           `json:"blocked_24h"`
	CurrentBuild    *BlocklistBuild `json:"current_build"`
	ActiveOffenders int             `json:"active_offenders"`
}
