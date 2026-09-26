package api

import "time"

// Allowlist (SPEC §7.5): names and IPs exempt from blocking, e.g. shared CDN space that
// landed on the regulator's list by mistake.

const (
	AllowDomain = "domain"
	AllowIP     = "ip"
)

type AllowEntry struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`  // AllowDomain | AllowIP
	Value          string     `json:"value"` // normalized name, address or CIDR
	Reason         string     `json:"reason"`
	CreatedByEmail string     `json:"created_by_email"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      *time.Time `json:"expires_at"` // nil = permanent
}

type AllowEntryCreate struct {
	Kind      string     `json:"kind"`
	Value     string     `json:"value"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Allowlist is GET /agent/v1/allowlist: the active entries. Version is also the ETag and
// is never empty, so "" in AgentConfig/HeartbeatAck means a panel without allowlist support.
type Allowlist struct {
	Version string   `json:"version"`
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
}
