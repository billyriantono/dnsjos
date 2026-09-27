package api

import "time"

// APIToken is a read-only API token (SPEC §10) without its secret.
type APIToken struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Prefix         string     `json:"prefix"` // first 8 characters, for display
	CreatedByEmail string     `json:"created_by_email"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	ExpiresAt      *time.Time `json:"expires_at"` // nil = never
	Revoked        bool       `json:"revoked"`
}

type APITokenCreate struct {
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expires_in_days,omitempty"` // 0 = never
}

// APITokenCreated is the create response: the only time the token itself is returned.
type APITokenCreated struct {
	APIToken
	Token string `json:"token"`
}
