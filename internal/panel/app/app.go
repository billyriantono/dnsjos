// Package app holds the shared dependencies, the router with its auth guards and the
// in-memory live state every feature package builds on.
package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/billyriantono/dnsjos/internal/panel/config"
	"github.com/billyriantono/dnsjos/internal/panel/jobs"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type Deps struct {
	Pool     *pgxpool.Pool
	Cfg      config.Config
	Log      *slog.Logger
	Live     *LiveStore
	Settings *Settings
	Jobs     *jobs.Scheduler
	Version  string
	// AgentVersion is the version of the agent binaries embedded in the panel ("" when
	// none are embedded); nodes running anything else are agent_outdated (SPEC §18).
	AgentVersion string
}

// LiveEntry is the latest heartbeat of a node.
type LiveEntry struct {
	Heartbeat  api.Heartbeat
	ReceivedAt time.Time
}

// LiveStore keeps the latest heartbeat per node id in memory for the live UI.
type LiveStore struct {
	mu sync.RWMutex
	m  map[string]LiveEntry
}

func NewLiveStore() *LiveStore { return &LiveStore{m: map[string]LiveEntry{}} }

func (s *LiveStore) Get(nodeID string) (LiveEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[nodeID]
	return e, ok
}

func (s *LiveStore) Set(nodeID string, hb api.Heartbeat) {
	s.mu.Lock()
	s.m[nodeID] = LiveEntry{Heartbeat: hb, ReceivedAt: time.Now()}
	s.mu.Unlock()
}

func (s *LiveStore) Delete(nodeID string) {
	s.mu.Lock()
	delete(s.m, nodeID)
	s.mu.Unlock()
}

// All returns a copy of the map.
func (s *LiveStore) All() map[string]LiveEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]LiveEntry, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

// Settings caches the settings table in memory. Load re-reads it (call after writes).
// ponytail: a second panel instance only sees another's writes after its own Load/restart.
type Settings struct {
	pool      *pgxpool.Pool
	publicURL string
	mu        sync.RWMutex
	m         map[string]json.RawMessage
}

func NewSettings(pool *pgxpool.Pool, publicURL string) *Settings {
	return &Settings{pool: pool, publicURL: publicURL, m: map[string]json.RawMessage{}}
}

func (s *Settings) Load(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]json.RawMessage{}
	for rows.Next() {
		var k string
		var v json.RawMessage
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		m[k] = v
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
	return nil
}

func (s *Settings) raw(key string) (json.RawMessage, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	return v, ok
}

// Int returns an integer setting, or def when missing or not a number.
func (s *Settings) Int(key string, def int) int {
	v, ok := s.raw(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(string(v))
	if err != nil {
		return def
	}
	return n
}

// String returns a string setting, or def when missing or empty.
func (s *Settings) String(key, def string) string {
	v, ok := s.raw(key)
	var str string
	if !ok || json.Unmarshal(v, &str) != nil || str == "" {
		return def
	}
	return str
}

// PublicURL is the URL nodes use to reach the panel (setting, else DNSJOS_PUBLIC_URL).
func (s *Settings) PublicURL() string { return s.String("public_url", s.publicURL) }

// Get returns the typed settings with defaults applied.
func (s *Settings) Get() api.Settings {
	return api.Settings{
		BlocklistBuildIntervalMinutes: s.Int("blocklist_build_interval_minutes", 180),
		MetricsRetentionDays:          s.Int("metrics_retention_days", 35),
		BlockedRetentionDays:          s.Int("blocked_retention_days", 800),
		AnalyticsRetentionDays:        s.Int("analytics_retention_days", 400),
		AgentPollIntervalS:            s.Int("agent_poll_interval_s", api.DefaultPollS),
		AgentHeartbeatIntervalS:       s.Int("agent_heartbeat_interval_s", api.DefaultHeartbS),
		PublicURL:                     s.String("public_url", ""),
	}
}
