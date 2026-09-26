package nodes

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/configs"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// setupReview is setup() on its own database (parallel review runs must not share "nodes").
func setupReview(t *testing.T) *env {
	pool := dbtest.New(t, "nodes_review")
	ctx := context.Background()
	d := &app.Deps{Pool: pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Live: app.NewLiveStore(),
		Settings: app.NewSettings(pool, "http://panel.test:8080")}
	if err := d.Settings.Load(ctx); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(api.DefaultConfigSpec())
	e := &env{t: t, pool: pool, d: d, cookie: app.NewToken()}
	e.run(`INSERT INTO config_versions (profile_id, version, spec, published, published_at)
		SELECT id, 1, $1, true, now() FROM config_profiles WHERE name = 'default'`, spec)
	e.run(`WITH u AS (INSERT INTO users (email, password_hash, role) VALUES ('a@example.com', 'x', 'admin') RETURNING id)
		INSERT INTO sessions (id_hash, user_id, expires_at) SELECT $1, id, now() + interval '1 hour' FROM u`,
		app.HashToken(e.cookie))
	r := app.NewRouter(d)
	Register(r, d)
	configs.Register(r, d)
	e.srv = httptest.NewServer(r)
	t.Cleanup(e.srv.Close)
	return e
}

// Moving a node to another profile whose published version number equals the old one
// keeps the ETag/version: the agent gets 304 and the heartbeat ack shows no change.
func TestReviewProfileSwitchKeepsETag(t *testing.T) {
	e := setupReview(t)
	er := e.enroll("ns1")
	var cfg api.AgentConfig
	e.call(200, "GET", "/agent/v1/config", er.NodeToken, nil, &cfg)
	if cfg.Profile != "default" {
		t.Fatalf("profile %q", cfg.Profile)
	}
	spec := api.DefaultConfigSpec()
	spec.Cache.MaxEntries = 12345 // clearly different config
	raw, _ := json.Marshal(spec)
	var pid string
	e.scalar(`WITH p AS (INSERT INTO config_profiles (name) VALUES ('edge') RETURNING id)
		INSERT INTO config_versions (profile_id, version, spec, published, published_at)
		SELECT id, 1, $1, true, now() FROM p RETURNING profile_id::text`, &pid, raw)
	e.call(200, "PATCH", "/api/v1/nodes/"+er.NodeID, "admin", map[string]any{"profile_id": pid}, nil)

	// What the agent does: conditional GET with its last seen version.
	resp := e.do("GET", "/agent/v1/config", er.NodeToken, nil, "If-None-Match", `"1"`)
	resp.Body.Close()
	var ack api.HeartbeatAck
	e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: time.Now()}, &ack)
	if resp.StatusCode == 304 && ack.ConfigVersion == 1 {
		t.Fatalf("DEFECT: node moved to profile 'edge' (max_entries 12345) but config answers 304 and ack version %d == seen 1; agent never applies it", ack.ConfigVersion)
	}
}

// A heartbeat older than the stored one (out of order) is treated as a dnsdist restart,
// booking the node's lifetime counters as one minute of traffic.
func TestReviewOutOfOrderHeartbeat(t *testing.T) {
	e := setupReview(t)
	er := e.enroll("ns1")
	t0 := time.Now().UTC()
	post := func(at time.Time, q int64) {
		e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: at, DnsdistRunning: true,
			Counters: api.Counters{Queries: q}}, nil)
	}
	post(t0, 10_000_000)
	post(t0.Add(20*time.Second), 10_000_200) // delta 200
	post(t0.Add(10*time.Second), 10_000_100) // late/duplicate older heartbeat
	var sum int64
	e.scalar("SELECT coalesce(sum(queries), 0) FROM metrics_minutely WHERE node_id = $1", &sum, er.NodeID)
	if sum != 200 {
		t.Fatalf("DEFECT: booked %d queries, want 200 (out-of-order heartbeat booked lifetime counters)", sum)
	}
}

// A heartbeat after a gap (panel outage) books the whole gap's traffic into one minute.
func TestReviewHeartbeatGapSpike(t *testing.T) {
	e := setupReview(t)
	er := e.enroll("ns1")
	t0 := time.Now().UTC().Add(-time.Hour)
	e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: t0, DnsdistRunning: true,
		Counters: api.Counters{Queries: 1_000_000}}, nil)
	// 1 hour at 1000 qps, first heartbeat after the outage
	e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: t0.Add(time.Hour), DnsdistRunning: true,
		Counters: api.Counters{Queries: 1_000_000 + 3_600_000}}, nil)
	var rows int
	var maxQ int64
	e.scalar("SELECT count(*) FROM metrics_minutely WHERE node_id = $1", &rows, er.NodeID)
	e.scalar("SELECT max(queries) FROM metrics_minutely WHERE node_id = $1", &maxQ, er.NodeID)
	if rows == 1 && maxQ == 3_600_000 {
		t.Fatalf("DEFECT: 1 h of traffic (3.6M queries) booked into one minute bucket = %.0f qps vs real 1000", float64(maxQ)/60)
	}
}
