package nodes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/panel/install"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type env struct {
	t      *testing.T
	pool   *pgxpool.Pool
	d      *app.Deps
	srv    *httptest.Server
	cookie string
}

func setup(t *testing.T) *env {
	pool := dbtest.New(t, "nodes")
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
	e.srv = httptest.NewServer(r)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) run(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) scalar(sql string, dst any, args ...any) {
	e.t.Helper()
	if err := e.pool.QueryRow(context.Background(), sql, args...).Scan(dst); err != nil {
		e.t.Fatal(err)
	}
}

// do sends a request; auth is "" (none), "admin" (session cookie) or a node bearer token.
func (e *env) do(method, path, auth string, body any, hdr ...string) *http.Response {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	switch auth {
	case "":
	case "admin":
		req.AddCookie(&http.Cookie{Name: app.SessionCookie, Value: e.cookie})
	default:
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

// call expects status want and decodes the JSON body into out (when non-nil).
func (e *env) call(want int, method, path, auth string, body, out any, hdr ...string) *http.Response {
	e.t.Helper()
	resp := e.do(method, path, auth, body, hdr...)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatalf("%s %s: %v: %s", method, path, err, b)
		}
	}
	return resp
}

func (e *env) enroll(name string) api.EnrollResponse {
	e.t.Helper()
	var tok api.EnrollmentTokenCreated
	e.call(201, "POST", "/api/v1/enrollment-tokens", "admin", api.EnrollmentTokenCreate{NodeName: name, TTLHours: 1}, &tok)
	var er api.EnrollResponse
	e.call(200, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: tok.Token, Hostname: "host-" + name,
		OS: "debian 12", Arch: "amd64", PublicIP: "192.0.2.10"}, &er)
	return er
}

func TestEnrollAndConfig(t *testing.T) {
	e := setup(t)

	var tok api.EnrollmentTokenCreated
	e.call(201, "POST", "/api/v1/enrollment-tokens", "admin",
		api.EnrollmentTokenCreate{NodeName: "ns1", Labels: map[string]string{"site": "jkt"}}, &tok)
	if want := "curl -fsSL http://panel.test:8080/install.sh | sudo sh -s -- --token " + tok.Token; tok.InstallCommand != want {
		t.Errorf("install command %q", tok.InstallCommand)
	}
	e.call(400, "POST", "/api/v1/enrollment-tokens", "admin", api.EnrollmentTokenCreate{NodeName: "bad name"}, nil)
	var list api.List[api.EnrollmentToken]
	e.call(200, "GET", "/api/v1/enrollment-tokens", "admin", nil, &list)
	if list.Total != 1 || list.Items[0].NodeName != "ns1" || list.Items[0].UsedAt != nil {
		t.Errorf("tokens: %+v", list)
	}

	var er api.EnrollResponse
	enrollReq := api.EnrollRequest{Token: tok.Token, Hostname: "ns1.example.net", OS: "debian 12", Arch: "amd64"}
	e.call(200, "POST", "/agent/v1/enroll", "", enrollReq, &er)
	if er.NodeID == "" || er.NodeToken == "" || er.PollIntervalS != 15 {
		t.Fatalf("enroll: %+v", er)
	}
	e.call(401, "POST", "/agent/v1/enroll", "", enrollReq, nil) // single use

	expired := app.NewToken()
	e.run(`INSERT INTO enrollment_tokens (token_hash, node_name, expires_at) VALUES ($1, 'ns9', now() - interval '1 minute')`,
		app.HashToken(expired))
	e.call(401, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: expired}, nil)

	// config + ETag
	var cfg api.AgentConfig
	resp := e.call(200, "GET", "/agent/v1/config", er.NodeToken, nil, &cfg)
	if cfg.Version != 1 || cfg.Profile != "default" || resp.Header.Get("ETag") != `"1"` || cfg.HeartbeatIntervalS != 10 {
		t.Fatalf("config: v%d %s %q", cfg.Version, cfg.Profile, resp.Header.Get("ETag"))
	}
	if cfg.Blocklist.SHA256 != "" {
		t.Error("blocklist ref without a build")
	}
	e.call(304, "GET", "/agent/v1/config", er.NodeToken, nil, nil, "If-None-Match", `"1"`)
	e.call(401, "GET", "/agent/v1/config", "nope", nil, nil)

	// override edit → new version/ETag; invalid overrides rejected
	path := "/api/v1/nodes/" + er.NodeID
	e.call(422, "PATCH", path, "admin", map[string]any{"overrides": map[string]any{"cache": map[string]any{"max_entries": 0}}}, nil)
	e.call(422, "PATCH", path, "admin", map[string]any{"overrides": []int{1}}, nil)
	var n api.Node
	e.call(200, "PATCH", path, "admin", map[string]any{"name": "ns1-jkt",
		"overrides": map[string]any{"cache": map[string]any{"max_entries": 42}}}, &n)
	if n.Name != "ns1-jkt" || n.Labels["site"] != "jkt" || n.DesiredConfigVersion == nil || *n.DesiredConfigVersion == 1 {
		t.Fatalf("patched node: %+v", n)
	}
	resp = e.call(200, "GET", "/agent/v1/config", er.NodeToken, nil, &cfg, "If-None-Match", `"1"`)
	etag := resp.Header.Get("ETag")
	if cfg.Spec.Cache.MaxEntries != 42 || etag == `"1"` || cfg.Version/100000 != 1 {
		t.Fatalf("override config: v%d etag %s max_entries %d", cfg.Version, etag, cfg.Spec.Cache.MaxEntries)
	}
	e.call(304, "GET", "/agent/v1/config", er.NodeToken, nil, nil, "If-None-Match", etag)

	// publishing a new profile version changes it again; a blocklist build shows up
	spec, _ := json.Marshal(api.DefaultConfigSpec())
	e.run(`INSERT INTO config_versions (profile_id, version, spec, published) SELECT id, 2, $1, true FROM config_profiles WHERE name = 'default'`, spec)
	e.run(`INSERT INTO blocklist_builds (status, finished_at, sha256, size_bytes) VALUES ('ok', now(), 'abc', 123)`)
	e.call(200, "GET", "/agent/v1/config", er.NodeToken, nil, &cfg, "If-None-Match", etag)
	if cfg.Version/100000 != 2 || cfg.Blocklist != (api.BlocklistRef{SHA256: "abc", Size: 123, URL: "/agent/v1/blocklist"}) {
		t.Fatalf("v2 config: %d %+v", cfg.Version, cfg.Blocklist)
	}
	// SPEC §7.5: the allowlist version rides on the config, and a change does not alter
	// the config ETag (agents would re-apply their dnsdist config for nothing).
	al0 := cfg.AllowlistVersion
	e.run(`INSERT INTO allowlist (kind, value) VALUES ('domain', 'cdn.example.net')`)
	e.call(304, "GET", "/agent/v1/config", er.NodeToken, nil, nil, "If-None-Match", fmt.Sprintf(`"%d"`, cfg.Version))
	e.call(200, "GET", "/agent/v1/config", er.NodeToken, nil, &cfg)
	if al0 == "" || cfg.AllowlistVersion == "" || cfg.AllowlistVersion == al0 {
		t.Fatalf("allowlist_version %q → %q", al0, cfg.AllowlistVersion)
	}

	// clearing overrides gives the plain profile version
	e.call(200, "PATCH", path, "admin", map[string]any{"overrides": nil}, &n)
	if *n.DesiredConfigVersion != 2 {
		t.Errorf("desired after clearing overrides: %d", *n.DesiredConfigVersion)
	}

	// a new token with the same name claims the node: same id, old token revoked
	var tok2 api.EnrollmentTokenCreated
	e.call(201, "POST", "/api/v1/enrollment-tokens", "admin", api.EnrollmentTokenCreate{NodeName: "ns1-jkt"}, &tok2)
	var er2 api.EnrollResponse
	e.call(200, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: tok2.Token, Hostname: "new"}, &er2)
	if er2.NodeID != er.NodeID {
		t.Errorf("claim created a new node")
	}
	e.call(401, "GET", "/agent/v1/config", er.NodeToken, nil, nil)
	e.call(200, "GET", "/agent/v1/config", er2.NodeToken, nil, nil)

	e.call(204, "DELETE", "/api/v1/enrollment-tokens/"+tok.ID, "admin", nil, nil)
	e.call(404, "DELETE", "/api/v1/enrollment-tokens/"+tok.ID, "admin", nil, nil)
	e.call(204, "DELETE", path, "admin", nil, nil)
	e.call(401, "GET", "/agent/v1/config", er2.NodeToken, nil, nil)
	e.call(404, "GET", path, "admin", nil, nil)
	e.call(404, "GET", "/api/v1/nodes/not-a-uuid", "admin", nil, nil)
}

func TestHeartbeat(t *testing.T) {
	e := setup(t)
	er := e.enroll("ns1")
	t0 := time.Now().UTC().Truncate(time.Second)
	hb := func(at time.Time, q, hits, misses int64, backends []api.BackendStat, dyn []api.DynBlock, acked ...int64) api.HeartbeatAck {
		var ack api.HeartbeatAck
		e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{
			Time: at, AgentVersion: "1.0", DnsdistRunning: true, AppliedConfigVersion: 1, LatencyAvgMs: 2,
			Counters: api.Counters{Queries: q, CacheHits: hits, CacheMisses: misses},
			Backends: backends, DynBlocks: dyn, AckedCommands: acked,
		}, &ack)
		return ack
	}
	sum := func() (q int64) {
		e.scalar("SELECT coalesce(sum(queries), 0) FROM metrics_minutely WHERE node_id = $1", &q, er.NodeID)
		return
	}
	up := []api.BackendStat{{Address: "1.1.1.1:53", State: "up"}, {Address: "8.8.8.8:53", State: "up"}}

	ack := hb(t0, 1000, 0, 0, up, nil)
	if ack.ConfigVersion != 1 || sum() != 0 || len(ack.AllowlistVersion) != 16 { // no baseline yet
		t.Fatalf("first heartbeat: ack %+v, queries %d", ack, sum())
	}
	var c api.Command
	e.call(202, "POST", "/api/v1/nodes/"+er.NodeID+"/commands", "admin", api.CommandRequest{Type: api.CmdReapply}, &c)
	e.call(422, "POST", "/api/v1/nodes/"+er.NodeID+"/commands", "admin", api.CommandRequest{Type: "rm -rf"}, nil)

	dyn := []api.DynBlock{{Client: "192.0.2.7/32", Reason: "rate", Stage: "warning", Blocks: 1}}
	ack = hb(t0.Add(10*time.Second), 1500, 300, 100, up, dyn)
	if sum() != 500 || len(ack.Commands) != 1 || ack.Commands[0] != c {
		t.Fatalf("second heartbeat: queries %d ack %+v", sum(), ack)
	}
	var list api.List[api.Node]
	e.call(200, "GET", "/api/v1/nodes", "admin", nil, &list)
	if n := list.Items[0]; n.QPS != 50 || n.CacheHitRatio != 0.75 || n.Status != api.NodeOnline || !n.ConfigInSync || n.LatencyAvgMs != 2 {
		t.Fatalf("live node: %+v", n)
	}

	// counter reset: delta = new value; one backend down → degraded; vanished backend deleted
	dyn[0].Stage, dyn[0].Blocks = "blocked", 9
	ack = hb(t0.Add(20*time.Second), 200, 0, 0, []api.BackendStat{{Address: "1.1.1.1:53", State: "down"}}, dyn, c.ID)
	if sum() != 700 || len(ack.Commands) != 0 {
		t.Fatalf("reset heartbeat: queries %d ack %+v", sum(), ack)
	}
	var n int
	e.scalar("SELECT count(*) FROM backend_status WHERE node_id = $1", &n, er.NodeID)
	var status string
	e.scalar("SELECT status FROM nodes WHERE id = $1", &status, er.NodeID)
	var acked bool
	e.scalar("SELECT acked_at IS NOT NULL AND delivered_at IS NOT NULL FROM node_commands WHERE id = $1", &acked, c.ID)
	if n != 1 || status != api.NodeDegraded || !acked {
		t.Fatalf("backends %d status %s acked %v", n, status, acked)
	}
	var samples int
	e.scalar("SELECT sum(samples) FROM metrics_minutely WHERE node_id = $1", &samples, er.NodeID)
	if samples != 2 {
		t.Errorf("latency samples %d", samples)
	}

	// offender: one open event, escalated to blocked; closed after 10 min unseen
	var events int
	var stage string
	var blocks int64
	e.scalar("SELECT count(*) FROM offender_events WHERE node_id = $1", &events, er.NodeID)
	e.scalar("SELECT stage FROM offender_events WHERE node_id = $1", &stage, er.NodeID)
	e.scalar("SELECT blocks FROM offender_events WHERE node_id = $1", &blocks, er.NodeID)
	if events != 1 || stage != "blocked" || blocks != 9 {
		t.Fatalf("offender events %d stage %s blocks %d", events, stage, blocks)
	}
	s := &svc{d: e.d}
	e.run("UPDATE offender_events SET last_seen = now() - interval '11 minutes'")
	if err := s.statusTick(context.Background()); err != nil {
		t.Fatal(err)
	}
	var closed bool
	e.scalar("SELECT closed FROM offender_events WHERE node_id = $1", &closed, er.NodeID)
	if !closed {
		t.Fatal("offender not closed")
	}
	hb(t0.Add(30*time.Second), 300, 0, 0, up, dyn)
	e.scalar("SELECT count(*) FROM offender_events WHERE node_id = $1 AND NOT closed", &events, er.NodeID)
	if events != 1 {
		t.Fatalf("reopened events %d", events)
	}

	var live api.NodeLive
	e.call(200, "GET", "/api/v1/nodes/"+er.NodeID+"/live", "admin", nil, &live)
	if live.Heartbeat == nil || live.Heartbeat.Counters.Queries != 300 {
		t.Fatalf("live: %+v", live)
	}
	e.d.Live.Delete(er.NodeID) // panel restart: falls back to nodes.last_heartbeat
	e.call(200, "GET", "/api/v1/nodes/"+er.NodeID+"/live", "admin", nil, &live)
	if live.Heartbeat == nil || live.Heartbeat.Counters.Queries != 300 || live.ReceivedAt == nil {
		t.Fatalf("live after restart: %+v", live)
	}
}

// Regression: a heartbeat sent while dnsdist was down carries zero counters; it must not
// become the baseline, or the next good heartbeat books dnsdist's lifetime totals.
func TestHeartbeatDnsdistDown(t *testing.T) {
	e := setup(t)
	er := e.enroll("ns1")
	t0 := time.Now().UTC()
	for i, c := range []struct {
		running bool
		q, sum  int64
	}{{true, 1000, 0}, {false, 0, 0}, {true, 5000, 0}, {true, 5100, 100}} {
		e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: t0.Add(time.Duration(i) * 10 * time.Second),
			DnsdistRunning: c.running, Counters: api.Counters{Queries: c.q}}, nil)
		var sum int64
		e.scalar("SELECT coalesce(sum(queries), 0) FROM metrics_minutely WHERE node_id = $1", &sum, er.NodeID)
		if sum != c.sum {
			t.Fatalf("heartbeat %d: booked %d queries, want %d", i, sum, c.sum)
		}
	}
}

func TestUpgradeCommands(t *testing.T) {
	e := setup(t)
	e.d.AgentVersion = "1.1"
	er := e.enroll("ns1")
	path := "/api/v1/nodes/" + er.NodeID
	now := time.Now().UTC().Truncate(time.Second)
	last := &api.UpgradeResult{Kind: api.UpgradeDnsdist, From: "2.0.0-1", To: "2.0.0-1", OK: true, At: now}
	hb := func(inv bool, inProgress bool) api.HeartbeatAck {
		h := api.Heartbeat{Time: time.Now(), AgentVersion: "1.0", DnsdistVersion: "2.0.0-1", DnsdistRunning: true,
			LastUpgrade: last, UpgradeInProgress: inProgress}
		if inv {
			h.DnsdistCandidate, h.DnsdistAvailable, h.DnsdistRepoSeries, h.InventoryAt = "2.0.1-1", []string{"2.0.0-1", "2.0.1-1"}, "20", &now
		}
		var ack api.HeartbeatAck
		e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, h, &ack)
		return ack
	}
	var n api.Node
	e.call(200, "GET", path, "admin", nil, &n)
	if n.DnsdistAvailable == nil || len(n.DnsdistAvailable) != 0 || n.InventoryAt != nil || n.AgentOutdated {
		t.Fatalf("fresh node: %+v", n)
	}
	hb(true, false)
	hb(false, false) // a restarted agent without inventory keeps the stored one
	e.call(200, "GET", path, "admin", nil, &n)
	if n.DnsdistCandidate != "2.0.1-1" || len(n.DnsdistAvailable) != 2 || n.DnsdistRepoSeries != "20" ||
		n.InventoryAt == nil || !n.InventoryAt.Equal(now) || n.LastUpgrade == nil || *n.LastUpgrade != *last || !n.AgentOutdated {
		t.Fatalf("node inventory: %+v", n)
	}
	var v api.NodeVersions
	e.call(200, "GET", path+"/versions", "admin", nil, &v)
	if v.Installed != "2.0.0-1" || v.Candidate != "2.0.1-1" || len(v.Available) != 2 || v.Series != "20" ||
		v.AgentVersion != "1.0" || v.PanelAgentVersion != "1.1" || !v.AgentOutdated || v.UpgradeInProgress {
		t.Fatalf("versions: %+v", v)
	}
	e.call(404, "GET", "/api/v1/nodes/00000000-0000-0000-0000-000000000000/versions", "admin", nil, nil)

	for _, bad := range []api.CommandRequest{{Type: "nuke"}, {Type: api.CmdUpgradeDnsdist}, {Type: api.CmdUpgradeDnsdist, Version: "9.9"},
		{Type: api.CmdSetDnsdistSeries, Series: "19"}, {Type: api.CmdReapply, Version: "2.0.1-1"}} {
		var eb api.ErrorBody
		e.call(422, "POST", path+"/commands", "admin", bad, &eb)
		if eb.Error.Code != "invalid_command" {
			t.Errorf("%+v: %+v", bad, eb)
		}
	}
	var up, series, agent api.Command
	e.call(202, "POST", path+"/commands", "admin", api.CommandRequest{Type: api.CmdUpgradeDnsdist, Version: "2.0.1-1"}, &up)
	e.call(202, "POST", path+"/commands", "admin", api.CommandRequest{Type: api.CmdSetDnsdistSeries, Series: "21"}, &series)
	e.call(202, "POST", path+"/commands", "admin", api.CommandRequest{Type: api.CmdUpgradeAgent}, &agent)
	ack := hb(false, false)
	if len(ack.Commands) != 3 || ack.Commands[0] != up || ack.Commands[1] != series || ack.Commands[2] != agent ||
		up.Version != "2.0.1-1" || series.Series != "21" {
		t.Fatalf("delivered %+v", ack.Commands)
	}
	var audits int
	e.scalar("SELECT count(*) FROM audit_log WHERE action = 'node.command' AND details->>'version' = '2.0.1-1'", &audits)
	if audits != 1 {
		t.Errorf("audit rows %d", audits)
	}

	e.d.AgentVersion = "1.0" // up to date: only with force
	e.call(422, "POST", path+"/commands", "admin", api.CommandRequest{Type: api.CmdUpgradeAgent}, nil)
	e.call(202, "POST", path+"/commands?force=true", "admin", api.CommandRequest{Type: api.CmdUpgradeAgent}, nil)
	e.d.AgentVersion = ""
	e.call(422, "POST", path+"/commands?force=true", "admin", api.CommandRequest{Type: api.CmdUpgradeAgent}, nil)

	hb(false, true) // node upgrading: no other upgrade command, other commands still fine
	var eb api.ErrorBody
	e.call(409, "POST", path+"/commands", "admin", api.CommandRequest{Type: api.CmdUpgradeDnsdist, Version: "2.0.1-1"}, &eb)
	e.call(200, "GET", path+"/versions", "admin", nil, &v)
	if eb.Error.Code != "upgrade_running" || !v.UpgradeInProgress {
		t.Fatalf("in progress: %+v %+v", eb, v)
	}
	e.call(202, "POST", path+"/commands", "admin", api.CommandRequest{Type: api.CmdReapply}, nil)
	hb(false, false)
	e.run("INSERT INTO upgrade_runs (kind, status) VALUES ('agent', 'paused')") // a paused run owns the fleet
	e.call(409, "POST", path+"/commands", "admin", api.CommandRequest{Type: api.CmdSetDnsdistSeries, Series: "21"}, nil)
	e.call(202, "POST", path+"/commands", "admin", api.CommandRequest{Type: api.CmdCheckUpdates}, nil)
}

func TestStatusJob(t *testing.T) {
	e := setup(t)
	er := e.enroll("ns1")
	s := &svc{d: e.d}
	status := func() (st string) {
		e.scalar("SELECT status FROM nodes WHERE id = $1", &st, er.NodeID)
		return
	}
	if status() != api.NodePending {
		t.Fatal("new node not pending")
	}
	e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: time.Now(), DnsdistRunning: true}, nil)
	_ = s.statusTick(context.Background())
	if status() != api.NodeOnline {
		t.Fatalf("status %s, want online", status())
	}
	e.run("UPDATE nodes SET last_seen_at = now() - interval '29 seconds'") // < 3 × 10 s
	_ = s.statusTick(context.Background())
	if status() != api.NodeOnline {
		t.Fatalf("status %s, want online", status())
	}
	e.run("UPDATE nodes SET last_seen_at = now() - interval '31 seconds'")
	if err := s.statusTick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status() != api.NodeOffline {
		t.Fatalf("status %s, want offline", status())
	}
	e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: time.Now(), DnsdistRunning: false}, nil)
	if status() != api.NodeDegraded {
		t.Fatalf("status %s, want degraded", status())
	}
}

func TestBlockedAndCGK(t *testing.T) {
	e := setup(t)
	er := e.enroll("ns1")
	today := time.Now().UTC().Format(time.DateOnly)
	batch := api.BlockedBatch{Items: []api.BlockedItem{
		{Day: today, QName: "Bad.Example.", QType: "A", Count: 2},
		{Day: today, QName: "bad.example", QType: "A", Count: 3}, // same key in one batch
		{Day: today, QName: "bad.example", QType: "AAAA", Count: 1},
		{Day: "2001-01-01", QName: "old.example", QType: "A", Count: 1}, // out of range
		{Day: "nope", QName: "x.example", QType: "A", Count: 1},
		{Day: today, QName: "neg.example", QType: "A", Count: -1},
	}}
	e.call(204, "POST", "/agent/v1/blocked", er.NodeToken, batch, nil)
	e.call(204, "POST", "/agent/v1/blocked", er.NodeToken, batch, nil)
	var rows, a int64
	e.scalar("SELECT count(*) FROM blocked_daily", &rows)
	e.scalar("SELECT count FROM blocked_daily WHERE qname = 'bad.example' AND qtype = 'A'", &a)
	if rows != 2 || a != 10 {
		t.Fatalf("blocked_daily rows %d, A count %d", rows, a)
	}
	// Idempotency-Key: a replayed batch is stored once.
	for range 2 {
		e.call(204, "POST", "/agent/v1/blocked", er.NodeToken, batch, nil, api.IdempotencyHeader, "spool-1")
	}
	e.scalar("SELECT count FROM blocked_daily WHERE qname = 'bad.example' AND qtype = 'A'", &a)
	if a != 15 {
		t.Fatalf("replayed batch counted twice: %d", a)
	}
	e.call(400, "POST", "/agent/v1/blocked", er.NodeToken, batch, nil, api.IdempotencyHeader, strings.Repeat("k", 256))
	e.call(204, "POST", "/agent/v1/blocked", er.NodeToken, api.BlockedBatch{}, nil)
	e.call(400, "POST", "/agent/v1/blocked", er.NodeToken, "garbage", nil)

	resp := e.do("GET", "/api/v1/nodes/"+er.NodeID+"/cgk", "admin", nil)
	if b, _ := io.ReadAll(resp.Body); resp.StatusCode != 200 || strings.TrimSpace(string(b)) != "null" {
		t.Fatalf("cgk before any report: %d %s", resp.StatusCode, b)
	}
	e.call(404, "GET", "/api/v1/nodes/00000000-0000-0000-0000-000000000000/cgk", "admin", nil, nil)

	base := time.Now().UTC().Truncate(time.Second)
	for i := range 103 {
		e.call(204, "POST", "/agent/v1/cgk", er.NodeToken, api.CGKReport{
			MeasuredAt: base.Add(time.Duration(i) * time.Second), OK: true, Aliases: []string{"104.16.0.1"}}, nil)
	}
	var n int
	var oldest time.Time
	e.scalar("SELECT count(*) FROM cgk_reports", &n)
	e.scalar("SELECT min(measured_at) FROM cgk_reports", &oldest)
	if n != 100 || !oldest.Equal(base.Add(3*time.Second)) {
		t.Fatalf("cgk reports %d, oldest %v", n, oldest)
	}
	var latest api.CGKReport
	e.call(200, "GET", "/api/v1/nodes/"+er.NodeID+"/cgk", "admin", nil, &latest)
	if !latest.MeasuredAt.Equal(base.Add(102*time.Second)) || !latest.OK || len(latest.Aliases) != 1 || latest.Pools == nil ||
		latest.Aliases6 == nil || latest.IPv6 != "" {
		t.Fatalf("latest cgk: %+v", latest)
	}
}

// SPEC §6.6: the latest learned CGK exclusions per node.
func TestCGKLearned(t *testing.T) {
	e := setup(t)
	er := e.enroll("dns-learn")
	var rep api.CGKLearnedReport
	e.call(200, "GET", "/api/v1/nodes/"+er.NodeID+"/cgk/learned", "admin", nil, &rep)
	if rep.Excluded == nil || len(rep.Excluded) != 0 || !rep.At.IsZero() {
		t.Fatalf("before any report: %+v", rep)
	}
	at := time.Now().UTC().Truncate(time.Second)
	e.call(204, "POST", "/agent/v1/cgk/learned", er.NodeToken, api.CGKLearnedReport{At: at, Checked: 12, Excluded: []api.CGKLearned{
		{Name: "mail.example.net", RealIP: "104.20.0.3", AliasIP: "104.16.0.9", RealCode: "000", AliasCode: "000", Excluded: true, Hits: 30}}}, nil)
	e.call(401, "POST", "/agent/v1/cgk/learned", "", api.CGKLearnedReport{}, nil)
	e.call(200, "GET", "/api/v1/nodes/"+er.NodeID+"/cgk/learned", "admin", nil, &rep)
	if rep.Checked != 12 || len(rep.Excluded) != 1 || rep.Excluded[0].Name != "mail.example.net" || !rep.At.Equal(at) {
		t.Fatalf("after report: %+v", rep)
	}
	e.call(404, "GET", "/api/v1/nodes/00000000-0000-0000-0000-000000000000/cgk/learned", "admin", nil, nil)

	// SPEC §6.7: the IPv6 half of a CGK report round-trips.
	e.call(204, "POST", "/agent/v1/cgk", er.NodeToken, api.CGKReport{MeasuredAt: at, OK: true, Aliases: []string{"104.16.0.1"},
		Aliases6: []string{"2606:4700::6810:1"}, IPv6: api.CGKIPv6OK}, nil)
	var latest api.CGKReport
	e.call(200, "GET", "/api/v1/nodes/"+er.NodeID+"/cgk", "admin", nil, &latest)
	if latest.IPv6 != api.CGKIPv6OK || len(latest.Aliases6) != 1 || latest.Aliases6[0] != "2606:4700::6810:1" {
		t.Fatalf("ipv6 report: %+v", latest)
	}
}

// SPEC §17: an adopted node gets its overrides from the enroll request and no config
// until a blocklist exists (panel build or a seeded local CDB reported by heartbeat).
func TestAdopt(t *testing.T) {
	e := setup(t)
	token := func() string {
		var tok api.EnrollmentTokenCreated
		e.call(201, "POST", "/api/v1/enrollment-tokens", "admin", api.EnrollmentTokenCreate{NodeName: "old1", TTLHours: 1}, &tok)
		return tok.Token
	}
	tok := token()
	bad := api.EnrollRequest{Token: tok, Adopt: true, AdoptOverrides: json.RawMessage(`{"webserver": {"listen": "nope"}}`)}
	e.call(422, "POST", "/agent/v1/enroll", "", bad, nil)
	var er api.EnrollResponse
	e.call(200, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: tok, Hostname: "old1", Adopt: true, // token not burnt by the 422
		AdoptOverrides: json.RawMessage(`{"webserver": {"listen": "0.0.0.0:8083"}}`)}, &er)
	if er.Name != "old1" {
		t.Fatalf("enroll name %q", er.Name)
	}
	e.call(409, "GET", "/agent/v1/config", er.NodeToken, nil, nil)
	e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: time.Now(), BlocklistSHA256: "seeded"}, nil)
	e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: time.Now()}, nil) // stays seeded
	var cfg api.AgentConfig
	e.call(200, "GET", "/agent/v1/config", er.NodeToken, nil, &cfg)
	if cfg.Spec.Webserver.Listen != "0.0.0.0:8083" {
		t.Fatalf("adopt overrides not applied: %+v", cfg.Spec.Webserver)
	}

	// re-adopting resets the seed; a panel build unblocks it too
	e.call(200, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: token(), Adopt: true}, &er)
	e.call(409, "GET", "/agent/v1/config", er.NodeToken, nil, nil)
	e.run(`INSERT INTO blocklist_builds (status, finished_at, sha256, size_bytes) VALUES ('ok', now(), 'abc', 1)`)
	e.call(200, "GET", "/agent/v1/config", er.NodeToken, nil, nil)
	e.call(200, "GET", "/agent/v1/config", e.enroll("fresh").NodeToken, nil, nil)
}

func TestInstall(t *testing.T) {
	e := setup(t)
	resp := e.do("GET", "/install.sh", "", nil)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "PANEL_URL='http://panel.test:8080'") ||
		!strings.HasPrefix(string(b), "#!/bin/sh") || strings.Contains(string(b), "{{") {
		t.Fatalf("install.sh %d:\n%s", resp.StatusCode, b)
	}
	// Agent binaries are only embedded after `make agent`; check whichever state this build is in.
	if _, err := fs.Stat(install.Assets(), "bin/dnsjos-agent-linux-amd64"); err == nil {
		e.call(200, "GET", "/dl/agent/linux/amd64", "", nil, nil)
		return
	}
	for path, code := range map[string]string{
		"/dl/agent/linux/amd64":        "agent_not_embedded",
		"/dl/agent/linux/arm64.sha256": "agent_not_embedded",
		"/dl/agent/linux/mips":         "not_found",
	} {
		var eb api.ErrorBody
		e.call(404, "GET", path, "", nil, &eb)
		if eb.Error.Code != code {
			t.Errorf("%s: %+v", path, eb)
		}
	}

	e.run(`INSERT INTO settings (key, value) VALUES ('public_url', '"http://x'' ; rm -rf /"')`)
	_ = e.d.Settings.Load(context.Background())
	e.call(500, "GET", "/install.sh", "", nil, nil)
}

func TestPure(t *testing.T) {
	if configVersion(3, "", []byte(`{}`)) != 3 || configVersion(3, "", nil) != 3 {
		t.Error("no overrides must keep the profile version")
	}
	a, b := configVersion(3, "", []byte(`{"acl": ["1.0.0.0/8"]}`)), configVersion(3, "", []byte(`{"acl": ["2.0.0.0/8"]}`))
	if a == b || a/100000 != 3 || a == configVersion(4, "", []byte(`{"acl": ["1.0.0.0/8"]}`)) {
		t.Errorf("override versions %d %d", a, b)
	}
	// same version number on another profile is another version
	p1, p2 := configVersion(1, "p1", nil), configVersion(1, "p2", nil)
	if p1 == 1 || p2 == 1 || p1 == p2 || p1/100000 != 1 || configVersion(1, "p1", []byte(`{"acl": ["1.0.0.0/8"]}`)) == p1 {
		t.Errorf("profile versions %d %d", p1, p2)
	}
	if gapMinutes(15*time.Second) != 1 || gapMinutes(-time.Hour) != 1 || gapMinutes(61*time.Second) != 2 ||
		gapMinutes(time.Hour) != 60 || gapMinutes(365*24*time.Hour) != maxGapMinutes {
		t.Error("gapMinutes")
	}
	prev := api.Counters{Queries: 100, CacheHits: 10}
	if d := counterDelta(&prev, api.Counters{Queries: 150, CacheHits: 12}); d.Queries != 50 || d.CacheHits != 2 {
		t.Errorf("delta %+v", d)
	}
	// any counter going down = dnsdist restart: every new value is the increment
	if d := counterDelta(&prev, api.Counters{Queries: 120, CacheHits: 5}); d.Queries != 120 || d.CacheHits != 5 {
		t.Errorf("reset delta %+v", d)
	}
	if d := counterDelta(nil, api.Counters{Queries: 9}); d != (api.Counters{}) {
		t.Errorf("no baseline %+v", d)
	}
	for in, want := range map[string]string{"ns1.example.net": "ns1.example.net", "-a b": "a-b", "": ""} {
		if got := nameFromHostname(in); got != want {
			t.Errorf("nameFromHostname(%q) = %q", in, got)
		}
	}
	if !httpx.ETagMatch(`W/"5", "7"`, `"7"`) || httpx.ETagMatch(`"5"`, `"7"`) {
		t.Error("etagMatch")
	}
}

// An unscoped token (no node_name) creates a node but never re-keys a live one: otherwise
// any leaked token takes over a node by claiming its hostname, and adopt_overrides (e.g.
// extra_lua, run as root by check-config) would persist on it.
func TestEnrollNoHostnameTakeover(t *testing.T) {
	e := setup(t)
	victim := e.enroll("edge-1")
	unscoped := func() string {
		var tok api.EnrollmentTokenCreated
		e.call(201, "POST", "/api/v1/enrollment-tokens", "admin", api.EnrollmentTokenCreate{TTLHours: 1}, &tok)
		return tok.Token
	}
	tok := unscoped()
	var eb struct{ Error struct{ Code string } }
	e.call(409, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: tok, Hostname: "edge-1", PublicIP: "203.0.113.66"}, &eb)
	if eb.Error.Code != "name_taken" {
		t.Fatalf("code %q", eb.Error.Code)
	}
	e.call(409, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: tok, Hostname: "edge-1", Adopt: true,
		AdoptOverrides: json.RawMessage(`{"acl": ["0.0.0.0/0"]}`)}, nil)
	e.call(200, "GET", "/agent/v1/config", victim.NodeToken, nil, nil) // real agent still in
	var ip, over string
	e.scalar("SELECT public_ip FROM nodes WHERE id = $1", &ip, victim.NodeID)
	e.scalar("SELECT overrides::text FROM nodes WHERE id = $1", &over, victim.NodeID)
	if ip != "192.0.2.10" || over != "{}" {
		t.Fatalf("victim changed: %s %s", ip, over)
	}

	// adopt_overrides may never carry extra_lua, even for a new node
	e.call(400, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: tok, Hostname: "new-1", Adopt: true,
		AdoptOverrides: json.RawMessage(`{"tuning": {"extra_lua": "os.execute('id')"}}`)}, nil)
	// the token was not burnt by the refusals: it still enrolls a new node
	var er api.EnrollResponse
	e.call(200, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: tok, Hostname: "new-1"}, &er)
	if er.Name != "new-1" || er.NodeID == victim.NodeID {
		t.Fatalf("new node %+v", er)
	}
	// a token scoped to the node still re-keys it (re-install keeps history)
	again := e.enroll("edge-1")
	if again.NodeID != victim.NodeID {
		t.Fatal("scoped re-enroll must keep the node")
	}
	e.call(401, "GET", "/agent/v1/config", victim.NodeToken, nil, nil)
}

// Moving a node to another profile at the same version number must change the version
// and ETag, or the agent keeps its old config and the UI shows it in sync.
func TestProfileSwitchChangesVersion(t *testing.T) {
	e := setup(t)
	er := e.enroll("ns1")
	var cfg api.AgentConfig
	e.call(200, "GET", "/agent/v1/config", er.NodeToken, nil, &cfg)
	if cfg.Version != 1 {
		t.Fatalf("default version %d", cfg.Version)
	}
	spec := api.DefaultConfigSpec()
	spec.Cache.MaxEntries = 12345
	raw, _ := json.Marshal(spec)
	var pid string
	e.scalar(`WITH p AS (INSERT INTO config_profiles (name) VALUES ('edge') RETURNING id)
		INSERT INTO config_versions (profile_id, version, spec, published, published_at)
		SELECT id, 1, $1, true, now() FROM p RETURNING profile_id::text`, &pid, raw)
	e.call(200, "PATCH", "/api/v1/nodes/"+er.NodeID, "admin", map[string]any{"profile_id": pid}, nil)

	var ack api.HeartbeatAck
	e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: time.Now(), AppliedConfigVersion: 1}, &ack)
	if ack.ConfigVersion == 1 {
		t.Fatal("ack version unchanged after profile switch")
	}
	var n api.Node
	e.call(200, "GET", "/api/v1/nodes/"+er.NodeID, "admin", nil, &n)
	if n.ConfigInSync || n.DesiredConfigVersion == nil || *n.DesiredConfigVersion != ack.ConfigVersion {
		t.Fatalf("node shows in sync / desired %v, ack %d", n.DesiredConfigVersion, ack.ConfigVersion)
	}
	e.call(200, "GET", "/agent/v1/config", er.NodeToken, nil, &cfg, "If-None-Match", `"1"`)
	if cfg.Version != ack.ConfigVersion || cfg.Spec.Cache.MaxEntries != 12345 {
		t.Fatalf("config v%d max_entries %d", cfg.Version, cfg.Spec.Cache.MaxEntries)
	}
	e.call(304, "GET", "/agent/v1/config", er.NodeToken, nil, nil, "If-None-Match", fmt.Sprintf(`"%d"`, cfg.Version))
}

// Traffic accumulated over a heartbeat gap (panel outage) is spread over the gap's minutes
// with exact totals, not booked as one spike in the current minute.
func TestHeartbeatGapSpread(t *testing.T) {
	e := setup(t)
	er := e.enroll("ns1")
	t0 := time.Now().UTC().Add(-time.Hour)
	hb := func(at time.Time, q int64) {
		e.call(200, "POST", "/agent/v1/heartbeat", er.NodeToken, api.Heartbeat{Time: at, DnsdistRunning: true,
			Counters: api.Counters{Queries: q, NXDomain: q / 10}}, nil)
	}
	hb(t0, 1_000_000)
	hb(t0.Add(time.Hour), 1_000_000+3_600_007)
	var rows int
	var sum, maxQ, nx int64
	e.scalar("SELECT count(*) FROM metrics_minutely WHERE node_id = $1", &rows, er.NodeID)
	e.scalar("SELECT sum(queries)::bigint FROM metrics_minutely WHERE node_id = $1", &sum, er.NodeID)
	e.scalar("SELECT max(queries)::bigint FROM metrics_minutely WHERE node_id = $1", &maxQ, er.NodeID)
	e.scalar("SELECT sum(nxdomain)::bigint FROM metrics_minutely WHERE node_id = $1", &nx, er.NodeID)
	if rows != 60 || sum != 3_600_007 || maxQ != 60_001 || nx != 360_000 {
		t.Fatalf("rows %d sum %d max %d nx %d", rows, sum, maxQ, nx)
	}
	// a normal interval stays in the current minute
	hb(t0.Add(time.Hour+15*time.Second), 1_000_000+3_600_007+100)
	e.scalar("SELECT count(*) FROM metrics_minutely WHERE node_id = $1", &rows, er.NodeID)
	e.scalar("SELECT sum(queries)::bigint FROM metrics_minutely WHERE node_id = $1", &sum, er.NodeID)
	if rows != 60 || sum != 3_600_107 {
		t.Fatalf("after normal hb: rows %d sum %d", rows, sum)
	}
}

// SPEC §6.8: the latest dual-stack selection per node.
func TestDualStackReport(t *testing.T) {
	e := setup(t)
	er := e.enroll("dns-dual")
	var rep api.DualStackReport
	e.call(200, "GET", "/api/v1/nodes/"+er.NodeID+"/dualstack", "admin", nil, &rep)
	if rep.Names == nil || len(rep.Names) != 0 || !rep.At.IsZero() || rep.IPv6 {
		t.Fatalf("before any report: %+v", rep)
	}
	at := time.Now().UTC().Truncate(time.Second)
	e.call(204, "POST", "/agent/v1/dualstack", er.NodeToken, api.DualStackReport{At: at, Checked: 7, IPv6: true, Names: []api.DualStackName{
		{Name: "dns.google", Prefer: "ipv4", V4Ms: 5.2, V6Ms: 150, TTL: 60, Hits: 3, CheckedAt: at}}}, nil)
	e.call(401, "POST", "/agent/v1/dualstack", "", api.DualStackReport{}, nil)
	e.call(200, "GET", "/api/v1/nodes/"+er.NodeID+"/dualstack", "admin", nil, &rep)
	if rep.Checked != 7 || !rep.IPv6 || len(rep.Names) != 1 || rep.Names[0].Name != "dns.google" || rep.Names[0].V4Ms != 5.2 ||
		rep.Names[0].Prefer != "ipv4" || rep.Names[0].TTL != 60 || !rep.At.Equal(at) {
		t.Fatalf("after report: %+v", rep)
	}
	e.call(404, "GET", "/api/v1/nodes/00000000-0000-0000-0000-000000000000/dualstack", "admin", nil, nil)
}
