package upgrades

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/panel/nodes"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type env struct {
	t      *testing.T
	pool   *pgxpool.Pool
	s      *svc
	srv    *httptest.Server
	cookie string
	now    time.Time
}

func setup(t *testing.T) *env {
	pool := dbtest.New(t, "upgrades")
	d := &app.Deps{Pool: pool, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Live: app.NewLiveStore(),
		Settings: app.NewSettings(pool, ""), Version: "v9", AgentVersion: "1.1"}
	if err := d.Settings.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, pool: pool, cookie: app.NewToken(), now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	e.s = &svc{d: d, now: func() time.Time { return e.now }, timeout: 10 * time.Minute, desired: nodes.DesiredConfigVersion}
	e.run(`WITH u AS (INSERT INTO users (email, password_hash, role) VALUES ('a@example.com', 'x', 'admin') RETURNING id)
		INSERT INTO sessions (id_hash, user_id, expires_at) SELECT $1, id, now() + interval '1 hour' FROM u`, app.HashToken(e.cookie))
	r := app.NewRouter(d)
	e.s.mount(r)
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

// call sends an admin request, expects status want and decodes the body into out.
func (e *env) call(want int, method, path string, body, out any) api.ErrorBody {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.AddCookie(&http.Cookie{Name: app.SessionCookie, Value: e.cookie})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, b)
	}
	var eb api.ErrorBody
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			e.t.Fatal(err)
		}
	} else if want >= 400 {
		_ = json.Unmarshal(b, &eb)
	}
	return eb
}

func (e *env) tick() {
	e.t.Helper()
	if err := e.s.tick(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) node(name, dnsdist string, hourQueries int) string {
	var id string
	e.scalar(`INSERT INTO nodes (name, status, dnsdist_version, agent_version, dnsdist_available, last_seen_at)
		VALUES ($1, 'online', $2, '1.0', '["2.0.0-1", "2.0.1-1"]', $3) RETURNING id`, &id, name, dnsdist, e.now)
	e.run("INSERT INTO metrics_minutely (node_id, ts, queries) VALUES ($1, $2, $3)", id, e.now.Add(-30*time.Minute), hourQueries)
	return id
}

// heartbeat simulates what nodes.heartbeat stores for a node.
func (e *env) heartbeat(id, status, dnsdist, agent string, last *api.UpgradeResult) {
	e.run(`UPDATE nodes SET status = $2, dnsdist_version = $3, agent_version = $4, last_upgrade = $5, last_seen_at = $6
		WHERE id = $1`, id, status, dnsdist, agent, last, e.now)
	// the agent received and acked its commands
	e.run(`UPDATE node_commands SET delivered_at = coalesce(delivered_at, $2), acked_at = coalesce(acked_at, $2)
		WHERE node_id = $1`, id, e.now)
}

func (e *env) get(id int64) api.UpgradeRun {
	var u api.UpgradeRun
	e.call(200, "GET", "/api/v1/upgrades/"+itoa(id), nil, &u)
	return u
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func statuses(u api.UpgradeRun) string {
	var s []string
	for _, st := range u.Steps {
		s = append(s, st.NodeName+"="+st.Status)
	}
	return u.Status + " " + strings.Join(s, ",")
}

func TestRollingDnsdist(t *testing.T) {
	e := setup(t)
	a := e.node("ns-a", "2.0.0-1", 100000)
	b := e.node("ns-b", "2.0.0-1", 100)
	e.node("ns-c", "2.0.1-1", 0) // already at the target
	for i := range 5 {           // ns-b: 10 qps in the 5 minutes before its upgrade starts
		e.run("INSERT INTO metrics_minutely (node_id, ts, queries) VALUES ($1, $2, 600)", b, e.now.Add(-time.Duration(i+1)*time.Minute))
	}
	dns := func(target string, ids ...string) api.UpgradeRunCreate {
		return api.UpgradeRunCreate{Kind: api.UpgradeDnsdist, TargetVersion: target, NodeIDs: ids}
	}

	for _, bad := range []api.UpgradeRunCreate{{Kind: "os"}, dns("9.9"), dns("2.0.1-1", "00000000-0000-0000-0000-000000000000"),
		{Kind: api.UpgradeAgent, TargetVersion: "0.9"}} {
		if eb := e.call(422, "POST", "/api/v1/upgrades", bad, nil); eb.Error.Code != "invalid_upgrade" {
			t.Errorf("%+v: %+v", bad, eb)
		}
	}
	e.run("UPDATE nodes SET status = 'degraded' WHERE id = $1", a)
	if eb := e.call(409, "POST", "/api/v1/upgrades", dns("2.0.1-1"), nil); eb.Error.Code != "nodes_not_ready" || !strings.Contains(eb.Error.Message, "ns-a (degraded)") {
		t.Fatalf("not ready: %+v", eb)
	}
	e.run("UPDATE nodes SET status = 'online' WHERE id = $1", a)

	var u api.UpgradeRun
	e.call(201, "POST", "/api/v1/upgrades", dns("2.0.1-1"), &u)
	if statuses(u) != "running ns-c=pending,ns-b=pending,ns-a=pending" || u.CreatedBy == nil {
		t.Fatalf("created: %s %+v", statuses(u), u)
	}
	if eb := e.call(409, "POST", "/api/v1/upgrades", dns("2.0.1-1"), nil); eb.Error.Code != "upgrade_running" {
		t.Fatalf("second run: %+v", eb)
	}

	e.tick() // ns-c skipped, ns-b started
	if u = e.get(u.ID); statuses(u) != "running ns-c=skipped,ns-b=running,ns-a=pending" || u.Steps[1].FromVersion != "2.0.0-1" {
		t.Fatalf("tick 1: %s", statuses(u))
	}
	var params string
	e.scalar("SELECT params::text FROM node_commands WHERE node_id = $1 AND type = 'upgrade_dnsdist'", &params, b)
	if params != `{"version": "2.0.1-1"}` {
		t.Fatalf("command params %s", params)
	}
	started := e.now

	e.now = e.now.Add(20 * time.Second)
	e.tick()
	if u = e.get(u.ID); u.Steps[1].Status != api.StepRunning || !strings.Contains(u.Steps[1].Message, "want \"2.0.1-1\"") {
		t.Fatalf("waiting for version: %+v", u.Steps[1])
	}
	e.now = e.now.Add(10 * time.Second)
	e.heartbeat(b, "online", "2.0.1-1", "1.0", &api.UpgradeResult{Kind: api.UpgradeDnsdist, From: "2.0.0-1", To: "2.0.1-1", OK: true, At: started.Add(15 * time.Second)})
	e.tick()
	if u = e.get(u.ID); u.Steps[1].Status != api.StepRunning || !strings.Contains(u.Steps[1].Message, "measuring qps") {
		t.Fatalf("qps not measurable yet: %+v", u.Steps[1])
	}
	e.now = started.Add(2 * time.Minute)
	e.heartbeat(b, "online", "2.0.1-1", "1.0", &api.UpgradeResult{Kind: api.UpgradeDnsdist, OK: true, At: started.Add(15 * time.Second)})
	e.run("INSERT INTO metrics_minutely (node_id, ts, queries) VALUES ($1, $2, 120)", b, started.Add(time.Minute))
	e.tick()
	if u = e.get(u.ID); u.Steps[1].Status != api.StepRunning || !strings.Contains(u.Steps[1].Message, "qps 2.0") {
		t.Fatalf("qps too low: %+v", u.Steps[1])
	}
	e.run("UPDATE metrics_minutely SET queries = 400 WHERE node_id = $1 AND ts = $2", b, started.Add(time.Minute))
	e.tick() // ns-b healthy → ns-a started in the same tick
	if u = e.get(u.ID); statuses(u) != "running ns-c=skipped,ns-b=ok,ns-a=running" {
		t.Fatalf("tick ns-b ok: %s", statuses(u))
	}

	e.call(200, "POST", "/api/v1/upgrades/"+itoa(u.ID)+"/pause", nil, &u)
	e.call(409, "POST", "/api/v1/upgrades/"+itoa(u.ID)+"/pause", nil, nil)
	e.tick() // paused: nothing moves
	e.call(200, "POST", "/api/v1/upgrades/"+itoa(u.ID)+"/resume", nil, &u)
	if u.Status != api.RunRunning {
		t.Fatalf("resume: %s", statuses(u))
	}

	aStart := e.now
	e.now = e.now.Add(time.Minute)
	e.heartbeat(a, "online", "2.0.0-1", "1.0", &api.UpgradeResult{Kind: api.UpgradeDnsdist, OK: false, Error: "check-config failed", At: e.now})
	e.tick()
	if u = e.get(u.ID); statuses(u) != "paused ns-c=skipped,ns-b=ok,ns-a=failed" || !strings.Contains(u.Message, "ns-a: upgrade failed on the node: check-config failed") {
		t.Fatalf("failed attempt: %s %q", statuses(u), u.Message)
	}

	e.run("UPDATE nodes SET status = 'offline' WHERE id = $1", b)
	e.call(409, "POST", "/api/v1/upgrades/"+itoa(u.ID)+"/resume", nil, nil)
	e.run("UPDATE nodes SET status = 'online' WHERE id = $1", b)
	e.call(200, "POST", "/api/v1/upgrades/"+itoa(u.ID)+"/resume", nil, &u)
	e.now = e.now.Add(time.Minute)
	e.tick() // retry: a new attempt, the old failed result predates it
	if u = e.get(u.ID); statuses(u) != "running ns-c=skipped,ns-b=ok,ns-a=running" || !u.Steps[2].StartedAt.After(aStart) {
		t.Fatalf("retry: %s", statuses(u))
	}
	e.now = e.now.Add(11 * time.Minute)
	e.tick()
	if u = e.get(u.ID); statuses(u) != "paused ns-c=skipped,ns-b=ok,ns-a=failed" || !strings.Contains(u.Steps[2].Message, "health gate timed out") {
		t.Fatalf("timeout: %s %+v", statuses(u), u.Steps[2])
	}

	e.call(200, "POST", "/api/v1/upgrades/"+itoa(u.ID)+"/abort", nil, &u)
	if u.Status != api.RunAborted || u.FinishedAt == nil {
		t.Fatalf("abort: %+v", u)
	}
	e.call(409, "POST", "/api/v1/upgrades/"+itoa(u.ID)+"/abort", nil, nil)
	e.call(409, "POST", "/api/v1/upgrades/"+itoa(u.ID)+"/resume", nil, nil)
	e.call(404, "POST", "/api/v1/upgrades/"+itoa(u.ID)+"/explode", nil, nil)
	e.call(404, "POST", "/api/v1/upgrades/999/pause", nil, nil)
	e.call(404, "GET", "/api/v1/upgrades/x", nil, nil)

	// ns-a still has the aborted run's command queued: it counts as upgrading until a heartbeat
	if eb := e.call(409, "POST", "/api/v1/upgrades", api.UpgradeRunCreate{Kind: api.UpgradeAgent, NodeIDs: []string{a}}, nil); !strings.Contains(eb.Error.Message, "ns-a (upgrading)") {
		t.Fatalf("queued command: %+v", eb)
	}
	e.heartbeat(a, "online", "2.0.0-1", "1.0", nil)

	// agent run on an explicit node list, target defaults to the embedded agent
	var ar api.UpgradeRun
	e.call(201, "POST", "/api/v1/upgrades", api.UpgradeRunCreate{Kind: api.UpgradeAgent, NodeIDs: []string{a}}, &ar)
	if ar.TargetVersion != "1.1" || statuses(ar) != "running ns-a=pending" {
		t.Fatalf("agent run: %+v", ar)
	}
	e.tick()
	e.now = e.now.Add(10 * time.Second)
	e.heartbeat(a, "online", "2.0.0-1", "1.1", nil)
	e.tick()
	if ar = e.get(ar.ID); statuses(ar) != "done ns-a=ok" || ar.FinishedAt == nil {
		t.Fatalf("agent run done: %s", statuses(ar))
	}

	var list api.List[api.UpgradeRun]
	e.call(200, "GET", "/api/v1/upgrades", nil, &list)
	if list.Total != 2 || list.Items[0].ID != ar.ID || len(list.Items[1].Steps) != 3 {
		t.Fatalf("list: %+v", list)
	}
	var audits int
	e.scalar("SELECT count(*) FROM audit_log WHERE action IN ('upgrade.create', 'upgrade.pause', 'upgrade.resume', 'upgrade.abort', 'upgrade.step')", &audits)
	if audits != 2+1+2+1+4 {
		t.Errorf("audit rows %d", audits)
	}
	var m api.Meta
	e.call(200, "GET", "/api/v1/meta", nil, &m)
	if m.PanelVersion != "v9" || m.AgentVersion != "1.1" || len(m.SupportedSeries) == 0 {
		t.Fatalf("meta %+v", m)
	}
}

// A node going unhealthy between steps pauses the run instead of upgrading the next node.
func TestPausesWhenFleetUnhealthy(t *testing.T) {
	e := setup(t)
	a := e.node("ns-a", "2.0.0-1", 0)
	b := e.node("ns-b", "2.0.0-1", 10)
	var u api.UpgradeRun
	e.call(201, "POST", "/api/v1/upgrades", api.UpgradeRunCreate{Kind: api.UpgradeDnsdist, TargetVersion: "2.0.1-1"}, &u)
	e.tick()
	e.now = e.now.Add(10 * time.Second)
	e.heartbeat(a, "online", "2.0.1-1", "1.0", &api.UpgradeResult{Kind: api.UpgradeDnsdist, OK: true, At: e.now})
	e.run("UPDATE nodes SET status = 'degraded' WHERE id = $1", b)
	e.tick()
	if u = e.get(u.ID); statuses(u) != "paused ns-a=ok,ns-b=pending" || !strings.Contains(u.Message, "not starting ns-b") {
		t.Fatalf("%s %q", statuses(u), u.Message)
	}
	var n int
	e.scalar("SELECT count(*) FROM node_commands WHERE node_id = $1", &n, b)
	if n != 0 {
		t.Fatalf("ns-b got %d commands", n)
	}
}

// SPEC §18: a rolling run never upgrades a node while another one runs a manual upgrade —
// queued, delivered without a heartbeat since, or reported as upgrade_in_progress.
func TestRunWaitsForManualUpgrade(t *testing.T) {
	e := setup(t)
	a := e.node("ns-a", "2.0.0-1", 0)
	b := e.node("ns-b", "2.0.0-1", 10)
	create := func(want int) api.ErrorBody {
		return e.call(want, "POST", "/api/v1/upgrades", api.UpgradeRunCreate{Kind: api.UpgradeDnsdist, TargetVersion: "2.0.1-1", NodeIDs: []string{b}}, nil)
	}

	e.run(`INSERT INTO node_commands (node_id, type, params) VALUES ($1, 'upgrade_dnsdist', '{"version":"2.0.1-1"}')`, a)
	if eb := create(409); !strings.Contains(eb.Error.Message, "ns-a (upgrading)") {
		t.Fatalf("queued manual upgrade: %+v", eb)
	}
	e.run("UPDATE node_commands SET delivered_at = $2 WHERE node_id = $1", a, e.now)
	create(409) // delivered, no heartbeat since
	e.now = e.now.Add(15 * time.Second)
	e.run(`UPDATE nodes SET last_seen_at = $2, last_heartbeat = '{"upgrade_in_progress": true}' WHERE id = $1`, a, e.now)
	e.run("UPDATE node_commands SET acked_at = $2 WHERE node_id = $1", a, e.now)
	create(409) // the agent reports it is upgrading
	e.run(`UPDATE nodes SET last_heartbeat = '{"upgrade_in_progress": false}' WHERE id = $1`, a)

	// Created while idle, then a manual upgrade is queued before the first tick: pause.
	var u api.UpgradeRun
	e.call(201, "POST", "/api/v1/upgrades", api.UpgradeRunCreate{Kind: api.UpgradeDnsdist, TargetVersion: "2.0.1-1", NodeIDs: []string{b}}, &u)
	e.run(`INSERT INTO node_commands (node_id, type, params) VALUES ($1, 'upgrade_dnsdist', '{"version":"2.0.1-1"}')`, a)
	e.tick()
	var n int
	e.scalar("SELECT count(*) FROM node_commands WHERE node_id = $1", &n, b)
	if u = e.get(u.ID); n != 0 || u.Status != api.RunPaused || !strings.Contains(u.Message, "ns-a (upgrading)") {
		t.Fatalf("run started ns-b while ns-a upgrades: %d commands, %s %q", n, statuses(u), u.Message)
	}
}
