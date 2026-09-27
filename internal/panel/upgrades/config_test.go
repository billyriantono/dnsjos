package upgrades

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/nodes"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func TestStagedConfigRollout(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	spec := api.DefaultConfigSpec()
	var prof string
	e.scalar(`INSERT INTO config_profiles (name) VALUES ('edge') RETURNING id`, &prof)
	for v := 1; v <= 3; v++ {
		e.run(`INSERT INTO config_versions (profile_id, version, spec, published) VALUES ($1, $2, $3, $4)`, prof, v, spec, v == 1)
	}
	a := e.node("ns-a", "2.0.0-1", 100000)
	b := e.node("ns-b", "2.0.0-1", 100)
	e.node("ns-other", "2.0.0-1", 0) // follows "default": not part of the rollout
	e.run("UPDATE nodes SET profile_id = $1 WHERE id = ANY($2)", prof, []string{a, b})

	desired := func(id string) int {
		t.Helper()
		v, ok, err := nodes.DesiredConfigVersion(ctx, e.pool, id)
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		return v
	}
	publish := func(v int, staged bool) (int64, error) {
		var runID int64
		err := pgx.BeginFunc(ctx, e.pool, func(tx pgx.Tx) error {
			var err error
			if staged {
				runID, err = StartConfigRollout(ctx, tx, prof, v, nil, e.now)
			} else {
				err = PublishAll(ctx, tx, prof)
			}
			if err != nil {
				return err
			}
			_, err = tx.Exec(ctx, "UPDATE config_versions SET published = true WHERE profile_id = $1 AND version = $2", prof, v)
			return err
		})
		return runID, err
	}
	// heartbeat stores what the agent reports after applying what it is served now.
	heartbeat := func(id, applyErr string) {
		e.run(`UPDATE nodes SET applied_config_version = $2, status = $3, last_seen_at = $4,
			last_heartbeat = jsonb_build_object('apply_error', $5::text) WHERE id = $1`,
			id, desired(id), map[bool]string{true: "online", false: "degraded"}[applyErr == ""], e.now, applyErr)
	}
	v1a, v1b := desired(a), desired(b)
	heartbeat(a, "")
	heartbeat(b, "")

	if _, err := publish(1, true); !isStatus(err, 422) {
		t.Fatalf("staging the published version: %v", err)
	}
	runID, err := publish(2, true)
	if err != nil || runID == 0 {
		t.Fatal(runID, err)
	}
	if desired(a) != v1a || desired(b) != v1b {
		t.Fatal("publishing staged must not move any node yet")
	}
	if _, err := publish(3, true); !isStatus(err, 409) {
		t.Fatalf("second rollout while one is active: %v", err)
	}
	u := e.get(runID)
	if u.Kind != api.UpgradeConfig || u.TargetVersion != "2" || u.ProfileID == nil || *u.ProfileID != prof ||
		len(u.Steps) != 2 || u.Steps[0].NodeName != "ns-b" || u.Steps[0].FromVersion != "1" {
		t.Fatalf("run: %+v", u)
	}

	e.tick() // ns-b (least busy) is released
	if desired(b) == v1b || desired(a) != v1a {
		t.Fatal("only ns-b may get v2")
	}
	if got := statuses(e.get(runID)); got != "running ns-b=running,ns-a=pending" {
		t.Fatal(got)
	}
	e.tick() // not applied yet
	if msg := e.get(runID).Steps[0].Message; msg == "" || msg[:8] != "waiting:" {
		t.Fatalf("want a waiting message, got %q", msg)
	}
	e.now = e.now.Add(15 * time.Second)
	heartbeat(b, "")
	e.tick() // ns-b healthy on v2 → ns-a released
	if got := statuses(e.get(runID)); got != "running ns-b=ok,ns-a=running" {
		t.Fatal(got)
	}
	e.now = e.now.Add(15 * time.Second)
	heartbeat(a, "dnsdist --check-config failed") // the agent rolled back and reports the error
	e.tick()
	u = e.get(runID)
	if statuses(u) != "paused ns-b=ok,ns-a=failed" {
		t.Fatal(statuses(u))
	}
	if desired(a) != v1a {
		t.Fatal("a failed node must be pinned back to its previous version")
	}
	if _, err := publish(2, false); !isStatus(err, 409) {
		t.Fatalf("publish to all while the rollout is paused: %v", err)
	}

	e.call(200, "POST", "/api/v1/upgrades/"+itoa(runID)+"/abort", nil, nil)
	if desired(a) != v1a {
		t.Fatal("abort keeps unreached nodes on their old version")
	}
	if _, err := publish(2, false); err != nil {
		t.Fatal(err)
	}
	if desired(a) != desired(b) || desired(a) == v1a {
		t.Fatal("publish to all must release every pin")
	}
	var pinned int
	e.scalar("SELECT count(*) FROM nodes WHERE config_pin IS NOT NULL", &pinned)
	if pinned != 0 {
		t.Fatal("pins left:", pinned)
	}
}

func isStatus(err error, status int) bool {
	var he *httpErr
	return errors.As(err, &he) && he.status == status
}
