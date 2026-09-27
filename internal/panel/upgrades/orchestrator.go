package upgrades

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type run struct {
	id           int64
	kind, target string
	createdBy    *string
	profileID    *string // config runs
}

// step is the current step of a run joined with its node's latest state.
type step struct {
	position                 int
	status                   string
	startedAt                *time.Time
	nodeID, name, nodeStatus string
	deleted                  bool
	version                  string // dnsdist_version or agent_version, per run kind ("" for config)
	lastSeen                 *time.Time
	last                     *api.UpgradeResult
	fromVersion              string // config: the version the node is pinned back to on failure
	applied                  *int   // config: applied_config_version
	applyErr                 string // config: the last heartbeat's apply_error
}

// tick advances the single running run: at most one node is ever in progress, and the
// next node starts only after the current one passed the health gate.
func (s *svc) tick(ctx context.Context) error {
	return pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		var rn run
		err := tx.QueryRow(ctx, "SELECT id, kind, target_version, created_by, profile_id FROM upgrade_runs WHERE status = 'running' FOR UPDATE").
			Scan(&rn.id, &rn.kind, &rn.target, &rn.createdBy, &rn.profileID)
		if db.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		now := s.now()
		for {
			var st step
			err := tx.QueryRow(ctx, `SELECT s.position, s.status, s.started_at, n.id, n.name, n.status, n.deleted_at IS NOT NULL,
					CASE $2 WHEN 'agent' THEN n.agent_version WHEN 'config' THEN '' ELSE n.dnsdist_version END,
					n.last_seen_at, n.last_upgrade, s.from_version, n.applied_config_version,
					coalesce(n.last_heartbeat->>'apply_error', '')
				FROM upgrade_run_steps s JOIN nodes n ON n.id = s.node_id
				WHERE s.run_id = $1 AND s.status IN ('pending', 'running') ORDER BY s.position LIMIT 1`, rn.id, rn.kind).
				Scan(&st.position, &st.status, &st.startedAt, &st.nodeID, &st.name, &st.nodeStatus, &st.deleted,
					&st.version, &st.lastSeen, &st.last, &st.fromVersion, &st.applied, &st.applyErr)
			if db.IsNotFound(err) {
				_, err = tx.Exec(ctx, "UPDATE upgrade_runs SET status = 'done', finished_at = $2, message = '' WHERE id = $1", rn.id, now)
				return err
			}
			if err != nil {
				return err
			}
			setStep := func(status, msg string) error {
				_, err := tx.Exec(ctx, `UPDATE upgrade_run_steps SET status = $3, message = $4,
					finished_at = CASE WHEN $3 IN ('ok', 'failed', 'skipped') THEN $5::timestamptz END
					WHERE run_id = $1 AND position = $2`, rn.id, st.position, status, msg, now)
				return err
			}

			if st.status == api.StepPending {
				switch {
				case st.deleted:
					err = setStep(api.StepSkipped, "node deleted")
				case rn.kind != api.UpgradeConfig && st.version == rn.target:
					err = setStep(api.StepSkipped, "already at "+rn.target)
				default:
					return s.startStep(ctx, tx, rn, st, now)
				}
				if err != nil {
					return err
				}
				continue
			}

			reason, fatal, err := s.gate(ctx, tx, rn, st, now)
			if err != nil {
				return err
			}
			if reason == "" {
				if err := setStep(api.StepOK, ""); err != nil {
					return err
				}
				continue
			}
			if !fatal && now.Sub(*st.startedAt) < s.timeout {
				return setStep(api.StepRunning, "waiting: "+reason)
			}
			if !fatal {
				reason = "health gate timed out: " + reason
			}
			if err := setStep(api.StepFailed, reason); err != nil {
				return err
			}
			if rn.kind == api.UpgradeConfig { // back to the version it ran before (the agent already rolled back)
				// Only while it still follows the run's profile: a pin is a version of that profile.
				if _, err := tx.Exec(ctx, `UPDATE nodes SET config_pin = nullif($2, '')::int WHERE id = $1
					AND coalesce(profile_id, (SELECT id FROM config_profiles WHERE name = 'default')) = $3`,
					st.nodeID, st.fromVersion, rn.profileID); err != nil {
					return err
				}
			}
			return pause(ctx, tx, rn.id, st.name+": "+reason)
		}
	})
}

func pause(ctx context.Context, tx pgx.Tx, id int64, msg string) error {
	_, err := tx.Exec(ctx, "UPDATE upgrade_runs SET status = 'paused', message = $2 WHERE id = $1", id, msg)
	return err
}

// startStep sends the upgrade command to the step's node, unless another node is unhealthy
// or upgrading.
func (s *svc) startStep(ctx context.Context, tx pgx.Tx, rn run, st step, now time.Time) error {
	if err := db.LockUpgrades(ctx, tx); err != nil {
		return err
	}
	if err := notReady(ctx, tx, rn.id); err != nil {
		if he, ok := err.(*httpErr); ok {
			return pause(ctx, tx, rn.id, "not starting "+st.name+": "+he.msg)
		}
		return err
	}
	if rn.kind == api.UpgradeConfig {
		// Unpinned, the node gets the new version with its next heartbeat ack (≤ 15 s).
		if _, err := tx.Exec(ctx, "UPDATE nodes SET config_pin = NULL WHERE id = $1", st.nodeID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE upgrade_run_steps SET status = 'running', started_at = $3, finished_at = NULL,
			message = 'config released to the node' WHERE run_id = $1 AND position = $2`, rn.id, st.position, now); err != nil {
			return err
		}
		return audit.Log(ctx, tx, rn.createdBy, "config_rollout.step", "node", st.nodeID,
			map[string]string{"from_version": st.fromVersion, "to_version": rn.target}, "")
	}
	typ, version := api.CmdUpgradeAgent, ""
	if rn.kind == api.UpgradeDnsdist {
		typ, version = api.CmdUpgradeDnsdist, rn.target
	}
	var cmdID int64
	if err := tx.QueryRow(ctx, `INSERT INTO node_commands (node_id, type, params, created_by)
		VALUES ($1, $2, jsonb_strip_nulls(jsonb_build_object('version', nullif($3, ''))), $4) RETURNING id`,
		st.nodeID, typ, version, rn.createdBy).Scan(&cmdID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE upgrade_run_steps SET status = 'running', started_at = $3, finished_at = NULL,
		from_version = $4, message = 'command sent' WHERE run_id = $1 AND position = $2`,
		rn.id, st.position, now, st.version); err != nil {
		return err
	}
	return audit.Log(ctx, tx, rn.createdBy, "upgrade.step", "node", st.nodeID,
		api.Command{ID: cmdID, Type: typ, Version: version}, "")
}

// gate returns why the step's node is not healthy on the target yet ("" = healthy);
// fatal means the node reported the upgrade failed, so waiting is pointless.
func (s *svc) gate(ctx context.Context, tx pgx.Tx, rn run, st step, now time.Time) (reason string, fatal bool, err error) {
	if st.deleted {
		return "node deleted", true, nil
	}
	if rn.kind == api.UpgradeConfig {
		return s.configGate(ctx, tx, st, now)
	}
	// ponytail: "this attempt" compares the node's clock with the panel's; assumes NTP-synced nodes.
	this := st.last != nil && st.last.Kind == rn.kind && !st.last.At.Before(*st.startedAt)
	if this && !st.last.OK {
		return "upgrade failed on the node: " + st.last.Error, true, nil
	}
	switch {
	case st.version != rn.target:
		reason = fmt.Sprintf("node reports %q, want %q", st.version, rn.target)
	case st.nodeStatus != api.NodeOnline: // online = dnsdist running, no apply/blocklist error, all backends up
		reason = "node is " + st.nodeStatus
	case st.lastSeen == nil || now.Sub(*st.lastSeen) > time.Duration(3*s.d.Settings.Get().AgentHeartbeatIntervalS)*time.Second:
		reason = "no fresh heartbeat"
	case rn.kind == api.UpgradeAgent: // agent restarts do not touch dnsdist (SPEC §18)
	case !this:
		reason = "waiting for the node's upgrade result"
	default:
		reason, err = s.qpsGate(ctx, tx, st, now)
	}
	return reason, false, err
}

// configGate: the node applied the config it is now served, is online with a fresh
// heartbeat, and its traffic came back (an apply restarts dnsdist). The node was online
// when the step started, so any apply error now is from this version.
func (s *svc) configGate(ctx context.Context, tx pgx.Tx, st step, now time.Time) (reason string, fatal bool, err error) {
	if st.applyErr != "" {
		return "apply failed on the node: " + st.applyErr, true, nil
	}
	want, ok, err := s.desired(ctx, tx, st.nodeID)
	switch {
	case err != nil:
		return "", false, err
	case !ok:
		return "the node's profile has no published version", true, nil
	case st.applied == nil || *st.applied != want:
		reason = fmt.Sprintf("waiting for the node to apply config %d", want)
	case st.nodeStatus != api.NodeOnline:
		reason = "node is " + st.nodeStatus
	case st.lastSeen == nil || !st.lastSeen.After(*st.startedAt) ||
		now.Sub(*st.lastSeen) > time.Duration(3*s.d.Settings.Get().AgentHeartbeatIntervalS)*time.Second:
		reason = "no fresh heartbeat"
	default:
		reason, err = s.qpsGate(ctx, tx, st, now)
	}
	return reason, false, err
}

// qpsGate: traffic must be back to ≥ 50% of the 5 minutes before the upgrade (when that
// was > 1 qps), measured over up to 2 whole minutes after the upgrade started.
func (s *svc) qpsGate(ctx context.Context, tx pgx.Tx, st step, now time.Time) (string, error) {
	start := st.startedAt.Truncate(time.Minute)
	from := now.Truncate(time.Minute).Add(-2 * time.Minute)
	if f := start.Add(time.Minute); f.After(from) {
		from = f
	}
	var before, after float64
	if err := tx.QueryRow(ctx, `SELECT
			coalesce(sum(queries) FILTER (WHERE ts >= $2::timestamptz - interval '5 minutes' AND ts < $2), 0),
			coalesce(sum(queries) FILTER (WHERE ts >= $3), 0)
		FROM metrics_minutely WHERE node_id = $1 AND ts >= $2::timestamptz - interval '5 minutes'`,
		st.nodeID, start, from).Scan(&before, &after); err != nil {
		return "", err
	}
	if before /= 300; before <= 1 {
		return "", nil
	}
	secs := now.Sub(from).Seconds()
	if secs < 30 {
		return fmt.Sprintf("measuring qps (was %.1f before the upgrade)", before), nil
	}
	if cur := after / secs; cur < before/2 {
		return fmt.Sprintf("qps %.1f, want ≥ %.1f (half of the pre-upgrade %.1f)", cur, before/2, before), nil
	}
	return "", nil
}
