package upgrades

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/db"
)

// Staged profile publish (SPEC §6.5): a 'config' run is an upgrade run whose step unpins
// one node (nodes.config_pin) so it fetches the new version, then waits for the same
// health gate as an upgrade before the next node. Nodes the run has not reached yet stay
// on the version they were pinned to.

// WriteErr answers with the status carried by an error from StartConfigRollout or
// PublishAll, or a DB error.
func WriteErr(w http.ResponseWriter, r *http.Request, err error) { writeErr(w, r, err) }

// StartConfigRollout pins every live node following the profile to the version it is on
// now, and creates a 'config' run to move them to version one at a time, least busy
// first. The caller marks the version published in the same transaction. runID is 0
// when no node follows the profile (nothing to stage).
func StartConfigRollout(ctx context.Context, tx pgx.Tx, profileID string, version int, by *string, now time.Time) (runID int64, err error) {
	invalid := func(msg string) error { return &httpErr{http.StatusUnprocessableEntity, "invalid_rollout", msg} }
	if err := db.LockUpgrades(ctx, tx); err != nil {
		return 0, err
	}
	if err := activeRun(ctx, tx); err != nil {
		return 0, err
	}
	var prev *int
	if err := tx.QueryRow(ctx, "SELECT max(version) FROM config_versions WHERE profile_id = $1 AND published",
		profileID).Scan(&prev); err != nil {
		return 0, err
	}
	if prev == nil {
		return 0, invalid("the profile has no published version to roll out from; publish to all nodes")
	}
	if version <= *prev {
		return 0, invalid(fmt.Sprintf("v%d is not newer than the published v%d", version, *prev))
	}
	// Pin before publishing (same transaction), so no node sees the new version early. A
	// node still pinned by an aborted rollout keeps its older pin.
	rows, _ := tx.Query(ctx, `UPDATE nodes n SET config_pin = least(coalesce(n.config_pin, $2), $2)
		WHERE n.deleted_at IS NULL
		AND coalesce(n.profile_id, (SELECT id FROM config_profiles WHERE name = 'default')) = $1
		RETURNING n.id`, profileID, *prev)
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	if err := notReady(ctx, tx, 0); err != nil {
		return 0, err
	}
	if err := tx.QueryRow(ctx, `INSERT INTO upgrade_runs (kind, target_version, profile_id, created_by, created_at)
		VALUES ('config', $1, $2, $3, $4) RETURNING id`, strconv.Itoa(version), profileID, by, now).Scan(&runID); err != nil {
		return 0, err
	}
	// Least busy first: queries in the last hour.
	_, err = tx.Exec(ctx, `INSERT INTO upgrade_run_steps (run_id, position, node_id, from_version, to_version)
		SELECT $1, row_number() OVER (ORDER BY coalesce(m.q, 0), n.name) - 1, n.id, n.config_pin::text, $3
		FROM nodes n LEFT JOIN LATERAL (SELECT sum(queries) q FROM metrics_minutely m
			WHERE m.node_id = n.id AND m.ts >= $4::timestamptz - interval '1 hour') m ON true
		WHERE n.id = ANY($2::uuid[])`, runID, ids, strconv.Itoa(version), now)
	return runID, err
}

// PublishAll is a normal publish: every node on the profile gets its newest published
// version now, so pins left by an aborted rollout are dropped. Refused while a rollout of
// the profile is running or paused (abort it first, or it would race the pins).
func PublishAll(ctx context.Context, tx pgx.Tx, profileID string) error {
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM upgrade_runs WHERE kind = 'config' AND profile_id = $1
		AND status IN ('running', 'paused'))`, profileID).Scan(&active); err != nil {
		return err
	}
	if active {
		return &httpErr{http.StatusConflict, "upgrade_running", "a staged rollout of this profile is running or paused; abort it first"}
	}
	_, err := tx.Exec(ctx, `UPDATE nodes SET config_pin = NULL WHERE config_pin IS NOT NULL
		AND coalesce(profile_id, (SELECT id FROM config_profiles WHERE name = 'default')) = $1`, profileID)
	return err
}
