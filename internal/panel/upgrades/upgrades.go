// Package upgrades is the rolling dnsdist/agent upgrade orchestrator (SPEC §18): upgrade
// runs and their per-node steps, the health gate job, and GET /meta.
package upgrades

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/dnsconf"
)

type svc struct {
	d       *app.Deps
	now     func() time.Time
	timeout time.Duration // health gate per node
	desired DesiredFunc
}

// DesiredFunc returns the config version a node should report as applied (ok false: its
// profile has nothing published) — nodes.DesiredConfigVersion, injected because nodes'
// tests import configs, which imports this package.
type DesiredFunc func(ctx context.Context, q db.Querier, nodeID string) (version int, ok bool, err error)

// Register mounts the upgrade and meta routes and the orchestrator job.
func Register(r *app.Router, d *app.Deps, desired DesiredFunc) {
	s := &svc{d: d, now: time.Now, timeout: 10 * time.Minute, desired: desired}
	s.mount(r)
	if d.Jobs != nil {
		d.Jobs.Every("upgrades", 5*time.Second, s.tick)
	}
}

func (s *svc) mount(r *app.Router) {
	r.Viewer("GET /api/v1/meta", s.meta)
	r.Viewer("GET /api/v1/upgrades", s.list)
	r.Viewer("GET /api/v1/upgrades/{id}", s.get)
	r.Admin("POST /api/v1/upgrades", s.create)
	r.Admin("POST /api/v1/upgrades/{id}/{action}", s.action)
}

func (s *svc) meta(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, api.Meta{PanelVersion: s.d.Version, AgentVersion: s.d.AgentVersion,
		SupportedSeries: dnsconf.SupportedSeries})
}

// httpErr is returned from inside a transaction to answer with a specific status.
type httpErr struct {
	status    int
	code, msg string
}

func (e *httpErr) Error() string { return e.msg }

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpErr
	switch {
	case errors.As(err, &he):
		httpx.WriteError(w, he.status, he.code, he.msg)
	case db.IsUniqueViolation(err): // upgrade_runs_one_active_idx lost a race
		httpx.WriteError(w, http.StatusConflict, "upgrade_running", "another upgrade run is active")
	default:
		httpx.WriteDBError(w, r, err)
	}
}

const runCols = "id, kind, target_version, profile_id, status, created_by, created_at, finished_at, message"

// loadRuns returns runs (newest first) with their ordered steps.
func loadRuns(ctx context.Context, q db.Querier, where string, args ...any) ([]api.UpgradeRun, error) {
	rows, _ := q.Query(ctx, "SELECT "+runCols+" FROM upgrade_runs "+where+" ORDER BY id DESC LIMIT 100", args...)
	runs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.UpgradeRun, error) {
		u := api.UpgradeRun{Steps: []api.UpgradeRunStep{}}
		err := row.Scan(&u.ID, &u.Kind, &u.TargetVersion, &u.ProfileID, &u.Status, &u.CreatedBy, &u.CreatedAt, &u.FinishedAt, &u.Message)
		return u, err
	})
	if err != nil || len(runs) == 0 {
		return runs, err
	}
	idx := map[int64]int{}
	ids := make([]int64, len(runs))
	for i, u := range runs {
		idx[u.ID], ids[i] = i, u.ID
	}
	rows, _ = q.Query(ctx, `SELECT s.run_id, s.position, s.node_id, n.name, s.status, s.started_at, s.finished_at,
			s.message, s.from_version, s.to_version
		FROM upgrade_run_steps s JOIN nodes n ON n.id = s.node_id
		WHERE s.run_id = ANY($1) ORDER BY s.run_id, s.position`, ids)
	var runID int64
	var st api.UpgradeRunStep
	_, err = pgx.ForEachRow(rows, []any{&runID, &st.Position, &st.NodeID, &st.NodeName, &st.Status, &st.StartedAt,
		&st.FinishedAt, &st.Message, &st.FromVersion, &st.ToVersion}, func() error {
		i := idx[runID]
		runs[i].Steps = append(runs[i].Steps, st)
		return nil
	})
	return runs, err
}

func oneRun(ctx context.Context, q db.Querier, id int64) (api.UpgradeRun, error) {
	runs, err := loadRuns(ctx, q, "WHERE id = $1", id)
	if err == nil && len(runs) == 0 {
		err = pgx.ErrNoRows
	}
	if err != nil {
		return api.UpgradeRun{}, err
	}
	return runs[0], nil
}

func (s *svc) list(w http.ResponseWriter, r *http.Request) {
	runs, err := loadRuns(r.Context(), s.d.Pool, "")
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if runs == nil {
		runs = []api.UpgradeRun{}
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.UpgradeRun]{Items: runs, Total: len(runs)})
}

func (s *svc) get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpx.NotFound(w)
		return
	}
	u, err := oneRun(r.Context(), s.d.Pool, id)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

// notReady lists live nodes that are not online or are upgrading: no node may be taken
// down for an upgrade while another one is already unhealthy or upgrading (a manual
// upgrade command). A node counts as upgrading while its heartbeat says so, or while an
// upgrade/series command for it is queued or delivered with no heartbeat since.
// A node with a running step of run ownRun counts only by its status (resuming a paused
// run while its own node upgrades). Callers hold db.LockUpgrades.
func notReady(ctx context.Context, q db.Querier, ownRun int64) error {
	rows, _ := q.Query(ctx, `SELECT n.name || ' (' || CASE WHEN n.status <> 'online' THEN n.status ELSE 'upgrading' END || ')'
		FROM nodes n WHERE n.deleted_at IS NULL AND (n.status <> 'online'
			OR NOT EXISTS (SELECT 1 FROM upgrade_run_steps s WHERE s.run_id = $1 AND s.node_id = n.id AND s.status = 'running')
			AND (coalesce((n.last_heartbeat->>'upgrade_in_progress')::bool, false)
			OR EXISTS (SELECT 1 FROM node_commands c WHERE c.node_id = n.id
				AND (c.type LIKE 'upgrade\_%' OR c.type = 'set_dnsdist_series') AND c.acked_at IS NULL
				AND (c.delivered_at IS NULL OR n.last_seen_at IS NULL OR c.delivered_at >= n.last_seen_at))))
		ORDER BY n.name`, ownRun)
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err == nil && len(names) > 0 {
		err = &httpErr{http.StatusConflict, "nodes_not_ready", "nodes not ready: " + strings.Join(names, ", ")}
	}
	return err
}

func activeRun(ctx context.Context, q db.Querier) error {
	var active bool
	if err := q.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM upgrade_runs WHERE status IN ('running', 'paused'))").Scan(&active); err != nil {
		return err
	}
	if active {
		return &httpErr{http.StatusConflict, "upgrade_running", "another upgrade run is running or paused; finish or abort it first"}
	}
	return nil
}

type candidate struct {
	id, name, status, dnsdist, agent string
	available                        []string
}

func (s *svc) create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var c api.UpgradeRunCreate
	if err := httpx.ReadJSON(r, &c, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	invalid := func(msg string) error { return &httpErr{http.StatusUnprocessableEntity, "invalid_upgrade", msg} }
	var runID int64
	err := pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		if err := c.Validate(); err != nil {
			return invalid(err.Error())
		}
		if c.Kind == api.UpgradeAgent {
			if s.d.AgentVersion == "" {
				return invalid("no agent binary is embedded in this panel build")
			}
			if c.TargetVersion == "" {
				c.TargetVersion = s.d.AgentVersion
			} else if c.TargetVersion != s.d.AgentVersion {
				return invalid(fmt.Sprintf("target_version: agent upgrades can only target the embedded agent %q", s.d.AgentVersion))
			}
		}
		if err := db.LockUpgrades(ctx, tx); err != nil {
			return err
		}
		if err := activeRun(ctx, tx); err != nil {
			return err
		}
		// Least busy first: queries in the last hour.
		rows, _ := tx.Query(ctx, `SELECT n.id, n.name, n.status, n.dnsdist_version, n.agent_version, n.dnsdist_available
			FROM nodes n LEFT JOIN LATERAL (SELECT sum(queries) q FROM metrics_minutely m
				WHERE m.node_id = n.id AND m.ts >= $1::timestamptz - interval '1 hour') m ON true
			WHERE n.deleted_at IS NULL ORDER BY coalesce(m.q, 0), n.name`, s.now())
		live, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
			var n candidate
			err := row.Scan(&n.id, &n.name, &n.status, &n.dnsdist, &n.agent, &n.available)
			return n, err
		})
		if err != nil {
			return err
		}
		picked := live
		if len(c.NodeIDs) > 0 { // the admin's order
			picked = nil
			for _, id := range c.NodeIDs {
				i := slices.IndexFunc(live, func(n candidate) bool { return n.id == id })
				if i < 0 {
					return invalid("node_ids: unknown node " + id)
				}
				picked = append(picked, live[i])
			}
		}
		if len(picked) == 0 {
			return invalid("no nodes to upgrade")
		}
		if c.Kind == api.UpgradeDnsdist {
			for _, n := range picked {
				if n.dnsdist != c.TargetVersion && !slices.Contains(n.available, c.TargetVersion) {
					return invalid(fmt.Sprintf("target_version: %q is not available on node %s (check_updates refreshes the list)", c.TargetVersion, n.name))
				}
			}
		}
		if err := notReady(ctx, tx, 0); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO upgrade_runs (kind, target_version, created_by, created_at)
			VALUES ($1, $2, $3, $4) RETURNING id`, c.Kind, c.TargetVersion, app.UserIDFrom(ctx), s.now()).Scan(&runID); err != nil {
			return err
		}
		ids := make([]string, len(picked))
		for i, n := range picked {
			ids[i] = n.id
		}
		if _, err := tx.Exec(ctx, `INSERT INTO upgrade_run_steps (run_id, position, node_id, to_version)
			SELECT $1, ord - 1, id, $3 FROM unnest($2::uuid[]) WITH ORDINALITY AS t(id, ord)`, runID, ids, c.TargetVersion); err != nil {
			return err
		}
		return audit.Record(r, tx, "upgrade.create", "upgrade_run", strconv.FormatInt(runID, 10), c)
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	u, err := oneRun(ctx, s.d.Pool, runID)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, u)
}

// action is POST /upgrades/{id}/pause|resume|abort.
func (s *svc) action(w http.ResponseWriter, r *http.Request) {
	ctx, act := r.Context(), r.PathValue("action")
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || !slices.Contains([]string{"pause", "resume", "abort"}, act) {
		httpx.NotFound(w)
		return
	}
	err = pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(ctx, "SELECT status FROM upgrade_runs WHERE id = $1 FOR UPDATE", id).Scan(&status); err != nil {
			return err
		}
		badState := &httpErr{http.StatusConflict, "invalid_state", fmt.Sprintf("cannot %s a %s run", act, status)}
		now := s.now()
		switch act {
		case "pause":
			if status != api.RunRunning {
				return badState
			}
			if _, err := tx.Exec(ctx, "UPDATE upgrade_runs SET status = 'paused', message = 'paused by an admin' WHERE id = $1", id); err != nil {
				return err
			}
		case "resume":
			if status != api.RunPaused {
				return badState
			}
			if err := db.LockUpgrades(ctx, tx); err != nil {
				return err
			}
			if err := notReady(ctx, tx, id); err != nil {
				return err
			}
			// A failed step is retried from scratch.
			if _, err := tx.Exec(ctx, `UPDATE upgrade_run_steps SET status = 'pending', started_at = NULL,
				finished_at = NULL, message = '' WHERE run_id = $1 AND status = 'failed'`, id); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "UPDATE upgrade_runs SET status = 'running', message = '' WHERE id = $1", id); err != nil {
				return err
			}
		case "abort":
			if status != api.RunRunning && status != api.RunPaused {
				return badState
			}
			if _, err := tx.Exec(ctx, `UPDATE upgrade_run_steps SET status = 'skipped', finished_at = $2,
				message = CASE WHEN status = 'running' THEN 'aborted while upgrading: check the node' ELSE 'aborted' END
				WHERE run_id = $1 AND status IN ('pending', 'running')`, id, now); err != nil {
				return err
			}
			// A config run leaves the nodes it did not reach pinned to their old version until the
			// profile is published again.
			if _, err := tx.Exec(ctx, `UPDATE upgrade_runs SET status = 'aborted', finished_at = $2,
				message = CASE WHEN kind = 'config' THEN 'aborted by an admin: nodes not reached stay on their previous config until the profile is published again'
				ELSE 'aborted by an admin' END WHERE id = $1`, id, now); err != nil {
				return err
			}
		}
		return audit.Record(r, tx, "upgrade."+act, "upgrade_run", strconv.FormatInt(id, 10), nil)
	})
	if err != nil {
		writeErr(w, r, err)
		return
	}
	u, err := oneRun(ctx, s.d.Pool, id)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}
