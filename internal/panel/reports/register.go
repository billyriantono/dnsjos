package reports

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type svc struct{ d *app.Deps }

// Register mounts the reports routes and jobs.
func Register(r *app.Router, d *app.Deps) {
	s := &svc{d}
	r.Viewer("GET /api/v1/overview", s.overview)
	r.Viewer("GET /api/v1/overview/metrics", s.metrics)
	r.Viewer("GET /api/v1/nodes/{id}/metrics", s.metrics)
	r.Viewer("GET /api/v1/reports/blocked", s.blocked)
	r.Viewer("GET /api/v1/reports/blocked.csv", s.blockedCSV)
	r.Viewer("GET /api/v1/offenders", s.offenders)
	d.Jobs.Every("reports-retention", time.Hour, s.retention)
}

// overview: qps and cache hit ratio come from the last two complete minutes of
// metrics_minutely (the heartbeat only carries raw counters, not rates).
func (s *svc) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	o := api.Overview{Nodes: map[string]int{"pending": 0, "online": 0, "degraded": 0, "offline": 0}}
	rows, _ := s.d.Pool.Query(ctx, "SELECT status, count(*) FROM nodes WHERE deleted_at IS NULL GROUP BY status")
	var st string
	var n int
	if _, err := pgx.ForEachRow(rows, []any{&st, &n}, func() error {
		o.Nodes[st] = n
		o.NodesTotal += n
		return nil
	}); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}

	var q, hits, misses int64
	err := s.d.Pool.QueryRow(ctx, `
		SELECT coalesce(sum(blocked), 0)::bigint,
		       coalesce(sum(queries) FILTER (WHERE ts >= m - interval '2 minutes' AND ts < m), 0)::bigint,
		       coalesce(sum(cache_hits) FILTER (WHERE ts >= m - interval '2 minutes' AND ts < m), 0)::bigint,
		       coalesce(sum(cache_misses) FILTER (WHERE ts >= m - interval '2 minutes' AND ts < m), 0)::bigint
		FROM metrics_minutely, (SELECT date_trunc('minute', now()) AS m) t
		WHERE ts >= now() - interval '24 hours'`).Scan(&o.Blocked24h, &q, &hits, &misses)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	o.QPS = float64(q) / 120
	o.CacheHitRatio = ratio(hits, misses)

	var b api.BlocklistBuild
	err = s.d.Pool.QueryRow(ctx, `
		SELECT id, started_at, finished_at, status, trigger, domains, ips, whitelisted, skipped, size_bytes, sha256, error
		FROM blocklist_builds WHERE status = 'ok' ORDER BY finished_at DESC LIMIT 1`).
		Scan(&b.ID, &b.StartedAt, &b.FinishedAt, &b.Status, &b.Trigger, &b.Domains, &b.IPs,
			&b.Whitelisted, &b.Skipped, &b.SizeBytes, &b.SHA256, &b.Error)
	switch {
	case err == nil:
		o.CurrentBuild = &b
	case !db.IsNotFound(err):
		httpx.WriteDBError(w, r, err)
		return
	}

	if err := s.d.Pool.QueryRow(ctx, `
		SELECT count(*) FROM offender_events e JOIN nodes n ON n.id = e.node_id
		WHERE NOT e.closed AND n.deleted_at IS NULL`).Scan(&o.ActiveOffenders); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, o)
}

func (s *svc) offenders(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	sql := `SELECT e.id, e.node_id, n.name, e.client, e.stage, e.reason, e.first_seen, e.last_seen, e.blocks, e.closed
		FROM offender_events e JOIN nodes n ON n.id = e.node_id WHERE true`
	args := []any{limit}
	if q.Get("active") == "true" {
		sql += " AND NOT e.closed"
	}
	if id := q.Get("node_id"); id != "" {
		args = append(args, id)
		sql += " AND e.node_id = $2"
	}
	rows, _ := s.d.Pool.Query(r.Context(), sql+" ORDER BY e.last_seen DESC LIMIT $1", args...)
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.Offender, error) {
		var o api.Offender
		err := row.Scan(&o.ID, &o.NodeID, &o.NodeName, &o.Client, &o.Stage, &o.Reason, &o.FirstSeen, &o.LastSeen, &o.Blocks, &o.Closed)
		return o, err
	})
	if err != nil {
		writeQueryErr(w, r, err)
		return
	}
	if items == nil {
		items = []api.Offender{}
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.Offender]{Items: items, Total: len(items)})
}

// writeQueryErr maps a malformed query parameter (e.g. node_id not a uuid) to 400.
func writeQueryErr(w http.ResponseWriter, r *http.Request, err error) {
	if db.IsInvalidInput(err) {
		httpx.BadRequest(w, "invalid node_id")
		return
	}
	httpx.WriteDBError(w, r, err)
}

func ratio(hits, misses int64) float64 {
	if hits+misses == 0 {
		return 0
	}
	return float64(hits) / float64(hits+misses)
}
