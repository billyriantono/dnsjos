// Package analytics stores the agents' per-day query analytics and serves the reports
// (SPEC §19).
package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const (
	maxItemsPerKind = 50_000 // = the largest allowed top_k
	keepPerGroup    = 1000   // rows kept per (day, node, kind) once the day is over
)

type svc struct{ d *app.Deps }

// Register mounts the analytics routes and the trim/retention job.
func Register(r *app.Router, d *app.Deps) {
	s := &svc{d}
	r.Agent("POST /agent/v1/analytics", s.ingest)
	r.Viewer("GET /api/v1/analytics", s.report)
	r.Viewer("GET /api/v1/analytics.csv", s.csv)
	d.Jobs.Every("analytics-maintenance", time.Hour, func(ctx context.Context) error {
		if err := s.trim(ctx); err != nil {
			return err
		}
		return s.retention(ctx)
	})
}

func (s *svc) ingest(w http.ResponseWriter, r *http.Request) {
	ctx, id := r.Context(), app.NodeIDFrom(r.Context())
	key := r.Header.Get(api.IdempotencyHeader)
	if len(key) > db.MaxBatchKey {
		httpx.BadRequest(w, "Idempotency-Key: too long")
		return
	}
	var b api.AnalyticsBatch
	if err := httpx.ReadJSON(r, &b, api.AnalyticsMaxBody); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	err := b.Validate()
	for kind, items := range b.Tops {
		if err == nil && len(items) > maxItemsPerKind {
			err = fmt.Errorf("tops.%s: at most %d items", kind, maxItemsPerKind)
		}
	}
	for kind, names := range b.Evicted {
		if err == nil && len(names) > maxItemsPerKind {
			err = fmt.Errorf("evicted.%s: at most %d names", kind, maxItemsPerKind)
		}
	}
	if err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_batch", err.Error())
		return
	}
	// Out-of-range days are dropped, not rejected: the agent would retry a spooled batch forever.
	day, _ := time.Parse(time.DateOnly, b.Day)
	now := time.Now().UTC()
	if day.After(now.AddDate(0, 0, 1)) || day.Before(now.AddDate(0, 0, -s.d.Settings.Get().AnalyticsRetentionDays)) {
		s.d.Log.Warn("analytics batch dropped: day out of range", "node_id", id, "day", b.Day)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	qtypes, _ := json.Marshal(nonNil(b.ByQType))
	rcodes, _ := json.Marshal(nonNil(b.ByRcode))
	var kinds, names []string
	var counts, errs []int64
	for kind, items := range b.Tops {
		for _, it := range items {
			kinds, names = append(kinds, kind), append(names, normName(it.Name))
			counts, errs = append(counts, it.Count), append(errs, it.Error)
		}
	}
	var evKinds, evNames []string
	for kind, ns := range b.Evicted {
		for _, n := range ns {
			evKinds, evNames = append(evKinds, kind), append(evNames, normName(n))
		}
	}
	err = pgx.BeginFunc(ctx, s.d.Pool, func(tx pgx.Tx) error {
		if fresh, err := db.ClaimBatch(ctx, tx, id, key); err != nil || !fresh {
			return err
		}
		// ON CONFLICT DO UPDATE locks the row, so concurrent batches add up correctly.
		if _, err := tx.Exec(ctx, `
			INSERT INTO analytics_daily_totals AS t (day, node_id, total, by_qtype, by_rcode, sampled)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (day, node_id) DO UPDATE SET
				total = t.total + EXCLUDED.total,
				by_qtype = `+addMaps("t.by_qtype", "EXCLUDED.by_qtype")+`,
				by_rcode = `+addMaps("t.by_rcode", "EXCLUDED.by_rcode")+`,
				sampled = t.sampled OR EXCLUDED.sampled`,
			b.Day, id, b.Total, qtypes, rcodes, b.SampleRate > 1); err != nil {
			return err
		}
		if b.TopsMode != api.AnalyticsTopsCumulative {
			if len(names) == 0 {
				return nil
			}
			// GROUP BY: one INSERT .. ON CONFLICT cannot touch the same row twice.
			_, err := tx.Exec(ctx, `
				INSERT INTO analytics_top_daily AS t (day, node_id, kind, name, count, error)
				SELECT $1::date, $2::uuid, k, n, sum(c), sum(e)
				FROM unnest($3::text[], $4::text[], $5::bigint[], $6::bigint[]) AS x(k, n, c, e)
				GROUP BY k, n
				ON CONFLICT (day, node_id, kind, name) DO UPDATE SET
					count = t.count + EXCLUDED.count, error = t.error + EXCLUDED.error`,
				b.Day, id, kinds, names, counts, errs)
			return err
		}
		return ingestCumulative(ctx, tx, b.Day, id, b.Epoch, kinds, names, counts, errs, evKinds, evNames)
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// fold is the SET list that moves a row from an older epoch into base before the row
// takes epoch $3 (every right-hand side sees the old row).
const fold = `
	base = t.base + CASE WHEN t.epoch <> $3 THEN t.count ELSE 0 END,
	base_error = t.base_error + CASE WHEN t.epoch <> $3 THEN t.error ELSE 0 END,
	epoch = $3`

// ingestCumulative applies a tops_mode "cumulative" batch (SPEC §19): evicted names first
// (a name evicted and re-added in the same window then ends up with its new count), then
// items replace count/error of their row's epoch.
func ingestCumulative(ctx context.Context, tx pgx.Tx, day, node, epoch string,
	kinds, names []string, counts, errs []int64, evKinds, evNames []string) error {
	if len(evNames) > 0 {
		// A row that would end with base = 0 and count = 0 is deleted instead.
		if _, err := tx.Exec(ctx, `
			DELETE FROM analytics_top_daily t USING unnest($4::text[], $5::text[]) AS x(k, n)
			WHERE t.day = $1 AND t.node_id = $2 AND t.kind = x.k AND t.name = x.n
			  AND t.base = 0 AND (t.epoch = $3 OR t.count = 0)`,
			day, node, epoch, evKinds, evNames); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE analytics_top_daily t SET`+fold+`, count = 0, error = 0
			FROM (SELECT DISTINCT k, n FROM unnest($4::text[], $5::text[]) AS x(k, n)) x
			WHERE t.day = $1 AND t.node_id = $2 AND t.kind = x.k AND t.name = x.n`,
			day, node, epoch, evKinds, evNames); err != nil {
			return err
		}
	}
	if len(names) == 0 {
		return nil
	}
	// max(): names that differ only in case or a trailing dot collapse into one row.
	_, err := tx.Exec(ctx, `
		INSERT INTO analytics_top_daily AS t (day, node_id, kind, name, count, error, epoch)
		SELECT $1::date, $2::uuid, k, n, max(c), max(e), $3
		FROM unnest($4::text[], $5::text[], $6::bigint[], $7::bigint[]) AS x(k, n, c, e)
		GROUP BY k, n
		ON CONFLICT (day, node_id, kind, name) DO UPDATE SET`+fold+`,
			count = EXCLUDED.count, error = EXCLUDED.error`,
		day, node, epoch, kinds, names, counts, errs)
	return err
}

// normName is the stored form of a name: lower case, no trailing dot, "." for the root.
func normName(n string) string {
	n = strings.ToLower(strings.TrimSuffix(n, "."))
	if n == "" {
		return "."
	}
	return n
}

// addMaps is the SQL for per-key addition of two {"key": number} jsonb maps.
func addMaps(a, b string) string {
	return `(SELECT coalesce(jsonb_object_agg(k, v), '{}') FROM (
		SELECT k, sum(v::bigint) AS v FROM (
			SELECT * FROM jsonb_each_text(` + a + `) UNION ALL SELECT * FROM jsonb_each_text(` + b + `)
		) x(k, v) GROUP BY k) y)`
}

func nonNil(m map[string]int64) map[string]int64 {
	if m == nil {
		return map[string]int64{}
	}
	return m
}

// trim keeps, for every (day, node, kind) of ended days, the rows that are in the node's
// top keepPerGroup or in the fleet's top keepPerGroup for that (day, kind). The fleet rule
// stops a name that sits just below every node's cut-off from vanishing from the fleet
// report although its fleet total is among the largest (so a node keeps at most 2x the cap).
// Days are the agents' local days, so a day counts as over once it has ended in every
// time zone. Idempotent: only (day, kind)s with a node above the cap are touched, which
// also catches late (spooled) batches for already trimmed days.
func (s *svc) trim(ctx context.Context) error {
	tag, err := s.d.Pool.Exec(ctx, `
		WITH g AS (
			SELECT DISTINCT day, kind FROM (
				SELECT day, kind FROM analytics_top_daily WHERE day < current_date - 1
				GROUP BY day, node_id, kind HAVING count(*) > $1) x),
		f AS (
			SELECT t.day, t.kind, t.name,
			       row_number() OVER (PARTITION BY t.day, t.kind ORDER BY sum(t.base + t.count) DESC, t.name) AS frn
			FROM analytics_top_daily t JOIN g USING (day, kind) GROUP BY t.day, t.kind, t.name),
		r AS (
			SELECT t.day, t.node_id, t.kind, t.name,
			       row_number() OVER (PARTITION BY t.day, t.node_id, t.kind ORDER BY t.base + t.count DESC, t.name) AS rn
			FROM analytics_top_daily t JOIN g USING (day, kind))
		DELETE FROM analytics_top_daily t USING r JOIN f USING (day, kind, name)
		WHERE r.rn > $1 AND f.frn > $1 AND t.day = r.day AND t.node_id = r.node_id AND t.kind = r.kind AND t.name = r.name`,
		keepPerGroup)
	if err != nil {
		return fmt.Errorf("analytics trim: %w", err)
	}
	if n := tag.RowsAffected(); n > 0 {
		s.d.Log.Info("analytics trimmed", "deleted", n)
	}
	return nil
}

// retention drops days older than analytics_retention_days (< 1 disables it).
func (s *svc) retention(ctx context.Context) error {
	days := s.d.Settings.Get().AnalyticsRetentionDays
	if days < 1 {
		return nil
	}
	for _, t := range []string{"analytics_top_daily", "analytics_daily_totals"} {
		tag, err := s.d.Pool.Exec(ctx, "DELETE FROM "+t+" WHERE day < current_date - $1::int", days)
		if err != nil {
			return fmt.Errorf("retention %s: %w", t, err)
		}
		if n := tag.RowsAffected(); n > 0 {
			s.d.Log.Info("retention", "table", t, "deleted", n)
		}
	}
	return nil
}
