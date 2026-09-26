package reports

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const (
	maxPoints     = 2000
	defaultPoints = 500
)

// parseRange reads from/to (RFC 3339, default last 6 h) and step (Go duration ≥ 1m,
// default ~500 points). step is rounded up to whole minutes and raised so the series
// has ≤ maxPoints buckets; from is aligned down to a step multiple since the epoch so
// buckets stay stable while a live chart's window slides.
func parseRange(q url.Values, now time.Time) (from, to time.Time, step time.Duration, err error) {
	to = now
	if s := q.Get("to"); s != "" {
		if to, err = time.Parse(time.RFC3339, s); err != nil {
			return from, to, 0, errors.New("to: want RFC 3339")
		}
	}
	from = to.Add(-6 * time.Hour)
	if s := q.Get("from"); s != "" {
		if from, err = time.Parse(time.RFC3339, s); err != nil {
			return from, to, 0, errors.New("from: want RFC 3339")
		}
	}
	if !from.Before(to) {
		return from, to, 0, errors.New("from must be before to")
	}
	span := to.Sub(from)
	step = span / (defaultPoints - 1)
	if s := q.Get("step"); s != "" {
		if step, err = time.ParseDuration(s); err != nil || step < time.Minute {
			return from, to, 0, errors.New("step: want a duration ≥ 1m")
		}
	}
	// Aligning from adds < one step, so span/(maxPoints-1) keeps us within maxPoints.
	step = ceilMinute(max(step, span/(maxPoints-1)))
	sec := int64(step / time.Second)
	from = time.Unix(from.Unix()/sec*sec, 0).UTC()
	return from, to.UTC(), step, nil
}

// metricsSelect: $1 step seconds, $2 from, $3 to (+ optional node filter).
const metricsSelect = `
	SELECT date_bin($1 * interval '1 second', ts, $2) AS b,
	       sum(queries)::bigint, sum(responses)::bigint, sum(cache_hits)::bigint, sum(cache_misses)::bigint,
	       sum(blocked)::bigint, sum(dyn_blocked)::bigint, sum(rule_drops)::bigint, sum(servfail)::bigint,
	       sum(nxdomain)::bigint, sum(noerror)::bigint, sum(cgk_rewrites)::bigint,
	       coalesce(sum(queries * latency_sum_ms / samples) FILTER (WHERE samples > 0)
	                / nullif(sum(queries) FILTER (WHERE samples > 0), 0), 0)
	FROM metrics_minutely
	WHERE ts >= $2 AND ts < $3`

func ceilMinute(d time.Duration) time.Duration {
	return max(time.Minute, (d+time.Minute-1)/time.Minute*time.Minute)
}

// metrics serves both the fleet series and, when the path has {id}, one node's series.
// Latency is the query-weighted mean of the per-minute averages.
func (s *svc) metrics(w http.ResponseWriter, r *http.Request) {
	from, to, step, err := parseRange(r.URL.Query(), time.Now())
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	ctx := r.Context()
	args := []any{int64(step / time.Second), from, to}
	filter := ""
	if id := r.PathValue("id"); id != "" {
		var exists bool
		if err := s.d.Pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM nodes WHERE id = $1)", id).Scan(&exists); err != nil {
			httpx.WriteDBError(w, r, err)
			return
		} else if !exists {
			httpx.NotFound(w)
			return
		}
		args = append(args, id)
		filter = " AND node_id = $4"
	}
	rows, err := s.d.Pool.Query(ctx, metricsSelect+filter+" GROUP BY b ORDER BY b", args...)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	defer rows.Close()

	n := int((to.Sub(from) + step - 1) / step)
	out := api.MetricSeries{From: from, To: to, StepS: int(step / time.Second), Points: make([]api.MetricSample, n)}
	for i := range out.Points {
		out.Points[i].TS = from.Add(time.Duration(i) * step)
	}
	for rows.Next() {
		var p api.MetricPoint
		if err := rows.Scan(&p.TS, &p.Queries, &p.Responses, &p.CacheHits, &p.CacheMisses, &p.Blocked, &p.DynBlocked,
			&p.RuleDrops, &p.Servfail, &p.NXDomain, &p.NoError, &p.CGKRewrites, &p.LatencyAvgMs); err != nil {
			httpx.WriteDBError(w, r, err)
			return
		}
		i := int(p.TS.Sub(from) / step)
		if i < 0 || i >= n {
			continue
		}
		p.TS = p.TS.UTC()
		out.Points[i] = api.MetricSample{
			MetricPoint:   p,
			QPS:           float64(p.Queries) / step.Seconds(),
			CacheHitRatio: ratio(p.CacheHits, p.CacheMisses),
		}
	}
	if err := rows.Err(); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
