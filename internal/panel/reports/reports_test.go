package reports

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func newSvc(t *testing.T, pool *pgxpool.Pool) *svc {
	st := app.NewSettings(pool, "")
	if err := st.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &svc{&app.Deps{Pool: pool, Settings: st, Live: app.NewLiveStore(), Log: slog.New(slog.DiscardHandler)}}
}

func mustExec(t testing.TB, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func node(t testing.TB, pool *pgxpool.Pool, name, status string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		"INSERT INTO nodes (name, status) VALUES ($1, $2) RETURNING id", name, status).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// call runs h; pathID fills {id}.
func call(h http.HandlerFunc, target, pathID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", target, nil)
	if pathID != "" {
		req.SetPathValue("id", pathID)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func readCSV(t *testing.T, r io.Reader) [][]string {
	t.Helper()
	recs, err := csv.NewReader(r).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func sameCSV(a, b [][]string) bool { return slices.EqualFunc(a, b, slices.Equal) }

func TestReports(t *testing.T) {
	pool := dbtest.New(t, "reports")
	s := newSvc(t, pool)
	a := node(t, pool, "alpha, inc", "online")
	b := node(t, pool, "beta", "pending")
	gone := node(t, pool, "gone", "offline")
	mustExec(t, pool, "UPDATE nodes SET deleted_at = now() WHERE id = $1", gone)

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 10 { // alpha: 60 q/min, avg latency 5 ms
		mustExec(t, pool, `INSERT INTO metrics_minutely (node_id, ts, queries, cache_hits, cache_misses, blocked, latency_sum_ms, samples)
			VALUES ($1, $2, 60, 30, 10, 1, 10, 2)`, a, base.Add(time.Duration(i)*time.Minute))
	}
	for i := range 5 { // beta: 120 q/min, avg latency 20 ms
		mustExec(t, pool, `INSERT INTO metrics_minutely (node_id, ts, queries, cache_hits, cache_misses, latency_sum_ms, samples)
			VALUES ($1, $2, 120, 90, 30, 20, 1)`, b, base.Add(time.Duration(i)*time.Minute))
	}

	t.Run("fleet metrics", func(t *testing.T) {
		m := decode[api.MetricSeries](t, call(s.metrics, "/?from=2026-01-01T00:00:00Z&to=2026-01-01T00:10:00Z&step=5m", ""))
		if m.StepS != 300 || len(m.Points) != 2 {
			t.Fatalf("step %d points %d", m.StepS, len(m.Points))
		}
		p := m.Points[0]
		if p.Queries != 900 || p.CacheHits != 600 || p.CacheMisses != 200 || p.Blocked != 5 {
			t.Fatalf("bucket0 %+v", p)
		}
		// query-weighted: (300*5 + 600*20) / 900 = 15
		if !near(p.LatencyAvgMs, 15) || !near(p.QPS, 3) || !near(p.CacheHitRatio, 0.75) {
			t.Fatalf("derived %+v", p)
		}
		if q := m.Points[1]; q.Queries != 300 || !near(q.LatencyAvgMs, 5) || !q.TS.Equal(base.Add(5*time.Minute)) {
			t.Fatalf("bucket1 %+v", q)
		}
	})

	t.Run("node metrics", func(t *testing.T) {
		m := decode[api.MetricSeries](t, call(s.metrics, "/?from=2026-01-01T00:00:00Z&to=2026-01-01T00:10:00Z&step=5m", b))
		if m.Points[0].Queries != 600 || !near(m.Points[0].LatencyAvgMs, 20) {
			t.Fatalf("beta bucket0 %+v", m.Points[0])
		}
		if z := m.Points[1]; z.Queries != 0 || !z.TS.Equal(base.Add(5*time.Minute)) {
			t.Fatalf("empty bucket not zero-filled: %+v", z)
		}
		// 90s rounds up to 2m; from aligns down to a 2m multiple.
		m = decode[api.MetricSeries](t, call(s.metrics, "/?from=2026-01-01T00:01:00Z&to=2026-01-01T00:10:00Z&step=90s", a))
		if m.StepS != 120 || !m.From.Equal(base) || len(m.Points) != 5 || m.Points[0].Queries != 120 {
			t.Fatalf("aligned %+v", m)
		}
		// 30 days at 1m would be 43200 points; capped.
		m = decode[api.MetricSeries](t, call(s.metrics, "/?from=2026-01-01T00:00:00Z&to=2026-01-31T00:00:00Z&step=1m", a))
		if len(m.Points) > maxPoints || m.StepS%60 != 0 || m.Points[0].Queries != 600 {
			t.Fatalf("cap: %d points step %d", len(m.Points), m.StepS)
		}
		for _, c := range []struct {
			q, id string
			code  int
		}{
			{"/?step=30s", "", 400},
			{"/?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z", "", 400},
			{"/?from=yesterday", "", 400},
			{"/", "00000000-0000-0000-0000-000000000000", 404},
			{"/", "not-a-uuid", 404},
		} {
			if rec := call(s.metrics, c.q, c.id); rec.Code != c.code {
				t.Errorf("%s %s: %d", c.q, c.id, rec.Code)
			}
		}
	})

	for _, r := range []struct {
		day, node, qname, qtype string
		n                       int
	}{
		{"2026-01-30", a, "x.com", "A", 5}, {"2026-01-30", a, "x.com", "AAAA", 3}, {"2026-01-30", a, "y.com", "A", 2},
		{"2026-02-02", b, "x.com", "A", 10}, {"2026-02-02", b, "=evil.com", "A", 1},
		{"2026-03-01", a, "y.com", "A", 100}, {"2025-12-31", b, "y.com", "A", 100},
	} {
		mustExec(t, pool, "INSERT INTO blocked_daily (day, node_id, qname, qtype, count) VALUES ($1, $2, $3, $4, $5)",
			r.day, r.node, r.qname, r.qtype, r.n)
	}

	t.Run("blocked report", func(t *testing.T) {
		rep := decode[api.BlockedReport](t, call(s.blocked, "/?from=2026-01-01&to=2026-02-28", ""))
		if rep.Total != 21 || len(rep.ByNode) != 2 || rep.ByNode[0].NodeName != "beta" || rep.ByNode[0].Count != 11 || rep.ByNode[1].Count != 10 {
			t.Fatalf("totals %+v", rep)
		}
		if len(rep.ByMonth) != 2 || rep.ByMonth[0] != (api.BlockedByMonth{Month: "2026-01", Count: 10}) || rep.ByMonth[1].Count != 11 {
			t.Fatalf("months %+v", rep.ByMonth)
		}
		if len(rep.TopDomains) != 3 || rep.TopDomains[0] != (api.TopDomain{QName: "x.com", Count: 18}) {
			t.Fatalf("top %+v", rep.TopDomains)
		}
		// Inclusive end date + node filter + limit.
		rep = decode[api.BlockedReport](t, call(s.blocked, "/?from=2026-01-30&to=2026-03-01&node_id="+a+"&limit=1", ""))
		if rep.Total != 110 || len(rep.ByNode) != 1 || len(rep.TopDomains) != 1 || rep.TopDomains[0].QName != "y.com" {
			t.Fatalf("filtered %+v", rep)
		}
		rep = decode[api.BlockedReport](t, call(s.blocked, "/?from=2020-01-01&to=2020-01-31", ""))
		if rep.Total != 0 || rep.ByNode == nil || rep.TopDomains == nil {
			t.Fatalf("empty %+v", rep)
		}
		for _, q := range []string{"/?from=2026-13-01", "/?from=2026-02-01&to=2026-01-01", "/?node_id=nope"} {
			if rec := call(s.blocked, q, ""); rec.Code != 400 {
				t.Errorf("%s: %d", q, rec.Code)
			}
		}
	})

	t.Run("blocked csv", func(t *testing.T) {
		rec := call(s.blockedCSV, "/?from=2026-01-01&to=2026-02-28&kind=top", "")
		if rec.Code != 200 || rec.Header().Get("Content-Disposition") != `attachment; filename="dnsjos-blocked-2026-01-01-2026-02-28-top.csv"` {
			t.Fatalf("%d %v", rec.Code, rec.Header())
		}
		if recs := readCSV(t, rec.Body); !sameCSV(recs, [][]string{{"qname", "count"}, {"x.com", "18"}, {"y.com", "2"}, {"'=evil.com", "1"}}) {
			t.Fatalf("top csv %q", recs)
		}
		rec = call(s.blockedCSV, "/?from=2026-01-01&to=2026-02-28", "")
		want := "node_id,node_name,count\n" + b + ",beta,11\n" + a + ",\"alpha, inc\",10\n"
		if rec.Body.String() != want {
			t.Fatalf("summary csv %q", rec.Body)
		}
		recs := readCSV(t, call(s.blockedCSV, "/?from=2026-01-01&to=2026-12-31&kind=monthly&node_id="+a, "").Body)
		if !sameCSV(recs, [][]string{{"month", "count"}, {"2026-01", "10"}, {"2026-03", "100"}}) {
			t.Fatalf("monthly csv %q", recs)
		}
		for _, q := range []string{"/?kind=yearly", "/?node_id=nope", "/?to=2026-99-01"} {
			if rec := call(s.blockedCSV, q, ""); rec.Code != 400 {
				t.Errorf("%s: %d", q, rec.Code)
			}
		}
	})

	mustExec(t, pool, "INSERT INTO offender_events (node_id, client, stage, reason) VALUES ($1, '1.2.3.4/32', 'blocked', 'qps')", a)
	mustExec(t, pool, "INSERT INTO offender_events (node_id, client, stage, reason, closed, last_seen) VALUES ($1, '5.6.7.8/32', 'warning', 'nx', true, now() - interval '1 hour')", b)
	mustExec(t, pool, "INSERT INTO offender_events (node_id, client, stage, reason) VALUES ($1, '9.9.9.9/32', 'blocked', 'qps')", gone)

	t.Run("offenders", func(t *testing.T) {
		all := decode[api.List[api.Offender]](t, call(s.offenders, "/", ""))
		if all.Total != 3 || all.Items[2].Client != "5.6.7.8/32" {
			t.Fatalf("all %+v", all)
		}
		act := decode[api.List[api.Offender]](t, call(s.offenders, "/?active=true&node_id="+a, ""))
		if act.Total != 1 || act.Items[0].NodeName != "alpha, inc" || act.Items[0].Closed {
			t.Fatalf("active %+v", act)
		}
		if n := decode[api.List[api.Offender]](t, call(s.offenders, "/?limit=1", "")); n.Total != 1 {
			t.Fatalf("limit %+v", n)
		}
		if rec := call(s.offenders, "/?node_id=x", ""); rec.Code != 400 {
			t.Fatalf("bad node: %d", rec.Code)
		}
	})

	t.Run("overview", func(t *testing.T) {
		mustExec(t, pool, `INSERT INTO metrics_minutely (node_id, ts, queries, cache_hits, cache_misses, blocked) VALUES
			($1, date_trunc('minute', now()) - interval '1 minute', 1200, 3, 1, 7),
			($1, date_trunc('minute', now()) - interval '3 hours', 999, 0, 0, 5),
			($1, now() - interval '25 hours', 1, 0, 0, 1000)`, a)
		mustExec(t, pool, `INSERT INTO blocklist_builds (status, finished_at, sha256) VALUES
			('ok', now() - interval '1 day', 'old'), ('ok', now(), 'new'), ('failed', now(), 'bad')`)
		o := decode[api.Overview](t, call(s.overview, "/", ""))
		if o.NodesTotal != 2 || o.Nodes["online"] != 1 || o.Nodes["pending"] != 1 || o.Nodes["offline"] != 0 {
			t.Fatalf("nodes %+v", o)
		}
		if !near(o.QPS, 10) || !near(o.CacheHitRatio, 0.75) || o.Blocked24h != 12 || o.ActiveOffenders != 1 {
			t.Fatalf("overview %+v", o)
		}
		if o.CurrentBuild == nil || o.CurrentBuild.SHA256 != "new" {
			t.Fatalf("build %+v", o.CurrentBuild)
		}
	})

	t.Run("retention", func(t *testing.T) {
		mustExec(t, pool, `INSERT INTO blocked_daily (day, node_id, qname, qtype, count) VALUES
			(current_date - 801, $1, 'old.com', 'A', 1), (current_date - 799, $1, 'keep.com', 'A', 1)`, a)
		mustExec(t, pool, `INSERT INTO offender_events (node_id, client, stage, closed, last_seen) VALUES
			($1, 'old', 'warning', true, now() - interval '91 days'), ($1, 'open', 'warning', false, now() - interval '91 days')`, a)
		mustExec(t, pool, `INSERT INTO cgk_reports (node_id, measured_at, ok)
			SELECT n, now() - g * interval '1 hour', true FROM unnest($1::uuid[]) n, generate_series(1, 105) g`, []string{a, b})
		mustExec(t, pool, `INSERT INTO metrics_minutely (node_id, ts) VALUES ($1, now() - interval '34 days')`, a)
		if err := s.retention(context.Background()); err != nil {
			t.Fatal(err)
		}
		for sql, want := range map[string]int{
			// the Jan 2026 fixture rows are past 35 days; 1 min, 3 h, 25 h and 34 d remain
			"SELECT count(*) FROM metrics_minutely":                                                        4,
			"SELECT count(*) FROM blocked_daily WHERE qname = 'old.com'":                                   0,
			"SELECT count(*) FROM blocked_daily WHERE qname = 'keep.com'":                                  1,
			"SELECT count(*) FROM offender_events WHERE client IN ('old', 'open')":                         1,
			"SELECT count(*) FROM cgk_reports":                                                             200,
			"SELECT count(*) FROM cgk_reports WHERE measured_at < now() - interval '100 hours 30 minutes'": 0,
		} {
			var n int
			if err := pool.QueryRow(context.Background(), sql).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != want {
				t.Errorf("%s = %d, want %d", sql, n, want)
			}
		}
	})
}
