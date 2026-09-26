package analytics

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func setup(t *testing.T) (*svc, *pgxpool.Pool, string, string) {
	pool := dbtest.New(t, "analytics")
	st := app.NewSettings(pool, "")
	if err := st.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	var a, b string
	if err := pool.QueryRow(context.Background(),
		"WITH n AS (INSERT INTO nodes (name) VALUES ('a'), ('b') RETURNING id, name) SELECT (SELECT id FROM n WHERE name='a'), (SELECT id FROM n WHERE name='b')").
		Scan(&a, &b); err != nil {
		t.Fatal(err)
	}
	return &svc{&app.Deps{Pool: pool, Settings: st, Log: slog.New(slog.DiscardHandler)}}, pool, a, b
}

// post sends a batch as nodeID through a real Agent route.
func post(t *testing.T, s *svc, nodeID string, b any) *httptest.ResponseRecorder {
	t.Helper()
	return postKey(t, s, nodeID, "", b)
}

// postKey is post with an Idempotency-Key ("" = none).
func postKey(t *testing.T, s *svc, nodeID, key string, b any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(b)
	rt := app.NewRouter(s.d)
	tok := app.NewToken()
	if _, err := s.d.Pool.Exec(context.Background(), "UPDATE nodes SET token_hash = $2 WHERE id = $1", nodeID, app.HashToken(tok)); err != nil {
		t.Fatal(err)
	}
	rt.Agent("POST /agent/v1/analytics", s.ingest)
	req := httptest.NewRequest("POST", "/agent/v1/analytics", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	if key != "" {
		req.Header.Set(api.IdempotencyHeader, key)
	}
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	return rec
}

func get(s *svc, h http.HandlerFunc, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", target, nil))
	return rec
}

func report(t *testing.T, s *svc, q string) api.AnalyticsReport {
	t.Helper()
	rec := get(s, s.report, "/api/v1/analytics?"+q)
	if rec.Code != 200 {
		t.Fatalf("%s: %d %s", q, rec.Code, rec.Body)
	}
	var r api.AnalyticsReport
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

var today = time.Now().UTC().Format(time.DateOnly)

func batch(day string, rate int) api.AnalyticsBatch {
	return api.AnalyticsBatch{Day: day, Total: 100, SampleRate: rate,
		ByQType: map[string]int64{"A": 60, "AAAA": 40}, ByRcode: map[string]int64{"NOERROR": 80, "NXDOMAIN": 20},
		Tops: map[string][]api.AnalyticsTopItem{
			"queried":  {{Name: "www.example.com", Count: 50}, {Name: "WWW.Example.com.", Count: 10, Error: 0}, {Name: "b.example.net", Count: 30, Error: 2}},
			"nxdomain": {{Name: "nope.example", Count: 20}},
		}}
}

func TestIngestAddsUp(t *testing.T) {
	s, pool, a, _ := setup(t)
	for range 2 {
		if rec := post(t, s, a, batch(today, 1)); rec.Code != 204 {
			t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
		}
	}
	b := batch(today, 4)
	b.ByQType = map[string]int64{"MX": 5}
	b.ByRcode = nil
	b.Tops = nil
	if rec := post(t, s, a, b); rec.Code != 204 {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	var total int64
	var qt, rc map[string]int64
	var sampled bool
	if err := pool.QueryRow(context.Background(), "SELECT total, by_qtype, by_rcode, sampled FROM analytics_daily_totals WHERE node_id = $1", a).
		Scan(&total, &qt, &rc, &sampled); err != nil {
		t.Fatal(err)
	}
	if total != 300 || qt["A"] != 120 || qt["AAAA"] != 80 || qt["MX"] != 5 || rc["NXDOMAIN"] != 40 || !sampled {
		t.Fatalf("totals: %d %v %v %v", total, qt, rc, sampled)
	}
	var count, errSum int64
	if err := pool.QueryRow(context.Background(),
		"SELECT count, error FROM analytics_top_daily WHERE node_id = $1 AND kind = 'queried' AND name = 'www.example.com'", a).
		Scan(&count, &errSum); err != nil {
		t.Fatal(err)
	}
	if count != 120 {
		t.Fatalf("normalised duplicates should sum: %d", count)
	}

	for name, bad := range map[string]api.AnalyticsBatch{
		"kind":  {Day: today, SampleRate: 1, Tops: map[string][]api.AnalyticsTopItem{"clients": {{Name: "x", Count: 1}}}},
		"day":   {Day: "yesterday", SampleRate: 1},
		"rate":  {Day: today},
		"items": {Day: today, SampleRate: 1, Tops: map[string][]api.AnalyticsTopItem{"queried": make([]api.AnalyticsTopItem, maxItemsPerKind+1)}},
	} {
		if name == "items" {
			for i := range bad.Tops["queried"] {
				bad.Tops["queried"][i] = api.AnalyticsTopItem{Name: fmt.Sprint(i), Count: 1}
			}
		}
		if rec := post(t, s, a, bad); rec.Code != 422 {
			t.Errorf("%s: want 422, got %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := post(t, s, a, batch("2001-01-01", 1)); rec.Code != 204 { // past retention: dropped
		t.Fatalf("old day: %d", rec.Code)
	}
	var n int
	pool.QueryRow(context.Background(), "SELECT count(*) FROM analytics_daily_totals WHERE day < '2002-01-01'").Scan(&n)
	if n != 0 {
		t.Fatal("old day stored")
	}
}

func TestIngestIdempotent(t *testing.T) {
	s, _, a, b := setup(t)
	for _, node := range []string{a, a, b} { // the key is per node
		if rec := postKey(t, s, node, "k1", batch(today, 1)); rec.Code != 204 {
			t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
		}
	}
	r := report(t, s, "node_id="+a)
	if r.Total != 100 || r.Top[0].Count != 60 {
		t.Fatalf("replay counted: total %d top %+v", r.Total, r.Top)
	}
	if r = report(t, s, "node_id="+b); r.Total != 100 {
		t.Fatalf("node b: %d", r.Total)
	}
}

func TestIngestCumulative(t *testing.T) {
	s, pool, a, _ := setup(t)
	send := func(epoch string, items []api.AnalyticsTopItem, evicted ...string) {
		t.Helper()
		b := api.AnalyticsBatch{Day: today, SampleRate: 1, TopsMode: api.AnalyticsTopsCumulative, Epoch: epoch,
			Tops: map[string][]api.AnalyticsTopItem{"queried": items}}
		if len(evicted) > 0 {
			b.Evicted = map[string][]string{"queried": evicted}
		}
		if rec := post(t, s, a, b); rec.Code != 204 {
			t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
		}
	}
	top := func() map[string]int64 {
		t.Helper()
		m := map[string]int64{}
		for _, e := range report(t, s, "node_id="+a).Top {
			m[e.Name] = e.Count
		}
		return m
	}
	check := func(want map[string]int64) {
		t.Helper()
		if got := top(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("top = %v, want %v", got, want)
		}
	}
	// A legacy delta row is folded into base by the first cumulative batch.
	if rec := post(t, s, a, api.AnalyticsBatch{Day: today, SampleRate: 1,
		Tops: map[string][]api.AnalyticsTopItem{"queried": {{Name: "z.example", Count: 7}}}}); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	send("e1", []api.AnalyticsTopItem{{Name: "x.example", Count: 10}, {Name: "y.example", Count: 5}, {Name: "z.example", Count: 3}})
	check(map[string]int64{"x.example": 10, "y.example": 5, "z.example": 10})
	send("e1", []api.AnalyticsTopItem{{Name: "x.example", Count: 25}}) // cumulative, not added
	check(map[string]int64{"x.example": 25, "y.example": 5, "z.example": 10})
	send("e1", []api.AnalyticsTopItem{{Name: "x.example", Count: 30}}, "y.example") // y only ever in e1: row dropped
	check(map[string]int64{"x.example": 30, "z.example": 10})
	send("e2", []api.AnalyticsTopItem{{Name: "x.example", Count: 4, Error: 1}}) // agent restart: new epoch
	check(map[string]int64{"x.example": 34, "z.example": 10})
	send("e2", nil, "x.example", "z.example") // evicted: earlier epochs stay
	check(map[string]int64{"x.example": 30, "z.example": 10})
	send("e2", []api.AnalyticsTopItem{{Name: "x.example", Count: 2, Error: 2}}, "x.example") // evicted and re-added
	check(map[string]int64{"x.example": 32, "z.example": 10})
	var rows int
	pool.QueryRow(context.Background(), "SELECT count(*) FROM analytics_top_daily WHERE node_id = $1", a).Scan(&rows)
	if rows != 2 {
		t.Fatalf("rows = %d", rows)
	}
	if e := report(t, s, "node_id="+a).Top[0]; !e.Approximate {
		t.Fatalf("error in the current epoch must mark approximate: %+v", e)
	}
	// A later epoch without error keeps the folded base_error.
	send("e3", []api.AnalyticsTopItem{{Name: "x.example", Count: 1}})
	if e := report(t, s, "node_id="+a).Top[0]; e.Count != 33 || !e.Approximate {
		t.Fatalf("after fold: %+v", e)
	}
}

func TestTrimAndRetention(t *testing.T) {
	s, pool, a, b := setup(t)
	ctx := context.Background()
	old := time.Now().UTC().AddDate(0, 0, -3).Format(time.DateOnly)
	ancient := time.Now().UTC().AddDate(0, 0, -500).Format(time.DateOnly)
	for _, day := range []string{old, today, ancient} {
		for _, n := range []string{a, b} {
			if _, err := pool.Exec(ctx, `
				INSERT INTO analytics_top_daily (day, node_id, kind, name, count)
				SELECT $1, $2, k, 'n' || i, i FROM generate_series(1, 1005) i, unnest(ARRAY['queried', 'servfail']) k`, day, n); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, "INSERT INTO analytics_daily_totals (day, node_id, total) VALUES ($1, $2, 1)", day, n); err != nil {
				t.Fatal(err)
			}
		}
	}
	for range 2 { // idempotent
		if err := s.trim(ctx); err != nil {
			t.Fatal(err)
		}
	}
	counts := func(day string) (n, minCount int) {
		pool.QueryRow(ctx, "SELECT count(*), min(count) FROM analytics_top_daily WHERE day = $1 AND node_id = $2 AND kind = 'queried'", day, a).Scan(&n, &minCount)
		return
	}
	if n, lo := counts(old); n != 1000 || lo != 6 {
		t.Fatalf("old day: %d rows, min %d", n, lo)
	}
	if n, _ := counts(today); n != 1005 {
		t.Fatalf("today must stay untrimmed: %d", n)
	}
	if err := s.retention(ctx); err != nil {
		t.Fatal(err)
	}
	var tops, totals int
	pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM analytics_top_daily WHERE day = $1), (SELECT count(*) FROM analytics_daily_totals WHERE day = $1)", ancient).Scan(&tops, &totals)
	if tops != 0 || totals != 0 {
		t.Fatalf("retention left %d/%d rows", tops, totals)
	}
}

func TestReport(t *testing.T) {
	s, _, a, b := setup(t)
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	post(t, s, a, batch(today, 1))
	post(t, s, b, batch(yesterday, 1))
	nb := batch(today, 1)
	nb.Tops = map[string][]api.AnalyticsTopItem{"queried": {{Name: "=cmd.example", Count: 5}}}
	nb.ByQType, nb.ByRcode = nil, map[string]int64{"SERVFAIL": 3}
	nb.Total = 0
	post(t, s, b, nb)

	r := report(t, s, "")
	if len(r.ByDay) != 7 || r.ByDay[6].Day != today || r.ByDay[6].Total != 100 || r.ByDay[5].Total != 100 || r.ByDay[0].Total != 0 {
		t.Fatalf("by_day: %+v", r.ByDay)
	}
	if r.Total != 200 || r.ByQType["A"] != 120 || r.ByRcode["NXDOMAIN"] != 40 || r.ByRcode["SERVFAIL"] != 3 {
		t.Fatalf("totals: %+v", r)
	}
	top := r.Top[0]
	if top.Rank != 1 || top.Name != "www.example.com" || top.Count != 120 || math.Abs(top.Share-0.6) > 1e-9 || top.Approximate {
		t.Fatalf("top[0]: %+v", top)
	}
	if e := r.Top[1]; e.Name != "b.example.net" || !e.Approximate || e.Rank != 2 {
		t.Fatalf("top[1]: %+v", e)
	}

	r = report(t, s, "kind=nxdomain&node_id="+a)
	if r.Total != 100 || len(r.Top) != 1 || r.Top[0].Share != 1 {
		t.Fatalf("nxdomain for a: %+v", r)
	}
	r = report(t, s, "from="+yesterday+"&to="+yesterday+"&limit=1")
	if len(r.ByDay) != 1 || r.Total != 100 || len(r.Top) != 1 || r.Top[0].Count != 60 {
		t.Fatalf("range/limit: %+v", r)
	}
	if r = report(t, s, "kind=servfail"); len(r.Top) != 0 {
		t.Fatalf("servfail: %+v", r.Top)
	}

	// Sampled rows make every entry they contribute to approximate.
	sb := batch(today, 10)
	sb.Tops = map[string][]api.AnalyticsTopItem{"queried": {{Name: "www.example.com", Count: 10}}}
	post(t, s, b, sb)
	if r = report(t, s, "node_id="+b); !r.Top[0].Approximate {
		t.Fatalf("sampled: %+v", r.Top[0])
	}
	if r = report(t, s, "node_id="+a); r.Top[0].Approximate {
		t.Fatalf("node a is not sampled: %+v", r.Top[0])
	}

	for _, q := range []string{"from=x", "to=2026-13-01", "from=2026-02-01&to=2026-01-01", "kind=clients",
		"limit=0", "limit=1001", "limit=x", "node_id=not-a-uuid", "from=2000-01-01&to=2026-01-01"} {
		if rec := get(s, s.report, "/api/v1/analytics?"+q); rec.Code != 400 {
			t.Errorf("%s: want 400, got %d", q, rec.Code)
		}
	}

	rec := get(s, s.csv, "/api/v1/analytics.csv?from="+yesterday+"&to="+today+"&node_id="+b)
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "analytics-queried-"+yesterday+"_"+today+".csv") {
		t.Fatalf("filename: %s", cd)
	}
	recs, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(recs[0], ",") != "rank,name,count,share,approximate" || len(recs) != 4 ||
		strings.Join(recs[1], ",") != "1,www.example.com,70,0.350000,true" || recs[3][1] != "'=cmd.example" {
		t.Fatalf("csv: %q", recs)
	}
}
