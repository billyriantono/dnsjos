package reports

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// TestQueryPlans seeds ~200k rows per table and checks the report queries use indexes
// for the ranges the UI asks for. Plans are logged (go test -v).
func TestQueryPlans(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 400k rows")
	}
	pool := dbtest.New(t, "reports_plans")
	ctx := context.Background()
	mustExec(t, pool, "INSERT INTO nodes (name) SELECT 'n' || g FROM generate_series(1, 20) g")
	// 20 nodes × 10 000 minutes ≈ 7 days of metrics.
	mustExec(t, pool, `INSERT INTO metrics_minutely (node_id, ts, queries, latency_sum_ms, samples)
		SELECT n.id, date_trunc('minute', now()) - g * interval '1 minute', 100, 5, 1
		FROM nodes n, generate_series(0, 9999) g`)
	// 4 nodes × 100 days × 500 names.
	mustExec(t, pool, `INSERT INTO blocked_daily (day, node_id, qname, qtype, count)
		SELECT current_date - d, n.id, 'd' || q || '.example', 'A', 1
		FROM (SELECT id FROM nodes ORDER BY name LIMIT 4) n, generate_series(0, 99) d, generate_series(1, 500) q`)
	mustExec(t, pool, "ANALYZE")

	var node string
	if err := pool.QueryRow(ctx, "SELECT id FROM nodes ORDER BY name LIMIT 1").Scan(&node); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	week := blockedFilter{from: now.AddDate(0, 0, -6).Format(day), to: now.Format(day), limit: 100}
	weekNode := week
	weekNode.nodeID = node
	group := " GROUP BY b ORDER BY b"
	for _, c := range []struct {
		name, sql string
		args      []any
		table     string // must not be seq-scanned
	}{
		{"fleet 6h", metricsSelect + group, []any{300, now.Add(-6 * time.Hour), now}, "metrics_minutely"},
		{"node 6h", metricsSelect + " AND node_id = $4" + group, []any{300, now.Add(-6 * time.Hour), now, node}, "metrics_minutely"},
		{"blocked week top", q(week, api.CSVTop), a(week, api.CSVTop), "blocked_daily"},
		{"blocked week node summary", q(weekNode, api.CSVSummary), a(weekNode, api.CSVSummary), "blocked_daily"},
	} {
		rows, _ := pool.Query(ctx, "EXPLAIN "+c.sql, c.args...)
		lines, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		plan := strings.Join(lines, "\n")
		t.Logf("%s:\n%s", c.name, plan)
		if strings.Contains(plan, "Seq Scan on "+c.table) {
			t.Errorf("%s: seq scan on %s", c.name, c.table)
		}
	}
}

func q(f blockedFilter, kind string) string { s, _ := f.query(kind); return s }
func a(f blockedFilter, kind string) []any  { _, v := f.query(kind); return v }
