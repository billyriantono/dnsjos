package analytics

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Per-node trim to 1000 rows, then a fleet sum: a name just below each node's cut-off
// vanishes from the fleet top list even though its fleet total is the largest, and no
// remaining entry is flagged approximate.
func TestReviewTrimThenFleetMergeUndercounts(t *testing.T) {
	pool := dbtest.New(t, "analytics_review")
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
	s := &svc{&app.Deps{Pool: pool, Settings: st, Log: slog.New(slog.DiscardHandler)}}
	day := time.Now().UTC().AddDate(0, 0, -3).Format(time.DateOnly)
	for _, n := range []struct{ id, prefix string }{{a, "a"}, {b, "b"}} {
		items := []api.AnalyticsTopItem{{Name: "shared.example", Count: 9}}
		for i := range 1000 {
			items = append(items, api.AnalyticsTopItem{Name: fmt.Sprintf("%s%04d.example", n.prefix, i), Count: 10})
		}
		if rec := post(t, s, n.id, api.AnalyticsBatch{Day: day, Total: 10009, SampleRate: 1,
			Tops: map[string][]api.AnalyticsTopItem{api.AnalyticsQueried: items}}); rec.Code != 204 {
			t.Fatalf("post: %d %s", rec.Code, rec.Body)
		}
	}
	if err := s.trim(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := report(t, s, "from="+day+"&to="+day+"&limit=5")
	if r.Top[0].Name != "shared.example" {
		t.Fatalf("DEFECT: fleet #1 is %s (%d, approximate=%v); shared.example (true fleet count 18 > 10) was trimmed away on every node",
			r.Top[0].Name, r.Top[0].Count, r.Top[0].Approximate)
	}
}
