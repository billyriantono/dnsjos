package reports

import (
	"context"
	"fmt"
)

// retention prunes the time-series tables. A retention setting < 1 disables that prune
// rather than deleting everything.
func (s *svc) retention(ctx context.Context) error {
	set := s.d.Settings.Get()
	steps := []struct {
		name string
		sql  string
		args []any
		on   bool
	}{
		{"metrics_minutely", "DELETE FROM metrics_minutely WHERE ts < now() - make_interval(days => $1)",
			[]any{set.MetricsRetentionDays}, set.MetricsRetentionDays > 0},
		{"blocked_daily", "DELETE FROM blocked_daily WHERE day < current_date - $1::int",
			[]any{set.BlockedRetentionDays}, set.BlockedRetentionDays > 0},
		{"offender_events", "DELETE FROM offender_events WHERE closed AND last_seen < now() - interval '90 days'", nil, true},
		{"cgk_reports", `DELETE FROM cgk_reports WHERE id IN (
			SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY node_id ORDER BY measured_at DESC, id DESC) AS rn
			                FROM cgk_reports) x WHERE rn > 100)`, nil, true},
	}
	for _, st := range steps {
		if !st.on {
			continue
		}
		tag, err := s.d.Pool.Exec(ctx, st.sql, st.args...)
		if err != nil {
			return fmt.Errorf("retention %s: %w", st.name, err)
		}
		if n := tag.RowsAffected(); n > 0 {
			s.d.Log.Info("retention", "table", st.name, "deleted", n)
		}
	}
	return nil
}
