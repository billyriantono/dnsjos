package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func registerSettings(r *app.Router, d *app.Deps) {
	r.Viewer("GET /api/v1/settings", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, d.Settings.Get())
	})
	// PUT decodes over the current values, so omitted fields keep their value.
	r.Admin("PUT /api/v1/settings", func(w http.ResponseWriter, req *http.Request) {
		s := d.Settings.Get()
		if err := httpx.ReadJSON(req, &s, 16<<10); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
		if msg := validateSettings(&s); msg != "" {
			httpx.BadRequest(w, msg)
			return
		}
		ctx := req.Context()
		err := pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
			v := reflect.ValueOf(s)
			for i := range v.NumField() {
				key := strings.Split(v.Type().Field(i).Tag.Get("json"), ",")[0]
				val, _ := json.Marshal(v.Field(i).Interface())
				if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
					ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, val); err != nil {
					return err
				}
			}
			return audit.Record(req, tx, "settings.update", "settings", "", s)
		})
		if err != nil {
			httpx.WriteDBError(w, req, err)
			return
		}
		if err := d.Settings.Load(ctx); err != nil {
			httpx.WriteDBError(w, req, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, d.Settings.Get())
	})
}

func validateSettings(s *api.Settings) string {
	in := func(v, lo, hi int) bool { return v >= lo && v <= hi }
	switch {
	case !in(s.BlocklistBuildIntervalMinutes, 15, 7*24*60):
		return "blocklist_build_interval_minutes must be 15..10080"
	case !in(s.MetricsRetentionDays, 1, 3650):
		return "metrics_retention_days must be 1..3650"
	case !in(s.BlockedRetentionDays, 1, 3650):
		return "blocked_retention_days must be 1..3650"
	case !in(s.AnalyticsRetentionDays, 1, 3650):
		return "analytics_retention_days must be 1..3650"
	case !in(s.AgentPollIntervalS, 5, 3600):
		return "agent_poll_interval_s must be 5..3600"
	case !in(s.AgentHeartbeatIntervalS, 5, 600):
		return "agent_heartbeat_interval_s must be 5..600"
	}
	s.PublicURL = strings.TrimRight(strings.TrimSpace(s.PublicURL), "/")
	if s.PublicURL != "" {
		u, err := url.Parse(s.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "public_url must be an http(s) URL"
		}
	}
	return ""
}
