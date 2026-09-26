// Package server wires the panel together: migrations, bootstrap, routes, jobs, HTTP.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/billyriantono/dnsjos/internal/panel/analytics"
	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/auth"
	"github.com/billyriantono/dnsjos/internal/panel/blocklist"
	"github.com/billyriantono/dnsjos/internal/panel/config"
	"github.com/billyriantono/dnsjos/internal/panel/configs"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/panel/install"
	"github.com/billyriantono/dnsjos/internal/panel/jobs"
	"github.com/billyriantono/dnsjos/internal/panel/nodes"
	"github.com/billyriantono/dnsjos/internal/panel/reports"
	"github.com/billyriantono/dnsjos/internal/panel/upgrades"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Run starts the panel and blocks until ctx is cancelled, then shuts down gracefully.
func Run(ctx context.Context, cfg config.Config, log *slog.Logger, version string) error {
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, err := db.Migrate(ctx, pool)
	if err != nil {
		return err
	}
	if len(applied) > 0 {
		log.Info("migrations applied", "versions", applied)
	}

	jobCtx, stopJobs := context.WithCancel(context.Background())
	sched := jobs.New(jobCtx, log)
	defer func() { stopJobs(); sched.Wait() }()

	d := &app.Deps{
		Pool:     pool,
		Cfg:      cfg,
		Log:      log,
		Live:     app.NewLiveStore(),
		Settings: app.NewSettings(pool, cfg.PublicURL),
		Jobs:     sched,
		Version:  version,

		AgentVersion: install.AgentVersion(),
	}
	if err := d.Settings.Load(ctx); err != nil {
		return fmt.Errorf("load settings: %w", err)
	}
	if err := auth.Bootstrap(ctx, d); err != nil {
		return err
	}
	if err := EnsureDefaultProfile(ctx, d); err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           Handler(d),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: agents download the blocklist CDB (hundreds of MB) over slow links.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("panel listening", "addr", cfg.Listen, "version", version, "public_url", cfg.PublicURL)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler builds the full HTTP handler (routes + middleware). Exposed for tests.
func Handler(d *app.Deps) http.Handler {
	r := app.NewRouter(d)
	r.Public("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": d.Version})
	})
	r.Public("GET /readyz", func(w http.ResponseWriter, req *http.Request) {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if err := d.Pool.Ping(ctx); err != nil {
			httpx.WriteError(w, http.StatusServiceUnavailable, "db_unavailable", err.Error())
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	auth.Register(r, d)
	audit.Register(r, d)
	registerSettings(r, d)
	nodes.Register(r, d)
	configs.Register(r, d)
	blocklist.Register(r, d)
	reports.Register(r, d)
	analytics.Register(r, d)
	upgrades.Register(r, d)
	r.Public("/", spaHandler())

	var h http.Handler = r
	h = httpx.CSRF(h)
	h = httpx.BodyLimit(httpx.MaxBody, h)
	h = httpx.Recover(d.Log, h)
	return httpx.Logging(d.Log, h)
}

// EnsureDefaultProfile gives the seeded "default" profile a published version 1 with
// the production defaults when it has no versions yet.
func EnsureDefaultProfile(ctx context.Context, d *app.Deps) error {
	spec, err := json.Marshal(api.DefaultConfigSpec())
	if err != nil {
		return err
	}
	tag, err := d.Pool.Exec(ctx, `
		INSERT INTO config_versions (profile_id, version, spec, comment, published, published_at)
		SELECT p.id, 1, $1, 'initial production defaults', true, now()
		FROM config_profiles p
		WHERE p.name = 'default' AND NOT EXISTS (SELECT 1 FROM config_versions v WHERE v.profile_id = p.id)
		ON CONFLICT DO NOTHING`, spec)
	if err != nil {
		return fmt.Errorf("default profile: %w", err)
	}
	if tag.RowsAffected() > 0 {
		d.Log.Info("default profile version 1 published")
	}
	return nil
}
