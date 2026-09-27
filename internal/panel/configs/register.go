package configs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/panel/upgrades"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/dnsconf"
)

// Register mounts the configs routes.
func Register(r *app.Router, d *app.Deps) {
	h := &handlers{d}
	r.Viewer("GET /api/v1/profiles", h.listProfiles)
	r.Admin("POST /api/v1/profiles", h.createProfile)
	r.Viewer("GET /api/v1/profiles/{id}", h.getProfile)
	r.Admin("PATCH /api/v1/profiles/{id}", h.patchProfile)
	r.Admin("DELETE /api/v1/profiles/{id}", h.deleteProfile)
	r.Viewer("GET /api/v1/profiles/{id}/versions", h.listVersions)
	r.Admin("POST /api/v1/profiles/{id}/versions", h.createVersion)
	r.Viewer("GET /api/v1/profiles/{id}/versions/{v}", h.getVersion)
	r.Admin("POST /api/v1/profiles/{id}/versions/{v}/publish", h.publish)
	r.Viewer("GET /api/v1/profiles/{id}/versions/{a}/diff/{b}", h.diff)
	// Read-only render, so any signed-in user may preview.
	r.Session("POST /api/v1/profiles/{id}/preview", h.preview)
	r.Viewer("GET /api/v1/nodes/{id}/config/rendered", h.nodeRendered)
}

type handlers struct{ d *app.Deps }

const profileSelect = `
	SELECT p.id, p.name, p.description, p.created_at,
		coalesce((SELECT max(version) FROM config_versions v WHERE v.profile_id = p.id), 0),
		(SELECT max(version) FROM config_versions v WHERE v.profile_id = p.id AND v.published),
		-- Nodes without a profile follow "default" (as in Effective and deleteProfile).
		(SELECT count(*) FROM nodes n WHERE n.deleted_at IS NULL
			AND (n.profile_id = p.id OR (n.profile_id IS NULL AND p.name = 'default')))
	FROM config_profiles p`

func scanProfile(row pgx.Row) (api.Profile, error) {
	var p api.Profile
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.LatestVersion, &p.PublishedVersion, &p.Nodes)
	return p, err
}

const versionSelect = `SELECT id, profile_id, version, spec, comment, created_by, created_at, published, published_at FROM config_versions`

func scanVersion(row pgx.Row) (api.ConfigVersion, error) {
	var v api.ConfigVersion
	err := row.Scan(&v.ID, &v.ProfileID, &v.Version, &v.Spec, &v.Comment, &v.CreatedBy, &v.CreatedAt, &v.Published, &v.PublishedAt)
	return v, err
}

func (h *handlers) listProfiles(w http.ResponseWriter, r *http.Request) {
	rows, _ := h.d.Pool.Query(r.Context(), profileSelect+" ORDER BY p.name")
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.Profile, error) { return scanProfile(row) })
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if items == nil {
		items = []api.Profile{}
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.Profile]{Items: items, Total: len(items)})
}

func (h *handlers) getProfile(w http.ResponseWriter, r *http.Request) {
	p, err := scanProfile(h.d.Pool.QueryRow(r.Context(), profileSelect+" WHERE p.id = $1", r.PathValue("id")))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func checkName(name string) error {
	if name == "" || len(name) > 64 || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("name: 1-64 characters, no control characters")
	}
	return nil
}

func (h *handlers) createProfile(w http.ResponseWriter, r *http.Request) {
	var req api.ProfileRequest
	if err := httpx.ReadJSON(r, &req, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	var name, desc string
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		desc = *req.Description
	}
	if err := checkName(name); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	ctx := r.Context()
	spec, comment := api.DefaultConfigSpec(), "initial defaults"
	if req.CopyFrom != nil && *req.CopyFrom != "" {
		err := h.d.Pool.QueryRow(ctx, `SELECT v.spec, 'copy of ' || p.name || ' v' || v.version
			FROM config_versions v JOIN config_profiles p ON p.id = v.profile_id
			WHERE v.profile_id = $1 AND v.published ORDER BY v.version DESC LIMIT 1`, *req.CopyFrom).Scan(&spec, &comment)
		if db.IsNotFound(err) || db.IsInvalidInput(err) {
			httpx.BadRequest(w, "copy_from: no such profile or it has no published version")
			return
		} else if err != nil {
			httpx.WriteDBError(w, r, err)
			return
		}
	}
	var id string
	err := pgx.BeginFunc(ctx, h.d.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO config_profiles (name, description) VALUES ($1, $2) RETURNING id`,
			name, desc).Scan(&id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO config_versions (profile_id, version, spec, comment, created_by, published, published_at)
			VALUES ($1, 1, $2, $3, $4, true, now())`, id, spec, comment, app.UserIDFrom(ctx)); err != nil {
			return err
		}
		return audit.Record(r, tx, "profile.create", "profile", id, map[string]any{"name": name, "copy_from": req.CopyFrom})
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	p, err := scanProfile(h.d.Pool.QueryRow(ctx, profileSelect+" WHERE p.id = $1", id))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (h *handlers) patchProfile(w http.ResponseWriter, r *http.Request) {
	var req api.ProfileRequest
	if err := httpx.ReadJSON(r, &req, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if req.Name != nil {
		*req.Name = strings.TrimSpace(*req.Name)
		if err := checkName(*req.Name); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
	}
	id := r.PathValue("id")
	err := pgx.BeginFunc(r.Context(), h.d.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `UPDATE config_profiles SET name = coalesce($2, name),
			description = coalesce($3, description) WHERE id = $1`, id, req.Name, req.Description)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return audit.Record(r, tx, "profile.update", "profile", id, req)
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	h.getProfile(w, r)
}

var errInUse = errors.New("in use")

func (h *handlers) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var nodes int
	err := pgx.BeginFunc(r.Context(), h.d.Pool, func(tx pgx.Tx) error {
		var name string
		if err := tx.QueryRow(r.Context(), "SELECT name FROM config_profiles WHERE id = $1 FOR UPDATE", id).Scan(&name); err != nil {
			return err
		}
		// Nodes without a profile follow "default", so they count as its users.
		if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM nodes WHERE deleted_at IS NULL
			AND (profile_id = $1 OR (profile_id IS NULL AND $2 = 'default'))`, id, name).Scan(&nodes); err != nil {
			return err
		}
		if nodes > 0 {
			return errInUse
		}
		if _, err := tx.Exec(r.Context(), "DELETE FROM config_profiles WHERE id = $1", id); err != nil {
			return err
		}
		return audit.Record(r, tx, "profile.delete", "profile", id, map[string]string{"name": name})
	})
	switch {
	case errors.Is(err, errInUse):
		httpx.WriteError(w, http.StatusConflict, "conflict", strconv.Itoa(nodes)+" node(s) still use this profile")
	case err != nil:
		httpx.WriteDBError(w, r, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *handlers) listVersions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !h.profileExists(w, r, id) {
		return
	}
	rows, _ := h.d.Pool.Query(r.Context(), versionSelect+" WHERE profile_id = $1 ORDER BY version DESC", id)
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.ConfigVersion, error) { return scanVersion(row) })
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if items == nil {
		items = []api.ConfigVersion{}
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.ConfigVersion]{Items: items, Total: len(items)})
}

func (h *handlers) profileExists(w http.ResponseWriter, r *http.Request, id string) bool {
	var one int
	if err := h.d.Pool.QueryRow(r.Context(), "SELECT 1 FROM config_profiles WHERE id = $1", id).Scan(&one); err != nil {
		httpx.WriteDBError(w, r, err)
		return false
	}
	return true
}

func (h *handlers) version(ctx context.Context, profileID, v string) (api.ConfigVersion, error) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return api.ConfigVersion{}, pgx.ErrNoRows
	}
	return scanVersion(h.d.Pool.QueryRow(ctx, versionSelect+" WHERE profile_id = $1 AND version = $2", profileID, n))
}

func (h *handlers) getVersion(w http.ResponseWriter, r *http.Request) {
	v, err := h.version(r.Context(), r.PathValue("id"), r.PathValue("v"))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

// previewRuntime stands in for node secrets the panel never has; MaskSecrets hides them anyway.
func previewRuntime(hostname string) api.NodeRuntime {
	return api.NodeRuntime{ConsoleKey: "preview", WebPassword: "preview", WebAPIKey: "preview", Hostname: hostname}
}

// checkSpec validates and test-renders spec; the error text is safe to show.
func checkSpec(spec api.ConfigSpec) (map[string][]byte, error) {
	return dnsconf.Render(spec, previewRuntime("preview"))
}

func (h *handlers) createVersion(w http.ResponseWriter, r *http.Request) {
	var req api.VersionCreate
	if err := httpx.ReadJSON(r, &req, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if _, err := checkSpec(req.Spec); err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_config", err.Error())
		return
	}
	id := r.PathValue("id")
	var v api.ConfigVersion
	err := pgx.BeginFunc(r.Context(), h.d.Pool, func(tx pgx.Tx) error {
		// Row lock serialises concurrent saves so version numbers stay dense.
		var one int
		if err := tx.QueryRow(r.Context(), "SELECT 1 FROM config_profiles WHERE id = $1 FOR UPDATE", id).Scan(&one); err != nil {
			return err
		}
		var err error
		v, err = scanVersion(tx.QueryRow(r.Context(), `
			INSERT INTO config_versions (profile_id, version, spec, comment, created_by)
			VALUES ($1, (SELECT coalesce(max(version), 0) + 1 FROM config_versions WHERE profile_id = $1), $2, $3, $4)
			RETURNING id, profile_id, version, spec, comment, created_by, created_at, published, published_at`,
			id, req.Spec, req.Comment, app.UserIDFrom(r.Context())))
		if err != nil {
			return err
		}
		return audit.Record(r, tx, "config_version.create", "profile", id, map[string]any{"version": v.Version, "comment": req.Comment})
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, v)
}

func (h *handlers) publish(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := strconv.Atoi(r.PathValue("v"))
	if err != nil {
		httpx.NotFound(w)
		return
	}
	// ?staged=true: one node at a time behind the upgrade health gate (SPEC §6.5).
	staged := r.URL.Query().Get("staged") == "true"
	var v api.ConfigVersion
	var runID int64
	err = pgx.BeginFunc(r.Context(), h.d.Pool, func(tx pgx.Tx) error {
		ctx := r.Context()
		if err := tx.QueryRow(ctx, "SELECT 1 FROM config_versions WHERE profile_id = $1 AND version = $2",
			id, n).Scan(new(int)); err != nil {
			return err
		}
		var err error
		if staged {
			runID, err = upgrades.StartConfigRollout(ctx, tx, id, n, app.UserIDFrom(ctx), time.Now())
		} else {
			err = upgrades.PublishAll(ctx, tx, id)
		}
		if err != nil {
			return err
		}
		v, err = scanVersion(tx.QueryRow(ctx, `
			UPDATE config_versions SET published = true, published_at = coalesce(published_at, now())
			WHERE profile_id = $1 AND version = $2
			RETURNING id, profile_id, version, spec, comment, created_by, created_at, published, published_at`, id, n))
		if err != nil {
			return err
		}
		detail := map[string]any{"version": n}
		if runID != 0 {
			detail["rollout_run"] = runID
		}
		return audit.Record(r, tx, "config_version.publish", "profile", id, detail)
	})
	if err != nil {
		upgrades.WriteErr(w, r, err)
		return
	}
	if runID != 0 {
		w.Header().Set("Location", "/api/v1/upgrades/"+strconv.FormatInt(runID, 10))
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (h *handlers) diff(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, err := h.version(r.Context(), id, r.PathValue("a"))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	b, err := h.version(r.Context(), id, r.PathValue("b"))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	changes, err := Diff(a.Spec, b.Spec)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.ConfigVersionDiff{VersionDiff: api.VersionDiff{A: a, B: b}, Changes: changes})
}

func (h *handlers) preview(w http.ResponseWriter, r *http.Request) {
	var req api.PreviewRequest
	if err := httpx.ReadJSON(r, &req, httpx.MaxJSON); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if !h.profileExists(w, r, r.PathValue("id")) {
		return
	}
	files, err := checkSpec(req.Spec)
	if err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_config", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.RenderedConfig{Spec: req.Spec, Files: dnsconf.MaskSecrets(files)})
}

var (
	// ErrNoConfig means the node has no profile or its profile has no published version.
	ErrNoConfig = errors.New("node has no published config")
	// ErrOverrides wraps a node overrides patch that cannot be merged.
	ErrOverrides = errors.New("invalid node overrides")
)

// Effective returns a node's effective spec: its profile's newest published version
// with the node overrides merged over it (SPEC §6.3).
func Effective(ctx context.Context, q db.Querier, nodeID string) (spec api.ConfigSpec, version int, profile string, err error) {
	var overrides []byte
	var profileID *string
	var pin *int
	// A node without a profile follows "default", exactly like GET /agent/v1/config.
	err = q.QueryRow(ctx, `SELECT p.id, coalesce(p.name, ''), n.overrides, n.config_pin FROM nodes n
		LEFT JOIN config_profiles p ON p.id = coalesce(n.profile_id, (SELECT id FROM config_profiles WHERE name = 'default'))
		WHERE n.id = $1 AND n.deleted_at IS NULL`, nodeID).Scan(&profileID, &profile, &overrides, &pin)
	if err != nil {
		return spec, 0, "", err
	}
	if profileID == nil {
		return spec, 0, "", ErrNoConfig
	}
	err = q.QueryRow(ctx, `SELECT version, spec FROM config_versions WHERE profile_id = $1 AND published
		AND ($2::int IS NULL OR version <= $2) ORDER BY version DESC LIMIT 1`, *profileID, pin).Scan(&version, &spec)
	if db.IsNotFound(err) {
		return spec, 0, profile, ErrNoConfig
	} else if err != nil {
		return spec, 0, profile, err
	}
	if spec, err = api.MergeSpec(spec, overrides); err != nil {
		return spec, 0, profile, fmt.Errorf("%w: %v", ErrOverrides, err)
	}
	return spec, version, profile, nil
}

func (h *handlers) nodeRendered(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	spec, _, _, err := Effective(r.Context(), h.d.Pool, id)
	switch {
	case errors.Is(err, ErrNoConfig):
		httpx.WriteError(w, http.StatusNotFound, "no_config", err.Error())
		return
	case errors.Is(err, ErrOverrides):
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_config", err.Error())
		return
	case err != nil:
		httpx.WriteDBError(w, r, err)
		return
	}
	var host string
	if err := h.d.Pool.QueryRow(r.Context(), "SELECT coalesce(nullif(hostname, ''), name) FROM nodes WHERE id = $1", id).Scan(&host); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	files, err := dnsconf.Render(spec, previewRuntime(host))
	if err != nil {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invalid_config", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.RenderedConfig{Spec: spec, Files: dnsconf.MaskSecrets(files)})
}
