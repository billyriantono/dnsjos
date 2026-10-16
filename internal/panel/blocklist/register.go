package blocklist

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/colinmarc/cdb"
	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	keys "github.com/billyriantono/dnsjos/internal/shared/cdb"
)

// Register mounts the blocklist routes and the scheduled build job.
func Register(r *app.Router, d *app.Deps) {
	s := newService(d)
	s.routes(r)
	// Rows left 'running' by a panel that died mid-build.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = d.Pool.Exec(ctx, `UPDATE blocklist_builds SET status = 'failed', finished_at = now(),
		error = 'interrupted (panel restarted)' WHERE status = 'running'`)
	// The interval setting is re-read on every tick.
	d.Jobs.Every("blocklist-build", time.Minute, s.tick)
	d.Jobs.Every("rpz-sync", time.Minute, s.rpzSyncAll)
	d.Jobs.Every("allowlist-purge", time.Hour, s.purgeAllow)
}

func (s *Service) routes(r *app.Router) {
	r.Viewer("GET /api/v1/blocklist/sources", s.listSources)
	r.Viewer("GET /api/v1/blocklist/sources/{id}", s.getSource)
	r.Admin("POST /api/v1/blocklist/sources", s.createSource)
	r.Admin("PATCH /api/v1/blocklist/sources/{id}", s.patchSource)
	r.Admin("DELETE /api/v1/blocklist/sources/{id}", s.deleteSource)
	r.Viewer("GET /api/v1/blocklist/builds", s.listBuilds)
	r.Viewer("GET /api/v1/blocklist/builds/{id}/changes", s.listChanges)
	r.Admin("POST /api/v1/blocklist/builds", s.startBuild)
	r.Viewer("GET /api/v1/blocklist/current", s.current)
	r.Viewer("GET /api/v1/blocklist/profiles", s.listProfiles)
	r.Viewer("GET /api/v1/blocklist/lookup", s.lookup)
	r.Viewer("GET /api/v1/rpz/upstreams", s.listRPZUpstreams)
	r.Admin("POST /api/v1/rpz/upstreams", s.createRPZUpstream)
	r.Admin("PATCH /api/v1/rpz/upstreams/{id}", s.patchRPZUpstream)
	r.Admin("DELETE /api/v1/rpz/upstreams/{id}", s.deleteRPZUpstream)
	r.Admin("POST /api/v1/rpz/upstreams/{id}/sync", s.syncRPZUpstream)
	r.Agent("GET /agent/v1/blocklist", s.serveCDB)
	r.Viewer("GET /api/v1/allowlist", s.listAllow)
	r.Admin("POST /api/v1/allowlist", s.createAllow)
	r.Admin("DELETE /api/v1/allowlist/{id}", s.deleteAllow)
	r.Agent("GET /agent/v1/allowlist", s.serveAllowlist)
}

const sourceCols = `id, name, kind, url, content, enabled,
	array(SELECT sp.profile_id::text FROM blocklist_source_profiles sp WHERE sp.source_id = blocklist_sources.id ORDER BY sp.profile_id),
	array(SELECT p.name FROM blocklist_source_profiles sp JOIN config_profiles p ON p.id = sp.profile_id WHERE sp.source_id = blocklist_sources.id ORDER BY sp.profile_id),
	etag, last_modified, last_fetch_at, last_status, entries, created_at, updated_at`

// sourceListCols deliberately omits the (potentially very large) source content. Keep the
// empty content expression in the projection so the shared scanner and response shape remain
// compatible, while PostgreSQL never transfers the stored payload for list requests.
const sourceListCols = `id, name, kind, url, ''::text, enabled,
	array(SELECT sp.profile_id::text FROM blocklist_source_profiles sp WHERE sp.source_id = blocklist_sources.id ORDER BY sp.profile_id),
	array(SELECT p.name FROM blocklist_source_profiles sp JOIN config_profiles p ON p.id = sp.profile_id WHERE sp.source_id = blocklist_sources.id ORDER BY sp.profile_id),
	etag, last_modified, last_fetch_at, last_status, entries, created_at, updated_at`

func scanSource(row pgx.Row) (api.BlocklistSource, error) {
	var x api.BlocklistSource
	err := row.Scan(&x.ID, &x.Name, &x.Kind, &x.URL, &x.Content, &x.Enabled, &x.ProfileIDs, &x.ProfileNames,
		&x.ETag, &x.LastModified, &x.LastFetchAt, &x.LastStatus, &x.Entries, &x.CreatedAt, &x.UpdatedAt)
	// ProfileID/ProfileName mirror the first profile so older single-profile clients keep working.
	if len(x.ProfileIDs) > 0 {
		x.ProfileID, x.ProfileName = x.ProfileIDs[0], x.ProfileNames[0]
	}
	if x.ProfileIDs == nil {
		x.ProfileIDs = []string{}
	}
	if x.ProfileNames == nil {
		x.ProfileNames = []string{}
	}
	return x, err
}

// setSourceProfiles replaces a source's profile set with profileIDs (empty = global). It runs
// in the caller's transaction so the row and its profiles change together. A typo'd id fails
// the FK here rather than silently dropping the scope.
func setSourceProfiles(ctx context.Context, tx pgx.Tx, sourceID string, profileIDs []string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM blocklist_source_profiles WHERE source_id = $1", sourceID); err != nil {
		return err
	}
	for _, pid := range profileIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO blocklist_source_profiles (source_id, profile_id)
			VALUES ($1, $2) ON CONFLICT DO NOTHING`, sourceID, pid); err != nil {
			return err
		}
	}
	return nil
}

// normProfileIDs dedupes and drops empties from a requested profile set, keeping order.
func normProfileIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// createProfileIDs resolves the requested profile set for a create payload, folding the legacy
// single ProfileID into it.
func createProfileIDs(single string, ids []string) []string {
	if len(ids) == 0 && single != "" {
		ids = []string{single}
	}
	return normProfileIDs(ids)
}

// checkProfiles validates every requested profile id (uuid + exists).
func (s *Service) checkProfiles(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if err := s.checkProfile(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

var kinds = []string{"trustpositif_domains", "trustpositif_ips", "url_domains", "url_ips",
	"manual_domains", "manual_ips", "whitelist", "rpz_domains"}

func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

var errProfileID = errors.New("profile_id must be a profile uuid, or empty for the global scope")

// profileParam reads ?profile_id=. present tells "profile_id=" (empty: the global scope)
// apart from no parameter at all; any other value must be a uuid, so a typo is a 400 and
// not a failed cast in the database.
func profileParam(r *http.Request) (id string, present bool, err error) {
	q := r.URL.Query()
	if _, present = q["profile_id"]; !present {
		return "", false, nil
	}
	if id = q.Get("profile_id"); id != "" && !uuidRe.MatchString(id) {
		return "", true, errProfileID
	}
	return id, true, nil
}

func (s *Service) listSources(w http.ResponseWriter, r *http.Request) {
	// profile_id= (empty string) selects the global sources; the parameter absent lists every
	// source. Any other value must be a profile uuid.
	profileID, scoped, err := profileParam(r)
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	where, args := "", []any{}
	if scoped {
		where = " WHERE " + sourceScopeWhere("blocklist_sources", 1)
		args = append(args, profileID)
	}
	rows, _ := s.d.Pool.Query(r.Context(), "SELECT "+sourceListCols+" FROM blocklist_sources"+where+" ORDER BY created_at, name", args...)
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.BlocklistSource, error) { return scanSource(row) })
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if items == nil {
		items = []api.BlocklistSource{}
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.BlocklistSource]{Items: items, Total: len(items)})
}

func (s *Service) getSource(w http.ResponseWriter, r *http.Request) {
	src, err := scanSource(s.d.Pool.QueryRow(r.Context(), "SELECT "+sourceCols+" FROM blocklist_sources WHERE id = $1", r.PathValue("id")))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, src)
}

func (s *Service) createSource(w http.ResponseWriter, r *http.Request) {
	var req api.BlocklistSourceCreate
	if err := httpx.ReadJSON(r, &req, httpx.MaxBody); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	req.Name, req.URL = strings.TrimSpace(req.Name), strings.TrimSpace(req.URL)
	switch {
	case req.Name == "":
		httpx.BadRequest(w, "name is required")
		return
	case !slices.Contains(kinds, req.Kind):
		httpx.BadRequest(w, "kind must be one of "+strings.Join(kinds, ", "))
		return
	case isURLKind(req.Kind) && !validURL(req.URL):
		httpx.BadRequest(w, "url must be an http(s) URL")
		return
	case !isURLKind(req.Kind):
		req.URL = ""
	}
	enabled := req.Enabled == nil || *req.Enabled
	profiles := createProfileIDs(req.ProfileID, req.ProfileIDs)
	if err := s.checkProfiles(r.Context(), profiles); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	var src api.BlocklistSource
	err := pgx.BeginFunc(r.Context(), s.d.Pool, func(tx pgx.Tx) error {
		var id string
		// The legacy profile_id column is set to the first profile so a mixed-version rollout
		// still scopes correctly; the join table is the source of truth.
		if err := tx.QueryRow(r.Context(), `INSERT INTO blocklist_sources (name, kind, url, content, enabled, profile_id)
			VALUES ($1, $2, $3, $4, $5, nullif($6, '')::uuid) RETURNING id`,
			req.Name, req.Kind, req.URL, req.Content, enabled, firstOrEmpty(profiles)).Scan(&id); err != nil {
			return err
		}
		if err := setSourceProfiles(r.Context(), tx, id, profiles); err != nil {
			return err
		}
		var err error
		src, err = scanSource(tx.QueryRow(r.Context(), "SELECT "+sourceCols+" FROM blocklist_sources WHERE id = $1", id))
		return err
	})
	if db.IsForeignKeyViolation(err) || db.IsInvalidInput(err) {
		httpx.BadRequest(w, "profile_id: no such profile")
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	_ = audit.Record(r, s.d.Pool, "blocklist.source.create", "blocklist_source", src.ID,
		map[string]any{"name": src.Name, "kind": src.Kind, "url": src.URL, "profile_ids": src.ProfileIDs})
	httpx.WriteJSON(w, http.StatusCreated, src)
}

// firstOrEmpty returns the first element or "" for an empty slice.
func firstOrEmpty(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// checkProfile rejects an unknown profile id so a bad client is told rather than the FK
// failing later.
func (s *Service) checkProfile(ctx context.Context, profileID string) error {
	if profileID == "" {
		return nil
	}
	if !uuidRe.MatchString(profileID) {
		return errProfileID
	}
	var exists bool
	if err := s.d.Pool.QueryRow(ctx, "SELECT true FROM config_profiles WHERE id = nullif($1, '')::uuid", profileID).Scan(&exists); err != nil {
		if db.IsNotFound(err) {
			return errors.New("profile not found")
		}
		return err
	}
	return nil
}

func (s *Service) patchSource(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req api.BlocklistSourcePatch
	if err := httpx.ReadJSON(r, &req, httpx.MaxBody); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	var kind string
	if err := s.d.Pool.QueryRow(r.Context(), "SELECT kind FROM blocklist_sources WHERE id = $1", id).Scan(&kind); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if req.Name != nil && strings.TrimSpace(*req.Name) == "" {
		httpx.BadRequest(w, "name must not be empty")
		return
	}
	// url is meaningless on a manual source: the dialog submits the full shape (url:""), so
	// ignore it rather than rejecting the request, mirroring createSource.
	if req.URL != nil {
		*req.URL = strings.TrimSpace(*req.URL)
		if !isURLKind(kind) {
			req.URL = nil
		} else if !validURL(*req.URL) {
			httpx.BadRequest(w, "url must be an http(s) URL on a URL source")
			return
		}
	}
	// A profile change is a request to set the exact profile set; null leaves it unchanged.
	// The legacy single ProfileID folds into it when ProfileIDs is absent.
	var profiles []string
	profilesSet := false
	if req.ProfileIDs != nil {
		profiles, profilesSet = normProfileIDs(*req.ProfileIDs), true
	} else if req.ProfileID != nil {
		profiles, profilesSet = normProfileIDs([]string{*req.ProfileID}), true
	}
	if profilesSet {
		if err := s.checkProfiles(r.Context(), profiles); err != nil {
			httpx.BadRequest(w, err.Error())
			return
		}
	}
	// A new URL invalidates the cached validators. A profile change is a scoped move, so the
	// source is also rebuilt from a clean slate (its fingerprint belongs to the old scope).
	var src api.BlocklistSource
	err := pgx.BeginFunc(r.Context(), s.d.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `UPDATE blocklist_sources SET
			name = coalesce($2, name), content = coalesce($4, content), enabled = coalesce($5, enabled),
			profile_id = CASE WHEN $6::boolean THEN nullif($7, '')::uuid ELSE profile_id END,
			etag = CASE WHEN $3::text <> url OR $6::boolean THEN '' ELSE etag END,
			last_modified = CASE WHEN $3::text <> url OR $6::boolean THEN '' ELSE last_modified END,
			url = coalesce($3, url), updated_at = now()
			WHERE id = $1 RETURNING id`,
			id, req.Name, req.URL, req.Content, req.Enabled, profilesSet, firstOrEmpty(profiles)).Scan(&src.ID); err != nil {
			return err
		}
		if profilesSet {
			if err := setSourceProfiles(r.Context(), tx, id, profiles); err != nil {
				return err
			}
		}
		var err error
		src, err = scanSource(tx.QueryRow(r.Context(), "SELECT "+sourceCols+" FROM blocklist_sources WHERE id = $1", id))
		return err
	})
	if db.IsNotFound(err) {
		httpx.NotFound(w)
		return
	} else if db.IsForeignKeyViolation(err) || db.IsInvalidInput(err) {
		httpx.BadRequest(w, "profile_id: no such profile")
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	_ = audit.Record(r, s.d.Pool, "blocklist.source.update", "blocklist_source", id, req)
	httpx.WriteJSON(w, http.StatusOK, src)
}

func (s *Service) deleteSource(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var name string
	if err := s.d.Pool.QueryRow(r.Context(), "DELETE FROM blocklist_sources WHERE id = $1 RETURNING name", id).Scan(&name); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	os.Remove(s.sourcePath(id))
	_ = audit.Record(r, s.d.Pool, "blocklist.source.delete", "blocklist_source", id, map[string]string{"name": name})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) listBuilds(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	// profile_id= (empty string) selects the global builds; the parameter absent lists every
	// build across scopes.
	profileID, scoped, err := profileParam(r)
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	itemsWhere, countWhere := "", ""
	if scoped {
		itemsWhere = " AND " + scopeWhere("b.profile_id", 2)
		countWhere = " AND " + scopeWhere("b.profile_id", 1)
	}
	rows, _ := s.d.Pool.Query(r.Context(), "SELECT "+buildCols+" "+buildFrom+" WHERE true"+itemsWhere+" ORDER BY b.id DESC LIMIT $1",
		append([]any{limit}, profileArg(itemsWhere, profileID)...)...)
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.BlocklistBuild, error) { return scanBuild(row) })
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if items == nil {
		items = []api.BlocklistBuild{}
	}
	var total int
	if err := s.d.Pool.QueryRow(r.Context(), "SELECT count(*) FROM blocklist_builds b WHERE true"+countWhere,
		profileArg(countWhere, profileID)...).Scan(&total); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.BlocklistBuild]{Items: items, Total: total})
}

// profileArg returns the profile id argument only when where references it ($1).
func profileArg(where, profileID string) []any {
	if where == "" {
		return nil
	}
	return []any{profileID}
}

func (s *Service) startBuild(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "true"
	profileID := r.URL.Query().Get("profile_id")
	if err := s.checkProfile(r.Context(), profileID); err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	b, err := s.Start("manual", profileID, force)
	if errors.Is(err, errBusy) {
		httpx.WriteError(w, http.StatusConflict, "conflict", err.Error())
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	_ = audit.Record(r, s.d.Pool, "blocklist.build", "blocklist_build", strconv.FormatInt(b.ID, 10),
		map[string]any{"force": force, "profile_id": b.ProfileID})
	httpx.WriteJSON(w, http.StatusAccepted, b)
}

func (s *Service) current(w http.ResponseWriter, r *http.Request) {
	profileID, _, err := profileParam(r)
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	b, err := Current(r.Context(), s.d.Pool, profileID)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, b) // JSON null when there is no build yet
}

// listProfiles lists every profile with its blocklist scope: how many sources it owns, its
// newest own build, and the build its nodes actually run (its own, or the global one).
func (s *Service) listProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	global, err := Current(ctx, s.d.Pool, "")
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	rows, _ := s.d.Pool.Query(ctx, `
		SELECT p.id::text, p.name, p.description,
			(SELECT count(*) FROM blocklist_source_profiles sp WHERE sp.profile_id = p.id)
		FROM config_profiles p ORDER BY p.name`)
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.BlocklistProfile, error) {
		var x api.BlocklistProfile
		err := row.Scan(&x.ID, &x.Name, &x.Description, &x.SourceCount)
		return x, err
	})
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if items == nil {
		items = []api.BlocklistProfile{}
	}
	// One query for every profile's own newest ok build, keyed by profile id, so the page
	// load stays O(1) queries regardless of how many profiles exist.
	own, err := collectScopedCurrent(ctx, s.d.Pool)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	for i := range items {
		if b, ok := own[items[i].ID]; ok {
			items[i].OwnBuild = b
			items[i].EffectiveBuild = b
			continue
		}
		// A profile without a build of its own is served the global one.
		items[i].UsesGlobal = true
		items[i].EffectiveBuild = global
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.BlocklistProfile]{Items: items, Total: len(items)})
}

// collectScopedCurrent returns the newest ok build of every non-global scope, keyed by
// profile id. It is the one-shot form of Current for the profiles listing.
func collectScopedCurrent(ctx context.Context, q db.Querier) (map[string]*api.BlocklistBuild, error) {
	rows, _ := q.Query(ctx, "SELECT DISTINCT ON (b.profile_id) "+buildCols+" "+buildFrom+
		" WHERE b.status = 'ok' AND b.profile_id IS NOT NULL ORDER BY b.profile_id, b.finished_at DESC, b.id DESC")
	builds, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.BlocklistBuild, error) { return scanBuild(row) })
	if err != nil {
		return nil, err
	}
	out := make(map[string]*api.BlocklistBuild, len(builds))
	for i := range builds {
		out[builds[i].ProfileID] = &builds[i]
	}
	return out, nil
}

func (s *Service) lookup(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("name"))
	if q == "" {
		httpx.BadRequest(w, "name is required")
		return
	}
	profileID, _, err := profileParam(r)
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	b, err := Current(r.Context(), s.d.Pool, profileID)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	res := api.BlocklistLookup{Name: q}
	if b != nil {
		res, err = lookupCDB(s.artifact(b.SHA256), q)
	}
	if err == nil {
		err = allowMatch(r.Context(), s.d.Pool, &res)
	}
	if err == nil {
		err = s.history(r.Context(), &res)
	}
	if errors.Is(err, errBadName) {
		httpx.BadRequest(w, err.Error())
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

const changeCols = "c.build_id, c.name, c.added, b.finished_at"

func scanChanges(rows pgx.Rows) ([]api.BlocklistChange, error) {
	items, err := pgx.CollectRows(rows, pgx.RowToStructByPos[api.BlocklistChange])
	if items == nil {
		items = []api.BlocklistChange{}
	}
	return items, err
}

// history fills res with the changes to res.Name and its parents (any of which blocks it).
func (s *Service) history(ctx context.Context, res *api.BlocklistLookup) error {
	names := []string{res.Name}
	if _, err := netip.ParseAddr(res.Name); err != nil {
		for n := res.Name; strings.Contains(n, "."); {
			n = n[strings.IndexByte(n, '.')+1:]
			names = append(names, n)
		}
	}
	rows, _ := s.d.Pool.Query(ctx, "SELECT "+changeCols+` FROM blocklist_changes c
		JOIN blocklist_builds b ON b.id = c.build_id WHERE c.name = ANY($1) ORDER BY c.build_id DESC LIMIT 50`, names)
	var err error
	if res.History, err = scanChanges(rows); err != nil {
		return err
	}
	for _, c := range res.History {
		if res.Blocked && c.Name == res.Match {
			if c.Added {
				res.BlockedSince = &c.At
			}
			break
		}
	}
	return nil
}

// listChanges pages the names a build added/removed; q filters by substring.
func (s *Service) listChanges(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	offset = max(offset, 0)
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	// kind: "added" | "removed" | "" (both, added first).
	var added *bool
	switch k := r.URL.Query().Get("kind"); k {
	case "added", "removed":
		v := k == "added"
		added = &v
	case "":
	default:
		httpx.BadRequest(w, "kind must be added or removed")
		return
	}
	where := ` FROM blocklist_changes c JOIN blocklist_builds b ON b.id = c.build_id
		WHERE c.build_id = $1 AND strpos(c.name, $2) > 0 AND ($3::boolean IS NULL OR c.added = $3)`
	rows, _ := s.d.Pool.Query(r.Context(), "SELECT "+changeCols+where+" ORDER BY c.added DESC, c.name LIMIT $4 OFFSET $5",
		id, q, added, limit, offset)
	items, err := scanChanges(rows)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	var total int
	if err := s.d.Pool.QueryRow(r.Context(), "SELECT count(*)"+where, id, q, added).Scan(&total); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.BlocklistChange]{Items: items, Total: total})
}

var errBadName = errors.New("not a valid domain name or IPv4 address")

// lookupCDB checks q the way dnsdist does: an IPv4 by its exact key, a name by
// KeyValueLookupKeySuffix(0, true) — the name, then each parent down to the TLD.
func lookupCDB(path, q string) (api.BlocklistLookup, error) {
	res := api.BlocklistLookup{Name: q}
	c, err := cdb.Open(path)
	if err != nil {
		return res, err
	}
	defer c.Close()
	if a, err := netip.ParseAddr(q); err == nil {
		if !a.Unmap().Is4() {
			return res, errBadName
		}
		res.Name = a.Unmap().String()
		v, err := c.Get(keys.IPv4Key(a))
		if v != nil {
			res.Blocked, res.Match = true, res.Name
		}
		return res, err
	}
	name, ok := normalizeDomain(q)
	if !ok {
		return res, errBadName
	}
	res.Name = name
	for n := name; ; {
		v, err := c.Get(keys.DomainKey(n))
		if err != nil {
			return res, err
		}
		if v != nil {
			res.Blocked, res.Match = true, n
			return res, nil
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return res, nil
		}
		n = n[i+1:]
	}
}

// NodeProfileID resolves the profile whose blocklist a node should be served: the node's own
// profile, or the "default" profile when unset. "" means the node has no profile row, so
// the caller falls back to the global build. The one implementation for both the CDB the
// agent downloads (serveCDB) and the build the panel reports as desired (nodes package).
func NodeProfileID(ctx context.Context, q db.Querier, nodeID string) (string, error) {
	if nodeID == "" {
		return "", nil
	}
	var id *string
	err := q.QueryRow(ctx, `SELECT p.id::text FROM nodes n
		JOIN config_profiles p ON p.id = coalesce(n.profile_id, (SELECT id FROM config_profiles WHERE name = 'default'))
		WHERE n.id = $1`, nodeID).Scan(&id)
	if db.IsNotFound(err) || (err == nil && id == nil) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return *id, nil
}

// serveCDB streams the current CDB; ServeContent handles Range and If-None-Match.
func (s *Service) serveCDB(w http.ResponseWriter, r *http.Request) {
	// The agent authenticates as one node; serve the CDB its profile should run, falling
	// back to the global build (SPEC §7.1). A ?profile_id= override lets an operator (or a
	// node pinned to another profile) fetch a specific build; empty means global, which only
	// presence (not the value) can tell apart from no override.
	profileID, override, err := profileParam(r)
	if err != nil {
		httpx.BadRequest(w, err.Error())
		return
	}
	if !override {
		if profileID, err = NodeProfileID(r.Context(), s.d.Pool, app.NodeIDFrom(r.Context())); err != nil {
			httpx.WriteDBError(w, r, err)
			return
		}
	}
	b, err := Current(r.Context(), s.d.Pool, profileID)
	if err == nil && b == nil && profileID != "" {
		b, err = Current(r.Context(), s.d.Pool, "") // fall back to the global build
	}
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if b == nil {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "no blocklist build yet")
		return
	}
	f, err := os.Open(s.artifact(b.SHA256))
	if err != nil {
		s.d.Log.Error("blocklist artifact missing", "sha256", b.SHA256, "err", err)
		httpx.WriteError(w, http.StatusNotFound, "not_found", "blocklist artifact missing")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+b.SHA256+`"`)
	w.Header().Set("X-Dnsjos-Sha256", b.SHA256)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", st.ModTime(), f)
}
