package blocklist

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/colinmarc/cdb"
	"github.com/jackc/pgx/v5"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/audit"
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
}

func (s *Service) routes(r *app.Router) {
	r.Viewer("GET /api/v1/blocklist/sources", s.listSources)
	r.Admin("POST /api/v1/blocklist/sources", s.createSource)
	r.Admin("PATCH /api/v1/blocklist/sources/{id}", s.patchSource)
	r.Admin("DELETE /api/v1/blocklist/sources/{id}", s.deleteSource)
	r.Viewer("GET /api/v1/blocklist/builds", s.listBuilds)
	r.Admin("POST /api/v1/blocklist/builds", s.startBuild)
	r.Viewer("GET /api/v1/blocklist/current", s.current)
	r.Viewer("GET /api/v1/blocklist/lookup", s.lookup)
	r.Agent("GET /agent/v1/blocklist", s.serveCDB)
}

const sourceCols = `id, name, kind, url, content, enabled, etag, last_modified, last_fetch_at,
	last_status, entries, created_at, updated_at`

func scanSource(row pgx.Row) (api.BlocklistSource, error) {
	var x api.BlocklistSource
	err := row.Scan(&x.ID, &x.Name, &x.Kind, &x.URL, &x.Content, &x.Enabled, &x.ETag, &x.LastModified,
		&x.LastFetchAt, &x.LastStatus, &x.Entries, &x.CreatedAt, &x.UpdatedAt)
	return x, err
}

var kinds = []string{"trustpositif_domains", "trustpositif_ips", "url_domains", "url_ips",
	"manual_domains", "manual_ips", "whitelist"}

func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func (s *Service) listSources(w http.ResponseWriter, r *http.Request) {
	rows, _ := s.d.Pool.Query(r.Context(), "SELECT "+sourceCols+" FROM blocklist_sources ORDER BY created_at, name")
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
	src, err := scanSource(s.d.Pool.QueryRow(r.Context(), `INSERT INTO blocklist_sources (name, kind, url, content, enabled)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+sourceCols, req.Name, req.Kind, req.URL, req.Content, enabled))
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	_ = audit.Record(r, s.d.Pool, "blocklist.source.create", "blocklist_source", src.ID,
		map[string]any{"name": src.Name, "kind": src.Kind, "url": src.URL})
	httpx.WriteJSON(w, http.StatusCreated, src)
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
	if req.URL != nil {
		*req.URL = strings.TrimSpace(*req.URL)
		if !isURLKind(kind) || !validURL(*req.URL) {
			httpx.BadRequest(w, "url must be an http(s) URL on a URL source")
			return
		}
	}
	// A new URL invalidates the cached validators.
	src, err := scanSource(s.d.Pool.QueryRow(r.Context(), `UPDATE blocklist_sources SET
		name = coalesce($2, name), content = coalesce($4, content), enabled = coalesce($5, enabled),
		etag = CASE WHEN $3::text <> url THEN '' ELSE etag END,
		last_modified = CASE WHEN $3::text <> url THEN '' ELSE last_modified END,
		url = coalesce($3, url), updated_at = now()
		WHERE id = $1 RETURNING `+sourceCols, id, req.Name, req.URL, req.Content, req.Enabled))
	if err != nil {
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
	rows, _ := s.d.Pool.Query(r.Context(), "SELECT "+buildCols+" FROM blocklist_builds ORDER BY id DESC LIMIT $1", limit)
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.BlocklistBuild, error) { return scanBuild(row) })
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if items == nil {
		items = []api.BlocklistBuild{}
	}
	var total int
	if err := s.d.Pool.QueryRow(r.Context(), "SELECT count(*) FROM blocklist_builds").Scan(&total); err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.List[api.BlocklistBuild]{Items: items, Total: total})
}

func (s *Service) startBuild(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "true"
	b, err := s.Start("manual", force)
	if errors.Is(err, errBusy) {
		httpx.WriteError(w, http.StatusConflict, "conflict", err.Error())
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	_ = audit.Record(r, s.d.Pool, "blocklist.build", "blocklist_build", strconv.FormatInt(b.ID, 10), map[string]bool{"force": force})
	httpx.WriteJSON(w, http.StatusAccepted, b)
}

func (s *Service) current(w http.ResponseWriter, r *http.Request) {
	b, err := Current(r.Context(), s.d.Pool)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, b) // JSON null when there is no build yet
}

func (s *Service) lookup(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("name"))
	if q == "" {
		httpx.BadRequest(w, "name is required")
		return
	}
	b, err := Current(r.Context(), s.d.Pool)
	if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	if b == nil {
		httpx.WriteJSON(w, http.StatusOK, api.BlocklistLookup{Name: q})
		return
	}
	res, err := lookupCDB(s.artifact(b.SHA256), q)
	if errors.Is(err, errBadName) {
		httpx.BadRequest(w, err.Error())
		return
	} else if err != nil {
		httpx.WriteDBError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
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

// serveCDB streams the current CDB; ServeContent handles Range and If-None-Match.
func (s *Service) serveCDB(w http.ResponseWriter, r *http.Request) {
	b, err := Current(r.Context(), s.d.Pool)
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
