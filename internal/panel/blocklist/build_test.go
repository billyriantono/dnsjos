package blocklist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/config"
	"github.com/billyriantono/dnsjos/internal/panel/db"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/panel/jobs"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// fakeList serves a body with an ETag and honours If-None-Match.
type fakeList struct {
	mu         sync.Mutex
	etag, body string
	hits, n304 int
}

func (f *fakeList) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits++
	if r.Header.Get("User-Agent") != userAgent {
		http.Error(w, "bot", http.StatusForbidden)
		return
	}
	if r.Header.Get("If-None-Match") == f.etag {
		f.n304++
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", f.etag)
	io.WriteString(w, f.body)
}

func (f *fakeList) set(etag, body string) {
	f.mu.Lock()
	f.etag, f.body = etag, body
	f.mu.Unlock()
}

func TestBuildFlow(t *testing.T) {
	pool := dbtest.New(t, "blocklist")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &app.Deps{Pool: pool, Log: log, Live: app.NewLiveStore(), Jobs: jobs.New(ctx, log),
		Settings: app.NewSettings(pool, "http://x"), Cfg: config.Config{DataDir: t.TempDir()}}
	if err := d.Settings.Load(ctx); err != nil {
		t.Fatal(err)
	}
	defer func(v int) { minDomains = v }(minDomains)
	minDomains = 2

	domains := &fakeList{etag: `"d1"`, body: "a.com\nb.com\nc.com\n"}
	ips := &fakeList{etag: `"i1"`, body: "1.2.3.4\n"}
	mux := http.NewServeMux()
	mux.Handle("/domains", domains)
	mux.Handle("/ips", ips)
	up := httptest.NewServer(mux)
	defer up.Close()
	exec(t, pool, `UPDATE blocklist_sources SET url = $1 || '/domains' WHERE kind = 'trustpositif_domains'`, up.URL)
	exec(t, pool, `UPDATE blocklist_sources SET url = $1 || '/ips' WHERE kind = 'trustpositif_ips'`, up.URL)

	s := newService(d)
	build := func(want string) api.BlocklistBuild {
		t.Helper()
		b, err := s.insert(ctx, "manual")
		if err != nil {
			t.Fatal(err)
		}
		b, err = s.execute(ctx, b.ID, false)
		if b.Status != want {
			t.Fatalf("status %s (err %v), want %s: %+v", b.Status, err, want, b)
		}
		return b
	}
	blocked := func(q string) bool {
		t.Helper()
		cur, err := Current(ctx, pool)
		if err != nil || cur == nil {
			t.Fatal("no current build", err)
		}
		res, err := lookupCDB(s.artifact(cur.SHA256), q)
		if err != nil {
			t.Fatal(err)
		}
		return res.Blocked
	}

	b1 := build("ok")
	if b1.Domains != 3 || b1.IPs != 1 {
		t.Fatalf("build 1: %+v", b1)
	}

	// Production bug regression: domains answers 304, ips changes → both must be in the CDB.
	ips.set(`"i2"`, "5.6.7.8\n")
	b2 := build("ok")
	if domains.n304 != 1 || b2.Domains != 3 || b2.IPs != 1 || !blocked("www.a.com") || !blocked("5.6.7.8") || blocked("1.2.3.4") {
		t.Fatalf("build 2 dropped a 304 source: %+v (304s %d)", b2, domains.n304)
	}

	build("skipped") // everything 304, nothing else changed

	// force: full re-download (no conditional request) and a rebuild despite unchanged inputs.
	hits, n304 := domains.hits, domains.n304
	fb, err := s.insert(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if fb, err = s.execute(ctx, fb.ID, true); fb.Status != "ok" || domains.hits != hits+1 || domains.n304 != n304 {
		t.Fatalf("forced build: %+v err %v (hits %d→%d, 304s %d→%d)", fb, err, hits, domains.hits, n304, domains.n304)
	}
	var st string
	if err := pool.QueryRow(ctx, "SELECT last_status FROM blocklist_sources WHERE kind = 'trustpositif_domains'").Scan(&st); err != nil ||
		!strings.HasPrefix(st, "ok: ") || !strings.Contains(st, "MB/s, 1 stream") {
		t.Fatalf("download timing missing from status: %q %v", st, err)
	}

	exec(t, pool, `INSERT INTO blocklist_sources (name, kind, content) VALUES ('wl', 'whitelist', 'b.com')`)
	if b := build("ok"); b.Domains != 2 || b.Whitelisted != 1 || blocked("x.b.com") || !blocked("c.com") {
		t.Fatalf("whitelist build: %+v", b)
	}

	minDomains = 10 // sanity floor: failed, previous build stays current
	cur, _ := Current(ctx, pool)
	if b := build("failed"); b.Error == "" {
		t.Fatal("floor failure without error")
	}
	if now, _ := Current(ctx, pool); now.ID != cur.ID {
		t.Fatal("failed build became current")
	}
	minDomains = 2

	exec(t, pool, `INSERT INTO blocklist_sources (name, kind, content) VALUES ('m', 'manual_domains', 'd.com')`)
	build("ok")
	if files, _ := filepath.Glob(filepath.Join(s.dir, "*.cdb")); len(files) != keepBuilds {
		t.Fatalf("kept %d artifacts, want %d: %v", len(files), keepBuilds, files)
	}
	var entries int
	pool.QueryRow(ctx, "SELECT entries FROM blocklist_sources WHERE kind = 'trustpositif_domains'").Scan(&entries)
	if entries != 2 {
		t.Fatalf("source entries = %d", entries)
	}

	// Single flight: a manual build while one runs is refused.
	s.mu.Lock()
	if _, err := s.Start("manual", false); err != errBusy {
		t.Fatalf("Start while busy: %v", err)
	}
	s.mu.Unlock()
	b, err := s.Start("manual", false)
	if err != nil || b.Status != "running" {
		t.Fatalf("Start: %+v %v", b, err)
	}
	s.mu.Lock() // waits for the async build
	s.mu.Unlock()
	var status string
	pool.QueryRow(ctx, "SELECT status FROM blocklist_builds WHERE id = $1", b.ID).Scan(&status)
	if status != "skipped" {
		t.Fatalf("async build status %s", status)
	}

	// The tick respects the interval: a build just ran, so nothing happens.
	var before, after int
	pool.QueryRow(ctx, "SELECT count(*) FROM blocklist_builds").Scan(&before)
	if err := s.tick(ctx); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, "SELECT count(*) FROM blocklist_builds").Scan(&after)
	if before != after {
		t.Fatal("tick built inside the interval")
	}

	testServeCDB(t, d, s)
	testAPI(t, d, s)
	testAllowlist(t, d, s)
}

func testServeCDB(t *testing.T, d *app.Deps, s *Service) {
	ctx := context.Background()
	token := app.NewToken()
	exec(t, d.Pool, "INSERT INTO nodes (name, token_hash) VALUES ('n1', $1)", app.HashToken(token))
	r := app.NewRouter(d)
	s.routes(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	cur, _ := Current(ctx, d.Pool)

	get := func(hdr map[string]string) *http.Response {
		req, _ := http.NewRequest("GET", srv.URL+"/agent/v1/blocklist", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	if resp := get(nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no bearer: %d", resp.StatusCode)
	}
	auth := "Bearer " + token
	resp := get(map[string]string{"Authorization": auth})
	body, _ := io.ReadAll(resp.Body)
	sum := sha256.Sum256(body)
	if resp.StatusCode != 200 || resp.Header.Get("ETag") != `"`+cur.SHA256+`"` ||
		resp.Header.Get("X-Dnsjos-Sha256") != cur.SHA256 || hex.EncodeToString(sum[:]) != cur.SHA256 ||
		resp.ContentLength != cur.SizeBytes {
		t.Fatalf("GET: %d %v", resp.StatusCode, resp.Header)
	}
	if resp := get(map[string]string{"Authorization": auth, "If-None-Match": `"` + cur.SHA256 + `"`}); resp.StatusCode != http.StatusNotModified {
		t.Fatalf("If-None-Match: %d", resp.StatusCode)
	}
	if resp := get(map[string]string{"Authorization": auth, "Range": "bytes=10-"}); resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("Range: %d", resp.StatusCode)
	}
}

func exec(t *testing.T, q db.Querier, sql string, args ...any) {
	t.Helper()
	if _, err := q.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func testAPI(t *testing.T, d *app.Deps, s *Service) {
	tok := app.NewToken()
	exec(t, d.Pool, `WITH u AS (INSERT INTO users (email, password_hash, role) VALUES ('a@x', 'x', 'admin') RETURNING id)
		INSERT INTO sessions (id_hash, user_id, expires_at) SELECT $1, id, now() + interval '1 hour' FROM u`, app.HashToken(tok))
	r := app.NewRouter(d)
	s.routes(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	call := func(method, path, body string, want int, out any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: app.SessionCookie, Value: tok})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d, want %d: %s", method, path, resp.StatusCode, want, b)
		}
		if out != nil {
			if err := json.Unmarshal(b, out); err != nil {
				t.Fatal(err)
			}
		}
	}
	call("POST", "/api/v1/blocklist/sources", `{"name":"x","kind":"url_domains","url":"ftp://x"}`, 400, nil)
	call("POST", "/api/v1/blocklist/sources", `{"name":"x","kind":"nope"}`, 400, nil)
	var src api.BlocklistSource
	call("POST", "/api/v1/blocklist/sources", `{"name":"extra","kind":"url_domains","url":"https://example.com/l.txt"}`, 201, &src)
	if !src.Enabled || src.Kind != "url_domains" {
		t.Fatalf("created %+v", src)
	}
	exec(t, d.Pool, "UPDATE blocklist_sources SET etag = 'e' WHERE id = $1", src.ID)
	call("PATCH", "/api/v1/blocklist/sources/"+src.ID, `{"url":"https://example.org/l.txt","enabled":false}`, 200, &src)
	if src.URL != "https://example.org/l.txt" || src.Enabled || src.ETag != "" {
		t.Fatalf("patched %+v", src)
	}
	var list api.List[api.BlocklistSource]
	call("GET", "/api/v1/blocklist/sources", "", 200, &list)
	if list.Total != 5 {
		t.Fatalf("sources total %d", list.Total)
	}
	call("DELETE", "/api/v1/blocklist/sources/"+src.ID, "", 204, nil)
	call("DELETE", "/api/v1/blocklist/sources/"+src.ID, "", 404, nil)

	var builds api.List[api.BlocklistBuild]
	call("GET", "/api/v1/blocklist/builds?limit=2", "", 200, &builds)
	if len(builds.Items) != 2 || builds.Total < 7 || builds.Items[0].ID < builds.Items[1].ID {
		t.Fatalf("builds %+v", builds)
	}
	var cur api.BlocklistBuild
	call("GET", "/api/v1/blocklist/current", "", 200, &cur)
	if cur.Status != "ok" {
		t.Fatalf("current %+v", cur)
	}
	var lk api.BlocklistLookup
	call("GET", "/api/v1/blocklist/lookup?name=WWW.D.com", "", 200, &lk)
	if !lk.Blocked || lk.Match != "d.com" || lk.Name != "www.d.com" {
		t.Fatalf("lookup %+v", lk)
	}
	call("GET", "/api/v1/blocklist/lookup?name=bad%20name", "", 400, nil)

	s.mu.Lock()
	call("POST", "/api/v1/blocklist/builds", "", 409, nil)
	s.mu.Unlock()
	var b api.BlocklistBuild
	call("POST", "/api/v1/blocklist/builds", "", 202, &b)
	s.mu.Lock()
	s.mu.Unlock()
	var audits int
	d.Pool.QueryRow(context.Background(), "SELECT count(*) FROM audit_log WHERE action LIKE 'blocklist.%'").Scan(&audits)
	if audits != 4 {
		t.Fatalf("audit rows %d, want 4", audits)
	}
}
