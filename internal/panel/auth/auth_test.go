package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/panel/auth"
	"github.com/billyriantono/dnsjos/internal/panel/config"
	"github.com/billyriantono/dnsjos/internal/panel/db/dbtest"
	"github.com/billyriantono/dnsjos/internal/panel/jobs"
	"github.com/billyriantono/dnsjos/internal/panel/server"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type client struct {
	t      *testing.T
	c      *http.Client
	url    string
	bearer string
}

func (c *client) do(method, path string, body any, csrf bool) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.url+path, rd)
	if csrf {
		req.Header.Set("X-Requested-With", "dnsjos")
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (c *client) expect(want int, method, path string, body any) []byte {
	c.t.Helper()
	got, b := c.do(method, path, body, true)
	if got != want {
		c.t.Fatalf("%s %s: status %d, want %d: %s", method, path, got, want, b)
	}
	return b
}

func newClient(t *testing.T, url string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, c: &http.Client{Jar: jar}, url: url}
}

func TestAuthFlow(t *testing.T) {
	pool := dbtest.New(t, "auth")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &app.Deps{
		Pool: pool, Log: log, Live: app.NewLiveStore(), Jobs: jobs.New(ctx, log),
		Settings: app.NewSettings(pool, "http://127.0.0.1:8080"),
		Cfg:      config.Config{BootstrapAdminEmail: "admin@example.com", BootstrapAdminPassword: "correct-horse"},
	}
	if err := d.Settings.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if err := auth.Bootstrap(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := auth.Bootstrap(ctx, d); err != nil { // idempotent
		t.Fatal(err)
	}
	if err := server.EnsureDefaultProfile(ctx, d); err != nil {
		t.Fatal(err)
	}
	var published bool
	if err := pool.QueryRow(ctx, `SELECT published FROM config_versions v JOIN config_profiles p ON p.id = v.profile_id
		WHERE p.name = 'default' AND v.version = 1`).Scan(&published); err != nil || !published {
		t.Fatalf("default profile v1: %v %v", published, err)
	}

	ts := httptest.NewServer(server.Handler(d))
	defer ts.Close()
	admin := newClient(t, ts.URL)

	admin.expect(401, "GET", "/api/v1/auth/me", nil)
	if code, _ := admin.do("POST", "/api/v1/auth/login", api.LoginRequest{Email: "admin@example.com", Password: "correct-horse"}, false); code != 403 {
		t.Fatalf("login without CSRF header: %d", code)
	}
	admin.expect(401, "POST", "/api/v1/auth/login", api.LoginRequest{Email: "admin@example.com", Password: "wrong-password"})
	admin.expect(401, "POST", "/api/v1/auth/login", api.LoginRequest{Email: "nobody@example.com", Password: "wrong-password"})
	var sess api.Session
	json.Unmarshal(admin.expect(200, "POST", "/api/v1/auth/login", api.LoginRequest{Email: "ADMIN@example.com", Password: "correct-horse"}), &sess)
	if sess.User.Role != "admin" || sess.User.LastLoginAt == nil || sess.User.ID == "" {
		t.Fatalf("login response: %+v", sess)
	}
	json.Unmarshal(admin.expect(200, "GET", "/api/v1/auth/me", nil), &sess)
	if sess.User.Email != "admin@example.com" || sess.ExpiresAt.IsZero() {
		t.Fatalf("me: %+v", sess)
	}
	me := sess.User.ID

	// users CRUD
	var viewer api.User
	json.Unmarshal(admin.expect(201, "POST", "/api/v1/users", api.UserCreate{Email: "viewer@example.com", Password: "viewer-pass", Role: "viewer"}), &viewer)
	admin.expect(409, "POST", "/api/v1/users", api.UserCreate{Email: "viewer@example.com", Password: "viewer-pass"})
	admin.expect(422, "POST", "/api/v1/users", api.UserCreate{Email: "x@example.com", Password: "short"})
	var users api.List[api.User]
	json.Unmarshal(admin.expect(200, "GET", "/api/v1/users", nil), &users)
	if users.Total != 2 {
		t.Fatalf("users: %+v", users)
	}
	yes, viewerRole := true, "viewer"
	admin.expect(400, "DELETE", "/api/v1/users/"+me, nil)
	admin.expect(400, "PATCH", "/api/v1/users/"+me, api.UserPatch{Disabled: &yes})
	admin.expect(409, "PATCH", "/api/v1/users/"+me, api.UserPatch{Role: &viewerRole})
	admin.expect(404, "PATCH", "/api/v1/users/not-a-uuid", api.UserPatch{Role: &viewerRole})

	// viewer: read-only
	v := newClient(t, ts.URL)
	v.expect(200, "POST", "/api/v1/auth/login", api.LoginRequest{Email: "viewer@example.com", Password: "viewer-pass"})
	v.expect(403, "GET", "/api/v1/users", nil)
	v.expect(200, "GET", "/api/v1/settings", nil)
	v.expect(403, "PUT", "/api/v1/settings", map[string]int{"metrics_retention_days": 10})
	v.expect(403, "PATCH", "/api/v1/auth/password", api.PasswordChange{Current: "nope-nope", New: "viewer-pass-2"})
	v.expect(422, "PATCH", "/api/v1/auth/password", api.PasswordChange{Current: "viewer-pass", New: "short"})
	v.expect(204, "PATCH", "/api/v1/auth/password", api.PasswordChange{Current: "viewer-pass", New: "viewer-pass-2"})
	short := "1234567"
	admin.expect(422, "PATCH", "/api/v1/users/"+viewer.ID, api.UserPatch{Password: &short})

	// disabling a user kills their sessions
	admin.expect(200, "PATCH", "/api/v1/users/"+viewer.ID, api.UserPatch{Disabled: &yes})
	v.expect(401, "GET", "/api/v1/auth/me", nil)

	// settings
	var s api.Settings
	json.Unmarshal(admin.expect(200, "PUT", "/api/v1/settings", map[string]any{"metrics_retention_days": 10, "public_url": "https://dns.example.com/"}), &s)
	if s.MetricsRetentionDays != 10 || s.BlockedRetentionDays != 800 || s.PublicURL != "https://dns.example.com" || d.Settings.PublicURL() != "https://dns.example.com" {
		t.Fatalf("settings: %+v", s)
	}
	admin.expect(400, "PUT", "/api/v1/settings", map[string]any{"agent_poll_interval_s": 1})

	var entries api.List[api.AuditEntry]
	json.Unmarshal(admin.expect(200, "GET", "/api/v1/audit?limit=100", nil), &entries)
	actions := map[string]bool{}
	for _, e := range entries.Items {
		actions[e.Action] = true
	}
	for _, a := range []string{"user.bootstrap", "auth.login", "auth.login_failed", "user.create", "user.update", "settings.update", "auth.password_change"} {
		if !actions[a] {
			t.Errorf("audit missing %s: %v", a, actions)
		}
	}

	admin.expect(204, "DELETE", "/api/v1/users/"+viewer.ID, nil)
	admin.expect(404, "DELETE", "/api/v1/users/"+viewer.ID, nil)

	// misc routes
	admin.expect(200, "GET", "/healthz", nil)
	admin.expect(200, "GET", "/readyz", nil)
	admin.expect(404, "GET", "/api/v1/does-not-exist", nil)
	if b := admin.expect(200, "GET", "/nodes/123", nil); !strings.Contains(string(b), "<html") {
		t.Fatalf("SPA fallback: %s", b)
	}

	admin.expect(204, "POST", "/api/v1/auth/logout", nil)
	admin.expect(401, "GET", "/api/v1/auth/me", nil)

	// 10 attempts per minute per IP (several were used above)
	var code int
	for range 11 {
		code, _ = admin.do("POST", "/api/v1/auth/login", api.LoginRequest{Email: "admin@example.com", Password: "wrong-password"}, true)
	}
	if code != 429 {
		t.Fatalf("rate limit: last status %d", code)
	}
}

func TestAPITokens(t *testing.T) {
	pool := dbtest.New(t, "auth_tokens")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &app.Deps{
		Pool: pool, Log: log, Live: app.NewLiveStore(), Jobs: jobs.New(ctx, log),
		Settings: app.NewSettings(pool, "http://127.0.0.1:8080"),
		Cfg:      config.Config{BootstrapAdminEmail: "admin@example.com", BootstrapAdminPassword: "correct-horse"},
	}
	if err := auth.Bootstrap(ctx, d); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.Handler(d))
	defer ts.Close()
	admin := newClient(t, ts.URL)
	admin.expect(200, "POST", "/api/v1/auth/login", api.LoginRequest{Email: "admin@example.com", Password: "correct-horse"})

	admin.expect(400, "POST", "/api/v1/api-tokens", api.APITokenCreate{Name: " "})
	admin.expect(400, "POST", "/api/v1/api-tokens", api.APITokenCreate{Name: "x", ExpiresInDays: -1})
	var tok api.APITokenCreated
	json.Unmarshal(admin.expect(201, "POST", "/api/v1/api-tokens", api.APITokenCreate{Name: "grafana", ExpiresInDays: 30}), &tok)
	if !strings.HasPrefix(tok.Token, "djt_") || len(tok.Token) != 4+43 || tok.Prefix != tok.Token[:8] ||
		tok.ExpiresAt == nil || tok.CreatedByEmail != "admin@example.com" || tok.Revoked || tok.LastUsedAt != nil {
		t.Fatalf("created: %+v", tok)
	}

	g := &client{t: t, c: http.DefaultClient, url: ts.URL, bearer: tok.Token}
	g.expect(200, "GET", "/api/v1/reports/blocked", nil)
	g.expect(200, "GET", "/api/v1/overview", nil)
	var me api.Session
	json.Unmarshal(g.expect(200, "GET", "/api/v1/auth/me", nil), &me)
	if me.User.Role != api.RoleViewer || me.User.ID != "" || me.User.Email != "" {
		t.Fatalf("token principal: %+v", me.User)
	}
	g.expect(401, "GET", "/api/v1/users", nil)                                 // admin route
	g.expect(401, "GET", "/api/v1/api-tokens", nil)                            // admin route
	g.expect(401, "POST", "/api/v1/blocklist/builds", nil)                     // mutating
	g.expect(401, "POST", "/api/v1/api-tokens", api.APITokenCreate{Name: "x"}) // mutating
	g.expect(401, "PATCH", "/api/v1/auth/password", api.PasswordChange{})      // session route
	g.expect(401, "GET", "/agent/v1/config", nil)                              // agent route
	for _, bad := range []string{"djt_nope", "not-a-token", tok.Token + "x"} {
		(&client{t: t, c: http.DefaultClient, url: ts.URL, bearer: bad}).expect(401, "GET", "/api/v1/overview", nil)
	}

	var list api.List[api.APIToken]
	b := admin.expect(200, "GET", "/api/v1/api-tokens", nil)
	json.Unmarshal(b, &list)
	if strings.Contains(string(b), tok.Token) || strings.Contains(string(b), "token_hash") || list.Total != 1 || list.Items[0].LastUsedAt == nil {
		t.Fatalf("list: %s", b)
	}

	// expired
	var exp api.APITokenCreated
	json.Unmarshal(admin.expect(201, "POST", "/api/v1/api-tokens", api.APITokenCreate{Name: "old"}), &exp)
	eg := &client{t: t, c: http.DefaultClient, url: ts.URL, bearer: exp.Token}
	eg.expect(200, "GET", "/api/v1/overview", nil)
	if _, err := pool.Exec(ctx, "UPDATE api_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1", exp.ID); err != nil {
		t.Fatal(err)
	}
	eg.expect(401, "GET", "/api/v1/overview", nil)

	// a disabled creator takes their tokens down with them (and back when re-enabled)
	for _, disabled := range []bool{true, false} {
		if _, err := pool.Exec(ctx, "UPDATE users SET disabled = $1 WHERE email = 'admin@example.com'", disabled); err != nil {
			t.Fatal(err)
		}
		want := 200
		if disabled {
			want = 401
		}
		g.expect(want, "GET", "/api/v1/overview", nil)
	}
	admin.expect(200, "POST", "/api/v1/auth/login", api.LoginRequest{Email: "admin@example.com", Password: "correct-horse"})

	// revoked
	admin.expect(204, "DELETE", "/api/v1/api-tokens/"+tok.ID, nil)
	admin.expect(404, "DELETE", "/api/v1/api-tokens/"+tok.ID, nil)
	admin.expect(404, "DELETE", "/api/v1/api-tokens/not-a-uuid", nil)
	g.expect(401, "GET", "/api/v1/reports/blocked", nil)
	json.Unmarshal(admin.expect(200, "GET", "/api/v1/api-tokens", nil), &list)
	if list.Total != 2 || list.Items[1].ID != tok.ID || !list.Items[1].Revoked {
		t.Fatalf("list after revoke: %+v", list)
	}

	var entries api.List[api.AuditEntry]
	b = admin.expect(200, "GET", "/api/v1/audit", nil)
	json.Unmarshal(b, &entries)
	actions := map[string]int{}
	for _, e := range entries.Items {
		actions[e.Action]++
	}
	if actions["api_token.create"] != 2 || actions["api_token.revoke"] != 1 || strings.Contains(string(b), tok.Token) {
		t.Fatalf("audit: %v", actions)
	}
}
