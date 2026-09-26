package blocklist

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func TestNormalizeAllow(t *testing.T) {
	for _, tc := range []struct{ kind, in, want string }{
		{"domain", " CDN.Example.COM. ", "cdn.example.com"},
		{"domain", "https://www.example.com/x", "www.example.com"},
		{"domain", "com", ""},
		{"domain", "192.0.2.1", ""},
		{"domain", "bad name", ""},
		{"ip", "192.0.2.1", "192.0.2.1"},
		{"ip", "192.0.2.1/32", "192.0.2.1"},
		{"ip", "192.0.2.77/24", "192.0.2.0/24"},
		{"ip", "::ffff:192.0.2.1", "192.0.2.1"},
		{"ip", "2001:DB8::1/48", "2001:db8::/48"},
		{"ip", "0.0.0.0/0", ""},
		{"ip", "2001:db8::/8", ""},
		{"ip", "fe80::1%eth0", ""},
		{"ip", "example.com", ""},
		{"url", "example.com", ""},
	} {
		got, msg := normalizeAllow(tc.kind, tc.in)
		if got != tc.want || (tc.want == "") != (msg != "") {
			t.Errorf("%s %q → %q (%s), want %q", tc.kind, tc.in, got, msg, tc.want)
		}
	}
}

// testAllowlist runs inside TestBuildFlow (shared DB and builds): d.com is a manual
// domain and 5.6.7.8 a TrustPositif IP in the current build.
func testAllowlist(t *testing.T, d *app.Deps, s *Service) {
	ctx := context.Background()
	tok, nodeTok := app.NewToken(), app.NewToken()
	run := func(sql string, args ...any) { t.Helper(); exec(t, d.Pool, sql, args...) }
	run(`WITH u AS (INSERT INTO users (email, password_hash, role) VALUES ('allow@x', 'x', 'admin') RETURNING id)
		INSERT INTO sessions (id_hash, user_id, expires_at) SELECT $1, id, now() + interval '1 hour' FROM u`, app.HashToken(tok))
	run("INSERT INTO nodes (name, token_hash) VALUES ('n-allow', $1)", app.HashToken(nodeTok))
	r := app.NewRouter(d)
	s.routes(r)
	srv := httptest.NewServer(r)
	defer srv.Close()
	do := func(method, path, body string, hdr map[string]string, want int, out any) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: app.SessionCookie, Value: tok})
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s %s: %d, want %d: %s", method, path, body, resp.StatusCode, want, b)
		}
		if out != nil {
			if err := json.Unmarshal(b, out); err != nil {
				t.Fatal(err)
			}
		}
		return resp
	}
	call := func(method, path, body string, want int, out any) { t.Helper(); do(method, path, body, nil, want, out) }
	lookup := func(q string) api.BlocklistLookup {
		t.Helper()
		var lk api.BlocklistLookup
		call("GET", "/api/v1/blocklist/lookup?name="+q, "", 200, &lk)
		return lk
	}

	// Validation → 422.
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	for _, body := range []string{`{"kind":"domain","value":"com"}`, `{"kind":"ip","value":"0.0.0.0/0"}`,
		`{"kind":"url","value":"x.com"}`, `{"kind":"domain","value":"x.com","expires_at":"` + past + `"}`} {
		call("POST", "/api/v1/allowlist", body, 422, nil)
	}

	if lk := lookup("www.d.com"); !lk.Blocked || lk.Allowed {
		t.Fatalf("before allow: %+v", lk)
	}
	var e api.AllowEntry
	call("POST", "/api/v1/allowlist", `{"kind":"domain","value":"D.com.","reason":"shared CDN"}`, 201, &e)
	if e.Value != "d.com" || e.Reason != "shared CDN" || e.CreatedByEmail != "allow@x" || e.ExpiresAt != nil {
		t.Fatalf("created %+v", e)
	}
	call("POST", "/api/v1/allowlist", `{"kind":"domain","value":"d.com"}`, 409, nil)
	// The current build still has d.com: the lookup shows "blocked by list but allowed".
	if lk := lookup("www.d.com"); !lk.Blocked || !lk.Allowed || lk.AllowEntry == nil || lk.AllowEntry.ID != e.ID {
		t.Fatalf("lookup after allow: %+v", lk)
	}
	var ipe api.AllowEntry
	call("POST", "/api/v1/allowlist", `{"kind":"ip","value":"5.6.7.8/32"}`, 201, &ipe)
	if lk := lookup("5.6.7.8"); ipe.Value != "5.6.7.8" || !lk.Allowed {
		t.Fatalf("ip entry %+v lookup %+v", ipe, lk)
	}

	// Expired rows are ignored everywhere and can be re-added.
	run("INSERT INTO allowlist (kind, value, expires_at) VALUES ('domain', 'c.com', now() - interval '1 minute')")
	var list api.List[api.AllowEntry]
	call("GET", "/api/v1/allowlist", "", 200, &list)
	if list.Total != 2 || lookup("c.com").Allowed {
		t.Fatalf("expired entry visible: %+v", list)
	}
	al, err := ActiveAllowlist(ctx, d.Pool)
	if err != nil || strings.Join(al.Domains, ",") != "d.com" || strings.Join(al.IPs, ",") != "5.6.7.8" || al.Version == "" {
		t.Fatalf("active %+v %v", al, err)
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	var ce api.AllowEntry
	call("POST", "/api/v1/allowlist", `{"kind":"domain","value":"c.com","expires_at":"`+future+`"}`, 201, &ce)
	if ce.ExpiresAt == nil || !lookup("x.c.com").Allowed {
		t.Fatalf("re-added %+v", ce)
	}

	// Agent endpoint: ETag = version, 304 on match, new version after a change.
	agent := func(inm string, want int) api.Allowlist {
		t.Helper()
		var out api.Allowlist
		var o any
		if want == 200 {
			o = &out
		}
		resp := do("GET", "/agent/v1/allowlist", "", map[string]string{"Authorization": "Bearer " + nodeTok, "If-None-Match": inm}, want, o)
		if want == 200 && resp.Header.Get("ETag") != `"`+out.Version+`"` {
			t.Fatalf("etag %s version %s", resp.Header.Get("ETag"), out.Version)
		}
		return out
	}
	do("GET", "/agent/v1/allowlist", "", nil, 401, nil)
	a1 := agent("", 200)
	if len(a1.Domains) != 2 || len(a1.IPs) != 1 {
		t.Fatalf("agent allowlist %+v", a1)
	}
	agent(`"`+a1.Version+`"`, 304)
	call("DELETE", "/api/v1/allowlist/"+ce.ID, "", 204, nil)
	call("DELETE", "/api/v1/allowlist/"+ce.ID, "", 404, nil)
	if a2 := agent(`"`+a1.Version+`"`, 200); a2.Version == a1.Version || len(a2.Domains) != 1 {
		t.Fatalf("after delete %+v", a2)
	}

	// Build integration: the allowlist changed the inputs, so a plain build rebuilds and
	// drops d.com (and its subdomains) and 5.6.7.8 from the CDB.
	b, err := s.insert(ctx, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if b, err = s.execute(ctx, b.ID, false); err != nil || b.Status != "ok" {
		t.Fatalf("build %+v %v", b, err)
	}
	for _, q := range []string{"d.com", "www.d.com", "5.6.7.8"} {
		if res, err := lookupCDB(s.artifact(b.SHA256), q); err != nil || res.Blocked {
			t.Fatalf("%s still in the CDB: %+v %v", q, res, err)
		}
	}
	if res, _ := lookupCDB(s.artifact(b.SHA256), "a.com"); !res.Blocked {
		t.Fatal("a.com lost")
	}
	if lk := lookup("www.d.com"); lk.Blocked || !lk.Allowed {
		t.Fatalf("lookup after build %+v", lk)
	}

	// Purge removes expired rows only.
	run("INSERT INTO allowlist (kind, value, expires_at) VALUES ('domain', 'old.example', now() - interval '1 day')")
	if err := s.purgeAllow(ctx); err != nil {
		t.Fatal(err)
	}
	var n, audits int
	d.Pool.QueryRow(ctx, "SELECT count(*) FROM allowlist").Scan(&n)
	d.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action LIKE 'allowlist.%'").Scan(&audits)
	if n != 2 || audits != 4 {
		t.Fatalf("after purge %d rows (want 2), %d audit rows (want 4)", n, audits)
	}
}
