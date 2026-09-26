package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/billyriantono/dnsjos/internal/panel/app"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func brandServer(t *testing.T) (*app.Router, string) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"login-logo.png": "png", "login-bg.jpg": "jpg", "favicon.ico": "ico", "icon-192.png": "i192",
		"secret.txt": "nope", // present but not allowlisted
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(filepath.Dir(dir), "outside.png"), []byte("x"), 0o644)
	os.Mkdir(filepath.Join(dir, "navbar-dark.png"), 0o755) // a directory is not an asset
	r := app.NewRouter(&app.Deps{})
	registerBranding(r, brand{"Acme <DNS>", "Fast", dir})
	r.Public("/", spaHandler("Acme <DNS>"))
	return r, dir
}

func fetch(r http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestBrandingInfo(t *testing.T) {
	r, _ := brandServer(t)
	rec := fetch(r, "/api/v1/branding")
	var b api.Branding
	if err := json.Unmarshal(rec.Body.Bytes(), &b); rec.Code != 200 || err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if b.Name != "Acme <DNS>" || b.Tagline != "Fast" || len(b.Assets) != len(api.BrandingAssets) {
		t.Fatalf("%+v", b)
	}
	for key, want := range map[string]string{"login_logo": "/branding/login-logo.png?v=", "login_bg": "/branding/login-bg.jpg?v=",
		"favicon_ico": "/branding/favicon.ico?v=", "icon_192": "/branding/icon-192.png?v="} {
		if u := b.Assets[key]; u == nil || !strings.HasPrefix(*u, want) {
			t.Errorf("%s = %v, want %s…", key, u, want)
		}
	}
	for _, key := range []string{"navbar_dark", "navbar_light", "login_bg_mobile", "cloud", "icon_512", "apple_touch"} {
		if u, ok := b.Assets[key]; !ok || u != nil {
			t.Errorf("%s = %v, want null", key, u)
		}
	}
}

func TestBrandingFiles(t *testing.T) {
	r, dir := brandServer(t)
	for path, want := range map[string]string{
		"/branding/login-logo.png": "image/png", "/branding/login-bg.jpg": "image/jpeg", "/branding/favicon.ico": "image/x-icon",
	} {
		rec := fetch(r, path)
		if rec.Code != 200 || rec.Header().Get("Content-Type") != want ||
			rec.Header().Get("Cache-Control") != "public, max-age=86400" {
			t.Errorf("%s: %d %v", path, rec.Code, rec.Header())
		}
	}
	for _, path := range []string{
		"/branding/secret.txt", "/branding/cloud.webp", "/branding/navbar-dark.png", "/branding/",
		"/branding/..%2Foutside.png", "/branding/x/../../outside.png", "/branding/%2e%2e/outside.png",
		"/branding/sub/login-logo.png",
	} {
		if rec := fetch(r, path); rec.Code == 200 {
			t.Errorf("%s: served %q", path, rec.Body)
		}
	}
	// favicon.ico: the brand file, else the generated default.
	if rec := fetch(r, "/favicon.ico"); rec.Body.String() != "ico" {
		t.Errorf("favicon: %q", rec.Body)
	}
	os.Remove(filepath.Join(dir, "favicon.ico"))
	if rec := fetch(r, "/favicon.ico"); rec.Code != 200 || rec.Header().Get("Content-Type") != "image/x-icon" ||
		!strings.HasPrefix(rec.Body.String(), "\x00\x00\x01\x00\x01\x00") || !strings.Contains(rec.Body.String(), "\x89PNG") {
		t.Errorf("default favicon: %d %q", rec.Code, rec.Body.String()[:min(16, rec.Body.Len())])
	}
}

func TestManifestAndTitle(t *testing.T) {
	r, dir := brandServer(t)
	var m struct {
		Name  string
		Icons []struct{ Src, Sizes, Type string }
	}
	rec := fetch(r, "/manifest.webmanifest")
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || rec.Header().Get("Content-Type") != "application/manifest+json" ||
		m.Name != "Acme <DNS>" || len(m.Icons) != 1 || !strings.HasPrefix(m.Icons[0].Src, "/branding/icon-192.png?v=") {
		t.Fatalf("%s %+v", rec.Body, m)
	}
	os.Remove(filepath.Join(dir, "icon-192.png"))
	json.Unmarshal(fetch(r, "/manifest.webmanifest").Body.Bytes(), &m)
	if len(m.Icons) != 1 || m.Icons[0].Src != "/favicon.ico" {
		t.Fatalf("fallback icons: %+v", m.Icons)
	}
	for _, path := range []string{"/", "/nodes/123"} {
		if body := fetch(r, path).Body.String(); !strings.Contains(body, "<title>Acme &lt;DNS&gt;</title>") || strings.Contains(body, "<title>DnsJos") {
			t.Errorf("%s: %s", path, body)
		}
	}
}
