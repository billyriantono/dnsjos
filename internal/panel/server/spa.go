package server

import (
	"html"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"

	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/webdist"
)

var titleRE = regexp.MustCompile(`(?is)<title>.*?</title>`)

// spaHandler serves the embedded SPA: real files as-is (hashed /assets/* cached
// forever), any other GET path gets index.html so client-side routes work. index.html
// gets <title> set to the brand name, so the tab is right before any JS runs.
func spaHandler(title string) http.HandlerFunc {
	dist := webdist.FS
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		panic("webdist: index.html missing: " + err.Error())
	}
	index = titleRE.ReplaceAllLiteral(index, []byte("<title>"+html.EscapeString(title)+"</title>"))
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/agent/") {
			httpx.NotFound(w)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			httpx.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		name := strings.TrimPrefix(path.Clean(p), "/")
		if st, err := fs.Stat(dist, name); name != "" && name != "index.html" && err == nil && !st.IsDir() {
			if strings.HasPrefix(name, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFileFS(w, r, dist, name)
			return
		}
		if strings.HasPrefix(name, "assets/") {
			http.NotFound(w, r) // a missing hashed asset must not turn into HTML
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(index)
	}
}
