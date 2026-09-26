package nodes

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/billyriantono/dnsjos/internal/panel/httpx"
	"github.com/billyriantono/dnsjos/internal/panel/install"
)

// installScript serves the node installer with the panel's public URL templated in.
func (s *svc) installScript(w http.ResponseWriter, r *http.Request) {
	pu := strings.TrimRight(s.d.Settings.PublicURL(), "/")
	// The URL lands inside single quotes in sh; refuse anything that could break out.
	if u, err := url.Parse(pu); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		strings.ContainsAny(pu, "'\"`$\\ \t\r\n;&|<>") {
		httpx.WriteError(w, http.StatusInternalServerError, "bad_public_url",
			"the panel public URL is not a valid http(s) URL; fix it in Settings")
		return
	}
	var buf bytes.Buffer
	if err := s.tmpl.Execute(&buf, struct{ PanelURL string }{pu}); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

// download serves bin/dnsjos-agent-linux-<arch>[.sha256] embedded by `make agent panel`.
func (s *svc) download(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("arch")
	arch, isSum := strings.CutSuffix(file, ".sha256")
	if arch != "amd64" && arch != "arm64" {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "unsupported architecture "+arch+" (amd64, arm64)")
		return
	}
	f, err := install.Assets().Open("bin/dnsjos-agent-linux-" + file)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "agent_not_embedded",
			"the dnsjos-agent binary for linux/"+arch+" is not embedded in this panel build; rebuild with `make agent panel`")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	rs, ok := f.(io.ReadSeeker)
	if err != nil || !ok {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "cannot read embedded agent")
		return
	}
	ctype := "application/octet-stream"
	if isSum {
		ctype = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	http.ServeContent(w, r, "", st.ModTime(), rs)
}
