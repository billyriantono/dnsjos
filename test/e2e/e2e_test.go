//go:build e2e

// Real end-to-end test on one machine: panel + Postgres + agent + a real dnsdist.
// See README.md.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/colinmarc/cdb"

	"github.com/billyriantono/dnsjos/internal/agent/dnsdist"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	keys "github.com/billyriantono/dnsjos/internal/shared/cdb"
)

const (
	panelAddr = "127.0.0.1:18080"
	dnsPort   = "15353"
	webAddr   = "127.0.0.1:18083"
	blockV4   = "192.0.2.10"
	blockV6   = "2001:db8::10"
)

func TestEndToEnd(t *testing.T) {
	for _, bin := range []string{"dnsdist", "dig", "createdb", "dropdb", "psql"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s not on PATH", bin)
		}
	}
	tmp := t.TempDir()
	repo, _ := filepath.Abs("../..")
	panelBin, agentBin := filepath.Join(tmp, "dnsjos"), filepath.Join(tmp, "dnsjos-agent")
	run(t, repo, nil, "go", "build", "-o", panelBin, "./cmd/dnsjos")
	run(t, repo, nil, "go", "build", "-o", agentBin, "./cmd/dnsjos-agent")

	// ── panel on a fresh database; the seeded TrustPositif sources are disabled so
	// nothing is fetched from the internet ──
	db := fmt.Sprintf("dnsjos_e2e_%d", os.Getpid())
	run(t, "", nil, "createdb", db)
	t.Cleanup(func() { exec.Command("dropdb", "--if-exists", db).Run() })
	env := []string{
		"DNSJOS_LISTEN=" + panelAddr, "DNSJOS_DATABASE_URL=postgres://" + os.Getenv("USER") + "@127.0.0.1:5432/" + db + "?sslmode=disable",
		"DNSJOS_DATA_DIR=" + filepath.Join(tmp, "panel"), "DNSJOS_PUBLIC_URL=http://" + panelAddr, "DNSJOS_LOG_LEVEL=info",
		"DNSJOS_BOOTSTRAP_ADMIN_EMAIL=admin@example.com", "DNSJOS_BOOTSTRAP_ADMIN_PASSWORD=admin-pass-1",
	}
	run(t, "", env, panelBin, "migrate")
	run(t, "", nil, "psql", "-q", "-d", db, "-c", "UPDATE blocklist_sources SET enabled = false")
	background(t, filepath.Join(tmp, "panel.log"), env, panelBin, "serve")
	p := &panel{t: t, base: "http://" + panelAddr}
	eventually(t, 20*time.Second, "panel healthy", func() (bool, string) {
		return p.call("GET", "/healthz", nil, nil) == 200, ""
	})
	jar, _ := cookiejar.New(nil)
	p.hc = &http.Client{Jar: jar, Timeout: 30 * time.Second}
	p.must(200, "POST", "/api/v1/auth/login", api.LoginRequest{Email: "admin@example.com", Password: "admin-pass-1"}, nil)

	// ── profile: local listeners only, public upstreams ──
	var profiles api.List[api.Profile]
	p.must(200, "GET", "/api/v1/profiles", nil, &profiles)
	def := profiles.Items[slices.IndexFunc(profiles.Items, func(x api.Profile) bool { return x.Name == "default" })].ID
	spec := api.DefaultConfigSpec()
	spec.Listen.Do53 = api.Do53{Enabled: true, Addresses: []string{"127.0.0.1:" + dnsPort}, ReusePortListeners: 1}
	spec.Webserver = api.Webserver{Listen: webAddr, PrometheusACL: []string{"127.0.0.1/32"}}
	spec.Upstreams.Servers = []api.Upstream{
		{Address: "1.1.1.1:53", Weight: 10, Order: 1, Sockets: 2, Name: "cloudflare1"},
		{Address: "8.8.8.8:53", Weight: 10, Order: 1, Sockets: 2, Name: "google1"},
	}
	var ver api.ConfigVersion
	p.must(201, "POST", "/api/v1/profiles/"+def+"/versions", api.VersionCreate{Spec: spec, Comment: "e2e"}, &ver)
	p.must(200, "POST", fmt.Sprintf("/api/v1/profiles/%s/versions/%d/publish", def, ver.Version), nil, nil)

	// ── adoption dry run while the panel has no blocklist build (409 no_blocklist) ──
	t.Run("adopt", func(t *testing.T) { adoptDryRun(t, p, repo, agentBin, filepath.Join(tmp, "adopt"), db) })

	// ── blocklist from a local fake source ──
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/domains.txt":
			io.WriteString(w, "# test list\nblocked.example\npornhub.com\n")
		case "/ips.txt":
			io.WriteString(w, "1.1.1.1\n")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(src.Close)
	p.must(201, "POST", "/api/v1/blocklist/sources", api.BlocklistSourceCreate{Name: "e2e domains", Kind: "url_domains", URL: src.URL + "/domains.txt"}, nil)
	p.must(201, "POST", "/api/v1/blocklist/sources", api.BlocklistSourceCreate{Name: "e2e ips", Kind: "url_ips", URL: src.URL + "/ips.txt"}, nil)
	var build api.BlocklistBuild
	p.must(202, "POST", "/api/v1/blocklist/builds", nil, &build)
	eventually(t, 30*time.Second, "blocklist build ok", func() (bool, string) {
		var builds api.List[api.BlocklistBuild]
		p.must(200, "GET", "/api/v1/blocklist/builds", nil, &builds)
		for _, b := range builds.Items {
			if b.ID == build.ID {
				build = b
			}
		}
		return build.Status == "ok", fmt.Sprintf("%+v", build)
	})
	if build.Domains != 2 || build.IPs != 1 {
		t.Fatalf("build: %+v", build)
	}

	// ── agent: enroll + run in test mode; this harness plays systemd for dnsdist ──
	root := filepath.Join(tmp, "node")
	var tok api.EnrollmentTokenCreated
	p.must(201, "POST", "/api/v1/enrollment-tokens", api.EnrollmentTokenCreate{NodeName: "e2e-node"}, &tok)
	run(t, "", nil, agentBin, "enroll", "--panel", p.base, "--token", tok.Token, "--root", root, "--no-systemd")
	var ac struct {
		NodeID string `json:"node_id"`
	}
	readJSON(t, filepath.Join(root, "etc/dnsjos/agent.json"), &ac)
	conf := filepath.Join(root, "etc/dnsdist/dnsdist.conf")
	superviseDnsdist(t, conf, filepath.Join(tmp, "dnsdist.log"))
	background(t, filepath.Join(tmp, "agent.log"), nil, agentBin, "run", "--root", root, "--no-systemd", "--log-level", "debug",
		"--flush-interval", "5s")

	eventually(t, 60*time.Second, "normal name resolves", func() (bool, string) {
		out := dig("example.com", "A", "+short")
		return out != "" && !strings.Contains(out, "timed out"), out
	})
	if out := dig("blocked.example", "A", "+short"); out != blockV4 {
		t.Errorf("blocked.example A = %q, want %s", out, blockV4)
	}
	if out := dig("www.pornhub.com", "A", "+short"); out != blockV4 {
		t.Errorf("www.pornhub.com A (subdomain) = %q, want %s", out, blockV4)
	}
	if out := dig("blocked.example", "AAAA", "+short"); out != blockV6 {
		t.Errorf("blocked.example AAAA = %q, want %s", out, blockV6)
	}
	if out := dig("blocked.example", "HTTPS"); !strings.Contains(out, "status: NOERROR") || !strings.Contains(out, "ANSWER: 0,") {
		t.Errorf("blocked.example HTTPS must be NODATA:\n%s", out)
	}
	if out := dig("one.one.one.one", "A", "+short"); !strings.Contains(out, blockV4) || strings.Contains(out, "1.1.1.1") {
		t.Errorf("one.one.one.one A = %q: 1.1.1.1 must be rewritten to the blockpage", out)
	}

	// ── heartbeat as the panel sees it ──
	var live api.NodeLive
	eventually(t, 45*time.Second, "heartbeat with traffic, blocks and healthy backends", func() (bool, string) {
		p.must(200, "GET", "/api/v1/nodes/"+ac.NodeID+"/live", nil, &live)
		hb := live.Heartbeat
		if hb == nil {
			return false, "no heartbeat"
		}
		up := len(hb.Backends) == 2
		for _, b := range hb.Backends {
			up = up && b.State == "up"
		}
		return hb.DnsdistRunning && hb.Counters.Queries > 0 && hb.Counters.Blocked >= 3 && up && hb.AppliedConfigVersion > 0,
			fmt.Sprintf("running=%v counters=%+v backends=%+v applied=%d err=%q", hb.DnsdistRunning, hb.Counters, hb.Backends,
				hb.AppliedConfigVersion, hb.ApplyError)
	})
	if live.Heartbeat.BlocklistSHA256 != build.SHA256 || fileSHA(t, filepath.Join(root, "var/lib/dnsjos/blocklist/current.cdb")) != build.SHA256 {
		t.Errorf("CDB sha: heartbeat %s, file %s, build %s", live.Heartbeat.BlocklistSHA256,
			fileSHA(t, filepath.Join(root, "var/lib/dnsjos/blocklist/current.cdb")), build.SHA256)
	}

	// ── console: the agent's client calls cgkReload() ──
	out, err := dnsdist.Console(context.Background(), conf, "cgkReload()")
	if err != nil || !strings.HasPrefix(out, "cgk: ") {
		t.Errorf("cgkReload(): %q %v", out, err)
	}

	// ── dnstap → agent → POST /blocked (flushed every 60 s) → report ──
	day := time.Now().UTC()
	q := fmt.Sprintf("/api/v1/reports/blocked?from=%s&to=%s", day.AddDate(0, 0, -1).Format(time.DateOnly), day.AddDate(0, 0, 1).Format(time.DateOnly))
	eventually(t, 30*time.Second, "blocked report lists blocked.example", func() (bool, string) {
		var rep api.BlockedReport
		p.must(200, "GET", q, nil, &rep)
		return slices.ContainsFunc(rep.TopDomains, func(d api.TopDomain) bool { return d.QName == "blocked.example" }), fmt.Sprintf("%+v", rep)
	})

	// ── a new published version is re-rendered, dnsdist restarted, and served ──
	spec.Blocking.BlockpageIPv4 = "10.9.9.9"
	p.must(201, "POST", "/api/v1/profiles/"+def+"/versions", api.VersionCreate{Spec: spec, Comment: "e2e v2"}, &ver)
	p.must(200, "POST", fmt.Sprintf("/api/v1/profiles/%s/versions/%d/publish", def, ver.Version), nil, nil)
	eventually(t, 60*time.Second, "new blockpage served", func() (bool, string) {
		out := dig("blocked.example", "A", "+short")
		return out == "10.9.9.9", out
	})

	// ── analytics: every answer → second dnstap stream → agent sketches → report ──
	const nx = "nonexistent-e2e.example.invalid"
	for _, name := range []string{"www.example.com", "example.org", "www.example.com", nx} {
		dig(name, "A")
	}
	aq := func(kind string) api.AnalyticsReport {
		var rep api.AnalyticsReport
		p.must(200, "GET", fmt.Sprintf("/api/v1/analytics?from=%s&to=%s&kind=%s&limit=1000",
			day.AddDate(0, 0, -1).Format(time.DateOnly), day.AddDate(0, 0, 1).Format(time.DateOnly), kind), nil, &rep)
		return rep
	}
	has := func(rep api.AnalyticsReport, name string) bool {
		return slices.ContainsFunc(rep.Top, func(e api.AnalyticsTopEntry) bool { return e.Name == name })
	}
	eventually(t, 45*time.Second, "analytics report with the queried names", func() (bool, string) {
		raw, grouped, nxd := aq(api.AnalyticsQueried), aq(api.AnalyticsQueriedGrouped), aq(api.AnalyticsNXDomain)
		ok := raw.Total > 0 && has(raw, "www.example.com") && has(raw, "example.org") && has(raw, nx) &&
			has(grouped, "example.com") && has(grouped, "example.invalid") && has(nxd, nx) && raw.ByRcode["NXDOMAIN"] > 0
		return ok, fmt.Sprintf("raw %+v\ngrouped %+v\nnxdomain %+v", raw, grouped.Top, nxd.Top)
	})
}

// adoptDryRun: a fake root holding a dnsdist_ootb server (reference yml with test
// secrets, old CDB) is enrolled with --adopt and planned; nothing is swapped.
func adoptDryRun(t *testing.T, p *panel, repo, agentBin, root, db string) {
	etc := filepath.Join(root, "etc/dnsdist")
	os.MkdirAll(filepath.Join(etc, "db"), 0o755)
	cert, key := selfSigned(t, filepath.Join(etc, "tls"))
	ref, err := os.ReadFile(filepath.Join(repo, "internal/agent/testdata/dnsdist-ootb.yml"))
	if err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(string(ref), "cert: /etc/dnsdist/tls/cert.pem\n    key: <redacted>", "cert: "+cert+"\n    key: "+key, 2)
	y = strings.Replace(y, "apikey: <redacted>", "apikey: test-api-key", 1)
	y = strings.Replace(y, "password: <redacted>", "password: 'test-web-password'", 1)
	y = strings.Replace(y, "key: <redacted>", `key: "dGVzdC1jb25zb2xlLWtleS0zMi1ieXRlcy0tLS0tLS0="`, 1)
	if strings.Contains(y, "<redacted>") {
		t.Fatalf("unreplaced secret in yml:\n%s", y)
	}
	os.WriteFile(filepath.Join(etc, "dnsdist.yml"), []byte(y), 0o640)
	oldConf, _ := os.ReadFile(filepath.Join(repo, "internal/agent/testdata/dnsdist-ootb.conf"))
	os.WriteFile(filepath.Join(etc, "dnsdist.conf"), oldConf, 0o640)
	w, err := cdb.Create(filepath.Join(etc, "db/blacklist.db"))
	if err != nil {
		t.Fatal(err)
	}
	w.Put(keys.DomainKey("old-blocked.example"), nil)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	oldSHA := fileSHA(t, filepath.Join(etc, "db/blacklist.db"))

	var tok api.EnrollmentTokenCreated
	p.must(201, "POST", "/api/v1/enrollment-tokens", api.EnrollmentTokenCreate{NodeName: "e2e-adopted"}, &tok)
	run(t, "", nil, agentBin, "enroll", "--adopt", "--panel", p.base, "--token", tok.Token, "--root", root, "--no-systemd")

	var sec struct {
		ConsoleKey  string `json:"console_key"`
		WebPassword string `json:"web_password"`
		WebAPIKey   string `json:"web_api_key"`
	}
	readJSON(t, filepath.Join(root, "var/lib/dnsjos/secrets.json"), &sec)
	if sec.ConsoleKey != "dGVzdC1jb25zb2xlLWtleS0zMi1ieXRlcy0tLS0tLS0=" || sec.WebPassword != "test-web-password" || sec.WebAPIKey != "test-api-key" {
		t.Errorf("imported secrets: %+v", sec)
	}
	var ac struct {
		NodeID string `json:"node_id"`
	}
	readJSON(t, filepath.Join(root, "etc/dnsjos/agent.json"), &ac)
	var node api.Node
	p.must(200, "GET", "/api/v1/nodes/"+ac.NodeID, nil, &node)
	var over map[string]any
	json.Unmarshal(node.Overrides, &over)
	wantOver := map[string]any{
		"listen": map[string]any{
			"do53": map[string]any{"addresses": []any{"0.0.0.0:53", "[::]:53"}},
			"doh":  map[string]any{"enabled": true, "addresses": []any{"0.0.0.0:443", "[::]:443"}, "path": "/dns-query"},
			"dot":  map[string]any{"enabled": true, "addresses": []any{"0.0.0.0:853", "[::]:853"}},
			"tls":  map[string]any{"cert_file": cert, "key_file": key},
		},
		"webserver": map[string]any{"listen": "0.0.0.0:8083",
			"prometheus_acl": []any{"127.0.0.1/8", "198.51.100.16/29", "198.51.100.8/29", "198.51.100.24/29", "198.51.100.32/29"}},
	}
	if a, b := jsonString(over), jsonString(wantOver); a != b {
		t.Errorf("stored overrides:\n got %s\nwant %s", a, b)
	}
	if out := run(t, "", nil, "psql", "-qtA", "-d", db, "-c", "SELECT adopted FROM nodes WHERE id = '"+ac.NodeID+"'"); strings.TrimSpace(out) != "t" {
		t.Errorf("nodes.adopted = %q", out)
	}

	plan := run(t, "", nil, agentBin, "plan", "--root", root, "--no-systemd")
	for _, want := range []string{
		"do53:       0.0.0.0:53, [::]:53", "doh:        0.0.0.0:443, [::]:443", "webserver:  0.0.0.0:8083",
		"sha256 " + oldSHA, "check-config: OK", "--- live/dnsdist.conf", "+-- generated by dnsjos, do not edit",
		`-dnsdist_ootb.loadConfig`, "+++ new/dnsjos/blocking.lua",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("plan output lacks %q:\n%s", want, plan)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(etc, "dnsdist.conf")); !bytes.Equal(got, oldConf) {
		t.Error("plan modified the live dnsdist.conf")
	}
	if fileSHA(t, filepath.Join(root, "var/lib/dnsjos/blocklist/current.cdb")) != oldSHA {
		t.Error("old CDB not seeded")
	}
	if out := run(t, "", nil, "psql", "-qtA", "-d", db, "-c", "SELECT seeded_blocklist_sha256 FROM nodes WHERE id = '"+ac.NodeID+"'"); strings.TrimSpace(out) != oldSHA {
		t.Errorf("panel did not record the seeded CDB: %q", out)
	}
	summary, _, _ := strings.Cut(plan, "\n--- ")
	t.Logf("plan summary:\n%s", summary)
}

// ── helpers ──

type panel struct {
	t    *testing.T
	base string
	hc   *http.Client
}

func (p *panel) call(method, path string, in, out any) int {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, p.base+path, body)
	req.Header.Set("X-Requested-With", "dnsjos")
	req.Header.Set("Content-Type", "application/json")
	hc := p.hc
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(b, out); err != nil {
			p.t.Fatalf("%s %s: decode: %v: %s", method, path, err, b)
		}
	}
	if resp.StatusCode >= 300 && out != nil {
		p.t.Logf("%s %s: %d %s", method, path, resp.StatusCode, b)
	}
	return resp.StatusCode
}

func (p *panel) must(want int, method, path string, in, out any) {
	p.t.Helper()
	if code := p.call(method, path, in, out); code != want {
		p.t.Fatalf("%s %s: HTTP %d, want %d", method, path, code, want)
	}
}

func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// background starts a process for the rest of the test; its output goes to logPath
// (printed when the test fails).
func background(t *testing.T, logPath string, env []string, name string, args ...string) {
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
		f.Close()
		dumpOnFailure(t, logPath)
	})
}

// dumpOnFailure prints a log when the test failed or E2E_LOGS is set.
func dumpOnFailure(t *testing.T, p string) {
	if t.Failed() || os.Getenv("E2E_LOGS") != "" {
		b, _ := os.ReadFile(p)
		if len(b) > 20000 {
			b = b[len(b)-20000:]
		}
		t.Logf("── %s ──\n%s", filepath.Base(p), b)
	}
}

// superviseDnsdist plays systemd: it (re)starts dnsdist in the foreground whenever the
// agent-rendered files change and stay unchanged for one poll (the agent writes
// several files per apply).
func superviseDnsdist(t *testing.T, conf, logPath string) {
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(conf)
	var cmd *exec.Cmd
	stop := func() {
		if cmd != nil {
			cmd.Process.Signal(syscall.SIGTERM)
			cmd.Wait()
			cmd = nil
		}
	}
	done, finished := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	go func() {
		defer close(finished)
		var running, last string
		for {
			select {
			case <-done:
				return
			case <-time.After(300 * time.Millisecond):
			}
			h := sha256.New()
			for _, rel := range []string{"dnsdist.conf", "dnsjos/blocking.lua", "dnsjos/abuse.lua", "dnsjos/cgk.lua"} {
				b, _ := os.ReadFile(filepath.Join(dir, rel))
				h.Write(b)
			}
			cur := hex.EncodeToString(h.Sum(nil))
			b, _ := os.ReadFile(conf)
			if cur != last || cur == running || !bytes.HasPrefix(b, []byte("-- generated by dnsjos")) {
				last = cur
				continue
			}
			mu.Lock()
			stop()
			fmt.Fprintf(logf, "── harness: starting dnsdist (%s) ──\n", cur[:12])
			cmd = exec.Command("dnsdist", "--supervised", "--disable-syslog", "-C", conf)
			cmd.Stdout, cmd.Stderr = logf, logf
			if err := cmd.Start(); err != nil {
				fmt.Fprintf(logf, "start: %v\n", err)
				cmd = nil
			}
			running = cur
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		close(done)
		<-finished
		mu.Lock()
		stop()
		mu.Unlock()
		logf.Close()
		dumpOnFailure(t, logPath)
	})
}

func dig(name, qtype string, extra ...string) string {
	args := append([]string{"@127.0.0.1", "-p", dnsPort, "+time=2", "+tries=2", name, qtype}, extra...)
	out, _ := exec.Command("dig", args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func eventually(t *testing.T, timeout time.Duration, what string, f func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, state := f()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s\nlast state: %s", timeout, what, state)
		}
		time.Sleep(time.Second)
	}
}

func readJSON(t *testing.T, p string, v any) {
	b, err := os.ReadFile(p)
	if err == nil {
		err = json.Unmarshal(b, v)
	}
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
}

func jsonString(v any) string { b, _ := json.Marshal(v); return string(b) }

func fileSHA(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return "missing: " + err.Error()
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func selfSigned(t *testing.T, dir string) (cert, key string) {
	os.MkdirAll(dir, 0o755)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dns.example"}, DNSNames: []string{"dns.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	cert, key = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cert, key
}
