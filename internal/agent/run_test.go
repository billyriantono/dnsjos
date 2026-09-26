package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	dt "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// TestRunTestMode drives enroll + run in test mode against a fake panel.
func TestRunTestMode(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no dnsdist, no systemctl
	cdb := []byte("fake cdb bytes")
	h := sha256.Sum256(cdb)
	sha := hex.EncodeToString(h[:])

	var mu sync.Mutex
	var hbs []api.Heartbeat
	var batches []api.AnalyticsBatch
	cmdSent := false
	fl, _ := net.Listen("tcp", "127.0.0.1:0")
	streamAddr := fl.Addr().String()
	fl.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		var req api.EnrollRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Token != "enroll-tok" || req.Hostname != "node-a" {
			w.WriteHeader(401)
			return
		}
		json.NewEncoder(w).Encode(api.EnrollResponse{NodeID: "n1", NodeToken: "node-tok"})
	})
	auth := func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer node-tok" || r.Header.Get(api.AgentHeader) != "t" {
				w.WriteHeader(401)
				return
			}
			f(w, r)
		}
	}
	mux.HandleFunc("GET /agent/v1/config", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"3"` {
			w.WriteHeader(304)
			return
		}
		spec := api.DefaultConfigSpec()
		spec.CGK.Enabled = false // no network probes in tests
		spec.Analytics.StreamAddr, spec.Analytics.SampleRate = streamAddr, 3
		json.NewEncoder(w).Encode(api.AgentConfig{Version: 3, Spec: spec, Profile: "default", PollIntervalS: 1, HeartbeatIntervalS: 1,
			Blocklist: api.BlocklistRef{SHA256: sha, Size: int64(len(cdb)), URL: "/agent/v1/blocklist"}})
	}))
	mux.HandleFunc("GET /agent/v1/blocklist", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+sha+`"`)
		w.Header().Set(api.Sha256Header, sha)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(cdb))
	}))
	mux.HandleFunc("POST /agent/v1/heartbeat", auth(func(w http.ResponseWriter, r *http.Request) {
		var hb api.Heartbeat
		json.NewDecoder(r.Body).Decode(&hb)
		mu.Lock()
		defer mu.Unlock()
		hbs = append(hbs, hb)
		ack := api.HeartbeatAck{ConfigVersion: 3, BlocklistSHA256: sha}
		if !cmdSent {
			ack.Commands, cmdSent = []api.Command{{ID: 7, Type: api.CmdReapply}}, true
		}
		json.NewEncoder(w).Encode(ack)
	}))
	mux.HandleFunc("POST /agent/v1/analytics", auth(func(w http.ResponseWriter, r *http.Request) {
		var b api.AnalyticsBatch
		json.NewDecoder(r.Body).Decode(&b)
		if b.Validate() != nil {
			w.WriteHeader(422)
			return
		}
		mu.Lock()
		batches = append(batches, b)
		mu.Unlock()
		w.WriteHeader(204)
	}))
	panel := httptest.NewServer(mux)
	defer panel.Close()

	root := t.TempDir()
	o := Options{Root: root, NoSystemd: true, DnsdistWeb: "http://127.0.0.1:1", Version: "t", FlushInterval: 200 * time.Millisecond,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := Enroll(context.Background(), o, panel.URL, "enroll-tok", "node-a", false); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(root, ConfigPath)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("agent.json: %v %v", fi, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- Run(ctx, o) }()
	deadline := time.Now().Add(10 * time.Second)
	var last api.Heartbeat
	acked := false
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		for _, hb := range hbs {
			acked = acked || slices.Contains(hb.AckedCommands, 7)
		}
		if len(hbs) > 0 {
			last = hbs[len(hbs)-1]
		}
		mu.Unlock()
		if acked && last.AppliedConfigVersion == 3 && last.BlocklistSHA256 == sha {
			break
		}
	}
	// analytics: a response on the configured stream reaches the panel ×sample_rate
	sendResponse(t, streamAddr, "Www.Example.COM.")
	var got []api.AnalyticsBatch
	for deadline := time.Now().Add(10 * time.Second); len(got) == 0 && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		mu.Lock()
		got = slices.Clone(batches)
		mu.Unlock()
	}
	if len(got) != 1 || got[0].Total != 3 || got[0].SampleRate != 3 || got[0].ByRcode["NXDOMAIN"] != 3 ||
		len(got[0].Tops[api.AnalyticsNXDomain]) != 1 || got[0].Tops[api.AnalyticsQueriedGrouped][0].Name != "example.com" {
		t.Fatalf("analytics batches: %+v", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !acked || last.AppliedConfigVersion != 3 || last.BlocklistSHA256 != sha || last.ApplyError != "" || last.DnsdistRunning {
		t.Fatalf("last heartbeat: %+v acked=%v", last, acked)
	}

	conf, err := os.ReadFile(filepath.Join(root, DnsdistDir, "dnsdist.conf"))
	if err != nil {
		t.Fatal(err)
	}
	blocking, _ := os.ReadFile(filepath.Join(root, DnsdistDir, "dnsjos/blocking.lua"))
	if !strings.Contains(string(blocking), `newCDBKVStore("`+filepath.Join(root, CDBPath)+`"`) {
		t.Fatalf("blocking.lua must use the root-prefixed CDB path:\n%s", blocking)
	}
	if got, _ := os.ReadFile(filepath.Join(root, CDBPath)); !bytes.Equal(got, cdb) {
		t.Fatal("blocklist not installed")
	}
	s, err := LoadSecrets(filepath.Join(root, SecretsPath))
	if err != nil {
		t.Fatal(err)
	}
	if k, err := base64.StdEncoding.DecodeString(s.ConsoleKey); err != nil || len(k) != 32 {
		t.Fatalf("console key: %q", s.ConsoleKey)
	}
	if !strings.Contains(string(conf), `setKey("`+s.ConsoleKey+`")`) {
		t.Fatal("rendered conf does not use the persisted console key")
	}
	if fi, _ := os.Stat(filepath.Join(root, SecretsPath)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("secrets.json mode %v", fi.Mode().Perm())
	}
}

// TestRunSeedsAdoptedCDB: the panel answers 409 no_blocklist until a heartbeat reports
// a CDB; the agent seeds the adopted server's old CDB, reports it and then applies.
func TestRunSeedsAdoptedCDB(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	root := t.TempDir()
	old := []byte("old cdb")
	h := sha256.Sum256(old)
	oldSHA := hex.EncodeToString(h[:])
	os.MkdirAll(filepath.Join(root, "etc/dnsdist/db"), 0o755)
	os.WriteFile(filepath.Join(root, OOTBCDB), old, 0o644)

	var mu sync.Mutex
	seeded, applied := "", 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agent/v1/config", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if seeded == "" {
			w.WriteHeader(409)
			io.WriteString(w, `{"error":{"code":"no_blocklist","message":"x"}}`)
			return
		}
		spec := api.DefaultConfigSpec()
		spec.CGK.Enabled = false
		json.NewEncoder(w).Encode(api.AgentConfig{Version: 5, Spec: spec, PollIntervalS: 1, HeartbeatIntervalS: 1})
	})
	mux.HandleFunc("POST /agent/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var hb api.Heartbeat
		json.NewDecoder(r.Body).Decode(&hb)
		mu.Lock()
		seeded, applied = hb.BlocklistSHA256, hb.AppliedConfigVersion
		mu.Unlock()
		json.NewEncoder(w).Encode(api.HeartbeatAck{ConfigVersion: 5})
	})
	panel := httptest.NewServer(mux)
	defer panel.Close()
	b, _ := json.Marshal(Config{PanelURL: panel.URL, NodeID: "n1", NodeToken: "tok"})
	writePrivate(filepath.Join(root, ConfigPath), b)

	o := Options{Root: root, NoSystemd: true, DnsdistWeb: "http://127.0.0.1:1", Version: "t",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go Run(ctx, o)
	for ctx.Err() == nil {
		mu.Lock()
		ok := seeded == oldSHA && applied == 5
		mu.Unlock()
		if ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("seeded=%q applied=%d", seeded, applied)
}

// sendResponse writes one dnstap CLIENT_RESPONSE (NXDOMAIN for name) to addr, retrying
// until the agent listens.
func sendResponse(t *testing.T, addr, name string) {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Response, m.Rcode = true, dns.RcodeNameError
	wire, _ := m.Pack()
	typ, kind := dt.Message_CLIENT_RESPONSE, dt.Dnstap_MESSAGE
	sec := uint64(time.Now().Unix())
	f := &dt.Dnstap{Type: &kind, Message: &dt.Message{Type: &typ, ResponseMessage: wire, ResponseTimeSec: &sec}}
	var c net.Conn
	var err error
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if c, err = net.Dial("tcp", addr); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	w, err := dt.NewWriter(c, &dt.WriterOptions{Bidirectional: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := dt.NewEncoder(w).Encode(f); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
