// Package agent wires the node agent together (SPEC §9): enrollment, node secrets and
// the run loop (config apply, blocklist sync, heartbeat + commands, dnstap, CGK).
package agent

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/billyriantono/dnsjos/internal/agent/client"
	"github.com/billyriantono/dnsjos/internal/agent/dnsdist"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Filesystem layout; every path is prefixed with Options.Root.
const (
	ConfigPath  = "/etc/dnsjos/agent.json"
	DnsdistDir  = "/etc/dnsdist"
	DataDir     = "/var/lib/dnsjos"
	SecretsPath = DataDir + "/secrets.json"
	BackupDir   = DataDir + "/backup"
	SpoolDir    = DataDir + "/blocked-spool"
	CDBPath     = DataDir + "/blocklist/current.cdb"
)

type Options struct {
	Root       string // test mode: prefix for every filesystem path
	NoSystemd  bool   // test mode: no systemctl; tolerate a missing dnsdist binary
	DnsdistWeb string // override of the dnsdist webserver URL (default from the spec)
	Version    string
	Log        *slog.Logger
}

func (o Options) path(p string) string { return filepath.Join(o.Root, p) }

// Config is /etc/dnsjos/agent.json.
type Config struct {
	PanelURL  string `json:"panel_url"`
	NodeID    string `json:"node_id"`
	NodeToken string `json:"node_token"`
}

// Secrets are generated on first run and never leave the node.
type Secrets struct {
	ConsoleKey  string `json:"console_key"` // base64 of 32 random bytes, as setKey() expects
	WebPassword string `json:"web_password"`
	WebAPIKey   string `json:"web_api_key"`
}

// Enroll exchanges an enrollment token for a node token and writes agent.json. With
// adopt, the secrets and node-specific settings of the live dnsdist_ootb config are
// taken over (SPEC §17).
func Enroll(ctx context.Context, o Options, panelURL, token, name string, adopt bool) error {
	if panelURL == "" || token == "" {
		return errors.New("enroll: --panel and --token are required")
	}
	host := name
	if host == "" {
		host, _ = os.Hostname()
	}
	req := api.EnrollRequest{
		Token: token, Hostname: host, OS: osName(), Arch: runtime.GOARCH,
		AgentVersion: o.Version, DnsdistVersion: dnsdist.Version(ctx),
	}
	var ad adoption
	if adopt {
		var err error
		if ad, err = adoptOOTB(o.path(OOTBConfig)); err != nil {
			return fmt.Errorf("enroll --adopt: %w", err)
		}
		if strings.HasPrefix(ad.Secrets.WebAPIKey, "$") {
			o.Log.Warn("admin.web.apikey is hashed: the agent cannot read dnsdist stats with it; set a plain key")
		}
		req.Adopt = true
		req.AdoptOverrides, _ = json.Marshal(ad.Overrides)
	}
	cl := client.New(panelURL, "", o.Version)
	resp, err := cl.Enroll(ctx, req)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if adopt { // only after the panel accepted: a failed enroll leaves the node untouched
		if err := saveSecrets(o.path(SecretsPath), ad.Secrets); err != nil {
			return err
		}
	}
	b, _ := json.MarshalIndent(Config{PanelURL: cl.BaseURL, NodeID: resp.NodeID, NodeToken: resp.NodeToken}, "", "  ")
	if err := writePrivate(o.path(ConfigPath), b); err != nil {
		return err
	}
	o.Log.Info("enrolled", "node_id", resp.NodeID, "name", resp.Name, "panel", cl.BaseURL, "adopt", adopt,
		"overrides", string(req.AdoptOverrides))
	return nil
}

// saveSecrets merges imported secrets over the stored ones and fills any gap.
func saveSecrets(p string, in Secrets) error {
	cur, _ := readSecrets(p)
	cur.ConsoleKey = cmp.Or(in.ConsoleKey, cur.ConsoleKey)
	cur.WebPassword = cmp.Or(in.WebPassword, cur.WebPassword)
	cur.WebAPIKey = cmp.Or(in.WebAPIKey, cur.WebAPIKey)
	b, _ := json.MarshalIndent(cur, "", "  ")
	if err := writePrivate(p, b); err != nil {
		return err
	}
	_, err := LoadSecrets(p)
	return err
}

func loadConfig(p string) (Config, error) {
	var c Config
	b, err := os.ReadFile(p)
	if err != nil {
		return c, fmt.Errorf("%w (run `dnsjos-agent enroll` first)", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", p, err)
	}
	if c.PanelURL == "" || c.NodeToken == "" {
		return c, fmt.Errorf("%s: panel_url and node_token are required", p)
	}
	return c, nil
}

// LoadSecrets reads the node secrets, generating and persisting them on first use.
func LoadSecrets(p string) (Secrets, error) {
	s, err := readSecrets(p)
	if err != nil {
		return s, err
	}
	if s.ConsoleKey != "" && s.WebPassword != "" && s.WebAPIKey != "" {
		return s, nil
	}
	rnd := func(n int, enc *base64.Encoding) string {
		b := make([]byte, n)
		rand.Read(b)
		return enc.EncodeToString(b)
	}
	if s.ConsoleKey == "" {
		s.ConsoleKey = rnd(32, base64.StdEncoding)
	}
	if s.WebPassword == "" {
		s.WebPassword = rnd(24, base64.RawURLEncoding)
	}
	if s.WebAPIKey == "" {
		s.WebAPIKey = rnd(24, base64.RawURLEncoding)
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return s, writePrivate(p, b)
}

func readSecrets(p string) (Secrets, error) {
	var s Secrets
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return s, nil
	} else if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("%s: %w", p, err)
	}
	return s, nil
}

// writePrivate writes a 0600 file atomically.
func writePrivate(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func osName() string {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
				return strings.Trim(v, `"`)
			}
		}
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}

// every runs f on each tick of a (re-read) interval or when kick fires, until ctx ends.
func every(ctx context.Context, interval func() time.Duration, kick <-chan struct{}, f func()) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		}
		f()
		t.Reset(interval())
	}
}

func poke(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
