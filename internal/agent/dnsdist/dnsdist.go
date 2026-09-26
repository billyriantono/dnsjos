// Package dnsdist wraps the dnsdist binary (config check, console via `dnsdist -c`)
// and the local webserver API.
package dnsdist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// Binary is the dnsdist executable name looked up on PATH.
var Binary = "dnsdist"

// ErrNoBinary is returned when dnsdist is not installed.
var ErrNoBinary = errors.New("dnsdist binary not found")

func run(ctx context.Context, args ...string) (string, error) {
	bin, err := exec.LookPath(Binary)
	if err != nil {
		return "", ErrNoBinary
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	s := strings.TrimSpace(out.String())
	if err != nil {
		if len(s) > 2000 {
			s = s[len(s)-2000:]
		}
		return s, fmt.Errorf("dnsdist %s: %w: %s", args[0], err, s)
	}
	return s, nil
}

// CheckConfig runs `dnsdist --check-config -C conf`.
func CheckConfig(ctx context.Context, conf string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	_, err := run(ctx, "--check-config", "-C", conf)
	return err
}

// Console runs one Lua command on the running dnsdist through its control socket;
// `dnsdist -c` reads controlSocket()/setKey() from conf.
func Console(ctx context.Context, conf, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := run(ctx, "-C", conf, "-c", "-e", command)
	return dropLogLines(out), err
}

// dropLogLines removes the structured log lines dnsdist prints on stdout while it
// parses the config in client mode (e.g. the plain-text password notice).
func dropLogLines(s string) string {
	lines := strings.Split(s, "\n")
	lines = slices.DeleteFunc(lines, func(l string) bool { return strings.HasPrefix(l, `msg="`) })
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// Version returns the first line of `dnsdist --version` ("" when unavailable).
func Version(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := run(ctx, "--version")
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(out, "\n")
	return strings.TrimSpace(line)
}

// Web is a client for the dnsdist webserver API (X-API-Key auth).
type Web struct {
	URL    string // http://127.0.0.1:8083
	APIKey string
	HTTP   *http.Client
}

func (w Web) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(w.URL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", w.APIKey)
	hc := w.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dnsdist webserver %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Stats is /jsonstat?command=stats: stat name → value (non-numeric values dropped).
func (w Web) Stats(ctx context.Context) (map[string]float64, error) {
	var raw map[string]any
	if err := w.get(ctx, "/jsonstat?command=stats", &raw); err != nil {
		return nil, err
	}
	out := make(map[string]float64, len(raw))
	for k, v := range raw {
		if f, ok := v.(float64); ok {
			out[k] = f
		}
	}
	return out, nil
}

// Server is one entry of /api/v1/servers/localhost "servers".
type Server struct {
	Address string   `json:"address"`
	Name    string   `json:"name"`
	Pools   []string `json:"pools"`
	State   string   `json:"state"`
	Weight  int      `json:"weight"`
	Order   int      `json:"order"`
	QPS     float64  `json:"qps"`
	Latency float64  `json:"latency"` // ms
	Queries int64    `json:"queries"`
	Drops   int64    `json:"drops"`
}

func (w Web) Servers(ctx context.Context) ([]Server, error) {
	var out struct {
		Servers []Server `json:"servers"`
	}
	err := w.get(ctx, "/api/v1/servers/localhost", &out)
	return out.Servers, err
}

// DynBlockEntry is one value of /jsonstat?command=dynblocklist (keyed by netmask or suffix).
type DynBlockEntry struct {
	Reason  string `json:"reason"`
	Seconds int    `json:"seconds"`
	Blocks  int64  `json:"blocks"`
	Warning bool   `json:"warning"`
}

func (w Web) DynBlocks(ctx context.Context) (map[string]DynBlockEntry, error) {
	var out map[string]DynBlockEntry
	err := w.get(ctx, "/jsonstat?command=dynblocklist", &out)
	return out, err
}
