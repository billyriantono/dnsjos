package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/colinmarc/cdb"
	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/agent/apply"
	"github.com/billyriantono/dnsjos/internal/agent/dnsdist"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/dnsconf"
)

// dnsdist and agent upgrades (SPEC §18).
const (
	AptSourcesDir   = "/etc/apt/sources.list.d"
	AptPrefsDir     = "/etc/apt/preferences.d"
	LastUpgradePath = DataDir + "/last-upgrade.json"
	AgentMarkerPath = DataDir + "/agent-upgrade.json" // written before the self-upgrade restart
	AptBackupDir    = DataDir + "/apt-backup"
	inventoryEvery  = 6 * time.Hour
	probeName       = "example.com."
)

// ErrRestart ends Run after the agent binary was replaced; the non-zero exit makes
// systemd (Restart=always) start the new binary.
var ErrRestart = errors.New("agent binary replaced, exiting so systemd restarts it")

var seriesRe = regexp.MustCompile(`-dnsdist-(\d+)\b`)

// executable is the running binary; tests point it at a scratch file.
var executable = os.Executable

// Runner runs a system command (apt-get, apt-cache, dpkg-query, systemctl) and returns
// its combined output.
type Runner func(ctx context.Context, env []string, name string, args ...string) (string, error)

func execRunner(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(append(os.Environ(), "LC_ALL=C"), env...) // apt output is parsed
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if len(s) > 1000 {
			s = s[len(s)-1000:]
		}
		return s, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, s)
	}
	return s, nil
}

// dnsdistVersion is the installed package version (comparable with the apt lists),
// falling back to `dnsdist --version` when dpkg does not know it.
func dnsdistVersion(ctx context.Context, run Runner) string {
	if v, err := run(ctx, nil, "dpkg-query", "-W", "-f=${Version}", "dnsdist"); err == nil && v != "" {
		return v
	}
	return dnsdist.Version(ctx)
}

type inventory struct {
	Candidate string
	Available []string // newest first, as apt-cache madison lists them
	Series    string
	At        *time.Time
}

// pdnsList finds the apt source of the PowerDNS dnsdist repo and its series.
func (a *agent) pdnsList() (path, series string, err error) {
	files, _ := filepath.Glob(a.o.path(AptSourcesDir + "/*"))
	for _, f := range files {
		if !strings.HasSuffix(f, ".list") && !strings.HasSuffix(f, ".sources") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil || !bytes.Contains(b, []byte("repo.powerdns.com")) || !bytes.Contains(b, []byte("dnsdist")) {
			continue
		}
		m := seriesRe.FindSubmatch(b)
		if m == nil {
			m = seriesRe.FindSubmatch([]byte(filepath.Base(f)))
		}
		if m != nil {
			series = string(m[1])
		}
		return f, series, nil
	}
	return "", "", errors.New("no repo.powerdns.com dnsdist source in " + AptSourcesDir)
}

// refreshInventory updates only the PowerDNS list and reads candidate + available versions.
func (a *agent) refreshInventory(ctx context.Context) error {
	a.aptMu.Lock()
	defer a.aptMu.Unlock()
	list, series, err := a.pdnsList()
	if err != nil {
		return err
	}
	if _, err := a.run(ctx, nil, "apt-get", "update", "-q", "-o", "Dir::Etc::sourcelist="+list,
		"-o", "Dir::Etc::sourceparts=-", "-o", "APT::Get::List-Cleanup=0"); err != nil {
		return err
	}
	pol, err := a.run(ctx, nil, "apt-cache", "policy", "dnsdist")
	if err != nil {
		return err
	}
	mad, err := a.run(ctx, nil, "apt-cache", "madison", "dnsdist")
	if err != nil {
		return err
	}
	inv := parseInventory(pol, mad, series)
	now := time.Now().UTC()
	inv.At = &now
	a.mu.Lock()
	a.inv = inv
	a.mu.Unlock()
	a.o.Log.Info("dnsdist inventory", "candidate", inv.Candidate, "available", inv.Available, "series", series)
	poke(a.hbNow)
	return nil
}

// parseInventory reads the candidate from `apt-cache policy` and the versions of the
// PowerDNS repo in series from `apt-cache madison`.
func parseInventory(policy, madison, series string) inventory {
	inv := inventory{Series: series, Available: []string{}}
	for _, l := range strings.Split(policy, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "Candidate:"); ok {
			if v = strings.TrimSpace(v); v != "(none)" {
				inv.Candidate = v
			}
		}
	}
	for _, l := range strings.Split(madison, "\n") {
		f := strings.Split(l, "|")
		if len(f) != 3 || strings.TrimSpace(f[0]) != "dnsdist" || !strings.Contains(f[2], "repo.powerdns.com") ||
			(series != "" && !strings.Contains(f[2], "-dnsdist-"+series+"/")) {
			continue
		}
		if v := strings.TrimSpace(f[1]); !slices.Contains(inv.Available, v) {
			inv.Available = append(inv.Available, v)
		}
	}
	return inv
}

func (a *agent) inventoryLoop(ctx context.Context) {
	every(ctx, func() time.Duration { return inventoryEvery }, a.invNow, func() {
		if err := a.refreshInventory(ctx); err != nil && ctx.Err() == nil {
			a.o.Log.Warn("dnsdist inventory failed", "err", err)
		}
	})
}

// upgrade runs f as the only upgrade on this node with upgrade_in_progress set and
// records its result (nil = nothing to record yet) as last_upgrade.
func (a *agent) upgrade(f func() *api.UpgradeResult) {
	a.mu.Lock()
	if a.upgrading {
		a.mu.Unlock()
		a.o.Log.Warn("an upgrade is already running, command ignored")
		return
	}
	a.upgrading = true
	a.mu.Unlock()
	poke(a.hbNow)
	res := f()
	a.mu.Lock()
	a.upgrading = false
	if res != nil {
		a.lastUp = res
	}
	a.mu.Unlock()
	if res != nil {
		a.o.Log.Info("upgrade finished", "kind", res.Kind, "from", res.From, "to", res.To, "ok", res.OK, "err", res.Error)
		b, _ := json.Marshal(res)
		if err := writePrivate(a.o.path(LastUpgradePath), b); err != nil {
			a.o.Log.Warn("saving last upgrade failed", "err", err)
		}
	}
	poke(a.hbNow)
}

// upgradeDnsdist installs version, verifies dnsdist and reinstalls the previous version
// when anything fails. Config applies wait meanwhile (opMu).
func (a *agent) upgradeDnsdist(ctx context.Context, version string) *api.UpgradeResult {
	ctx = context.WithoutCancel(ctx) // never interrupt dpkg half-way
	res := &api.UpgradeResult{Kind: api.UpgradeDnsdist, To: version}
	err := func() error {
		a.aptMu.Lock()
		defer a.aptMu.Unlock()
		a.opMu.Lock()
		defer a.opMu.Unlock()
		res.From = dnsdistVersion(ctx, a.run)
		a.mu.Lock()
		avail := a.inv.Available
		a.mu.Unlock()
		if !slices.Contains(avail, version) {
			return fmt.Errorf("version %q is not available (have %v; check_updates refreshes the list)", version, avail)
		}
		i, j := slices.Index(avail, version), slices.Index(avail, res.From)
		err := a.aptInstall(ctx, version, j >= 0 && i > j)
		if err == nil {
			err = a.verifyDnsdist(ctx)
		}
		if err == nil || res.From == "" {
			return err
		}
		a.o.Log.Error("dnsdist upgrade failed, reinstalling the previous version", "err", err, "previous", res.From)
		if rerr := a.aptInstall(ctx, res.From, true); rerr != nil {
			return fmt.Errorf("%w; rollback to %s failed: %v", err, res.From, rerr)
		}
		if rerr := a.verifyDnsdist(ctx); rerr != nil {
			return fmt.Errorf("%w; after rollback to %s: %v", err, res.From, rerr)
		}
		return fmt.Errorf("%w (rolled back to %s)", err, res.From)
	}()
	ver := dnsdistVersion(ctx, a.run)
	a.mu.Lock()
	a.dnsdistVer = ver
	a.mu.Unlock()
	res.OK, res.At = err == nil, time.Now().UTC()
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

func (a *agent) aptInstall(ctx context.Context, version string, downgrade bool) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	args := []string{"install", "-y", "-q", "--only-upgrade", "-o", "Dpkg::Options::=--force-confold"}
	if downgrade {
		args = append(args, "--allow-downgrades")
	}
	_, err := a.run(ctx, []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", append(args, "dnsdist="+version)...)
	return err
}

// verifyDnsdist checks the freshly installed dnsdist: console, service, config, and a
// resolving and a blocked test query against the local Do53 listener.
func (a *agent) verifyDnsdist(ctx context.Context) error {
	if err := a.app.WaitConsole(ctx); err != nil {
		return err
	}
	if _, err := a.run(ctx, nil, "systemctl", "is-active", "dnsdist"); err != nil {
		return fmt.Errorf("dnsdist not active: %w", err)
	}
	if err := dnsdist.CheckConfig(ctx, a.app.Conf()); err != nil {
		return fmt.Errorf("check-config: %w", err)
	}
	cfg := a.config()
	if cfg == nil || !cfg.Spec.Listen.Do53.Enabled || len(cfg.Spec.Listen.Do53.Addresses) == 0 {
		return nil
	}
	addr := loopback(cfg.Spec.Listen.Do53.Addresses[0])
	query := func(name string) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		c := dns.Client{Timeout: 3 * time.Second}
		var r *dns.Msg
		var err error
		for range 10 { // backends may still be marked down right after the restart
			if r, _, err = c.ExchangeContext(ctx, m, addr); err == nil && r.Rcode == dns.RcodeSuccess {
				return r, nil
			}
			time.Sleep(time.Second)
		}
		if err == nil {
			err = errors.New(dns.RcodeToString[r.Rcode])
		}
		return nil, fmt.Errorf("test query %s via %s: %w", name, addr, err)
	}
	if _, err := query(probeName); err != nil {
		return err
	}
	name := firstBlockedName(a.o.path(CDBPath))
	if !cfg.Spec.Blocking.Enabled || name == "" || cfg.Spec.Blocking.BlockpageIPv4 == "" {
		return nil
	}
	r, err := query(name)
	if err != nil {
		return err
	}
	for _, rr := range r.Answer {
		if a4, ok := rr.(*dns.A); ok && a4.A.String() == cfg.Spec.Blocking.BlockpageIPv4 {
			return nil
		}
	}
	return fmt.Errorf("blocked name %s did not return the blockpage %s: %v", name, cfg.Spec.Blocking.BlockpageIPv4, r.Answer)
}

// firstBlockedName returns the first domain key of the CDB ("" when there is none);
// IPv4 keys (four numeric labels) are skipped.
func firstBlockedName(p string) string {
	c, err := cdb.Open(p)
	if err != nil {
		return ""
	}
	defer c.Close()
	it := c.Iter()
	for n := 0; n < 1000 && it.Next(); n++ {
		var labels []string
		for k := it.Key(); len(k) > 0 && k[0] > 0 && int(k[0]) < len(k); k = k[1+k[0]:] {
			labels = append(labels, string(k[1:1+k[0]]))
		}
		if len(labels) > 0 && !(len(labels) == 4 && strings.Trim(strings.Join(labels, ""), "0123456789") == "") {
			return strings.Join(labels, ".") + "."
		}
	}
	return ""
}

// setSeries points the PowerDNS source and pin at another dnsdist series (backups in
// AptBackupDir) and refreshes the inventory; the old files come back when apt fails.
// It returns the previous series.
func (a *agent) setSeries(ctx context.Context, series string) (old string, err error) {
	if !slices.Contains(dnsconf.SupportedSeries, series) {
		return "", fmt.Errorf("series %q is not supported (%v)", series, dnsconf.SupportedSeries)
	}
	a.aptMu.Lock()
	list, old, err := a.pdnsList()
	if err != nil {
		a.aptMu.Unlock()
		return "", err
	}
	orig := map[string][]byte{} // path → content before (nil = did not exist)
	remember := func(p string) {
		if _, ok := orig[p]; !ok {
			orig[p], _ = os.ReadFile(p)
		}
	}
	write := func(p string, b []byte) error {
		remember(p)
		return apply.WriteFile(p, b, 0o644)
	}
	b, _ := os.ReadFile(list)
	err = write(list, seriesRe.ReplaceAll(b, []byte("-dnsdist-"+series)))
	pins, _ := filepath.Glob(a.o.path(AptPrefsDir + "/*"))
	pinned := false
	for _, p := range pins {
		b, rerr := os.ReadFile(p)
		if err != nil || rerr != nil || !bytes.Contains(b, []byte("dnsdist")) || !bytes.Contains(b, []byte("repo.powerdns.com")) {
			continue
		}
		np := p
		if old != "" && filepath.Base(p) == "dnsdist-"+old {
			np = filepath.Join(filepath.Dir(p), "dnsdist-"+series)
		}
		if err = write(np, seriesRe.ReplaceAll(b, []byte("-dnsdist-"+series))); err == nil && np != p {
			remember(p)
			err = os.Remove(p)
		}
		pinned = true
	}
	if err == nil && !pinned {
		err = write(a.o.path(AptPrefsDir+"/dnsdist-"+series), []byte("Package: dnsdist*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n"))
	}
	if err == nil {
		err = a.backupApt(orig)
	}
	a.aptMu.Unlock()
	if err == nil {
		a.o.Log.Info("dnsdist series switched", "from", old, "to", series)
		if err = a.refreshInventory(ctx); err == nil {
			return old, nil
		}
	}
	for p, b := range orig {
		if b == nil {
			os.Remove(p)
		} else {
			apply.WriteFile(p, b, 0o644)
		}
	}
	return old, fmt.Errorf("switching to series %s (old apt files restored): %w", series, err)
}

// backupApt keeps the original apt files in AptBackupDir/<timestamp>/.
func (a *agent) backupApt(orig map[string][]byte) error {
	dir := a.o.path(filepath.Join(AptBackupDir, time.Now().UTC().Format("20060102T150405Z")))
	for p, b := range orig {
		if b == nil {
			continue
		}
		if err := apply.WriteFile(filepath.Join(dir, filepath.Base(p)), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// upgradeAgent replaces the running binary with the panel's and stops the agent; the
// result is reported by the new binary (AgentMarkerPath). Only failures return a result.
func (a *agent) upgradeAgent(ctx context.Context) *api.UpgradeResult {
	err := func() error {
		exe, err := executable()
		if err == nil {
			exe, err = filepath.EvalSymlinks(exe)
		}
		if err != nil {
			return err
		}
		url := "/dl/agent/linux/" + runtime.GOARCH
		var sum bytes.Buffer
		if err := a.download(ctx, url+".sha256", &sum); err != nil {
			return err
		}
		want, _, _ := strings.Cut(strings.TrimSpace(sum.String()), " ")
		f, err := os.OpenFile(exe+".new", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		h := sha256.New()
		err = a.download(ctx, url, io.MultiWriter(f, h))
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if got := hex.EncodeToString(h.Sum(nil)); err == nil && !strings.EqualFold(got, want) {
			err = fmt.Errorf("sha256 mismatch: got %s, panel says %q", got, want)
		}
		if err != nil {
			os.Remove(exe + ".new")
			return err
		}
		os.Remove(exe + ".prev")
		if err := os.Link(exe, exe+".prev"); err != nil {
			a.o.Log.Warn("keeping the previous agent binary failed", "err", err)
		}
		if err := os.Rename(exe+".new", exe); err != nil {
			return err
		}
		if d, err := os.Open(filepath.Dir(exe)); err == nil {
			d.Sync()
			d.Close()
		}
		b, _ := json.Marshal(agentMarker{UpgradeResult: api.UpgradeResult{Kind: api.UpgradeAgent, From: a.o.Version, At: time.Now().UTC()}})
		return writePrivate(a.o.path(AgentMarkerPath), b)
	}()
	if err != nil {
		return &api.UpgradeResult{Kind: api.UpgradeAgent, From: a.o.Version, Error: err.Error(), At: time.Now().UTC()}
	}
	a.o.Log.Info("agent binary replaced, restarting")
	a.heartbeat(ctx) // ack the command before exiting
	a.opMu.Lock()    // let a running config apply finish first
	a.stop(ErrRestart)
	a.opMu.Unlock()
	return nil
}

func (a *agent) download(ctx context.Context, path string, w io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := a.cl.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	resp, err := a.cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	_, err = io.Copy(w, io.LimitReader(resp.Body, 512<<20))
	return err
}

// agentMarker is AgentMarkerPath: written just before the self-upgrade restart, counted
// up by every start of the new binary and removed by its first successful heartbeat.
type agentMarker struct {
	api.UpgradeResult     // Kind, From; At = when the binary was replaced
	Starts            int `json:"starts"`
}

// A new agent that starts more than crashStarts times within crashWindow of the
// upgrade without a successful heartbeat is replaced by the previous binary.
const (
	crashStarts = 3
	crashWindow = 5 * time.Minute
)

// reexec replaces the process image (tests stub it).
var reexec = func(exe string) error { return syscall.Exec(exe, os.Args, os.Environ()) }

// upgradeGuard runs first on every start: while an agent upgrade is unconfirmed it
// counts starts and, once the new binary keeps crashing, restores exe.prev, records
// the failed upgrade and execs the previous binary.
func upgradeGuard(o Options) error {
	p := o.path(AgentMarkerPath)
	var m agentMarker
	if b, err := os.ReadFile(p); err != nil || json.Unmarshal(b, &m) != nil {
		return nil
	}
	if m.At.IsZero() { // marker of an agent without the guard
		m.At = time.Now().UTC()
	}
	m.Starts++
	save := func() {
		b, _ := json.Marshal(m)
		if err := writePrivate(p, b); err != nil {
			o.Log.Warn("updating the agent upgrade marker failed", "err", err)
		}
	}
	if m.Starts <= crashStarts || time.Since(m.At) > crashWindow {
		save()
		return nil
	}
	exe, err := executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err == nil {
		err = os.Rename(exe+".prev", exe)
	}
	if err != nil {
		o.Log.Error("agent keeps crashing after the upgrade but the previous binary cannot be restored", "err", err)
		save()
		return nil
	}
	res := api.UpgradeResult{Kind: api.UpgradeAgent, From: m.From, To: o.Version, At: time.Now().UTC(),
		Error: fmt.Sprintf("agent %s restarted %d times within %s of the upgrade without reaching the panel; restored %s",
			o.Version, m.Starts-1, crashWindow, m.From)}
	b, _ := json.Marshal(res)
	writePrivate(o.path(LastUpgradePath), b)
	os.Remove(p)
	o.Log.Error("agent upgrade failed, running the previous binary", "restored", m.From, "failed", o.Version)
	return reexec(exe)
}

// confirmUpgrade records a pending agent upgrade as done (first successful heartbeat).
func (a *agent) confirmUpgrade() {
	a.mu.Lock()
	m := a.marker
	a.marker = nil
	a.mu.Unlock()
	if m == nil {
		return
	}
	res := m.UpgradeResult
	res.To, res.OK, res.At = a.o.Version, true, time.Now().UTC()
	b, _ := json.Marshal(res)
	writePrivate(a.o.path(LastUpgradePath), b)
	os.Remove(a.o.path(AgentMarkerPath))
	a.mu.Lock()
	a.lastUp = &res
	a.mu.Unlock()
	a.o.Log.Info("agent upgraded", "from", res.From, "to", res.To)
	poke(a.hbNow)
}

// loadLastUpgrade reads last_upgrade and a pending agent upgrade marker.
func (a *agent) loadLastUpgrade() {
	var m agentMarker
	if b, err := os.ReadFile(a.o.path(AgentMarkerPath)); err == nil && json.Unmarshal(b, &m) == nil {
		a.marker = &m
	}
	var res api.UpgradeResult
	if b, err := os.ReadFile(a.o.path(LastUpgradePath)); err == nil && json.Unmarshal(b, &res) == nil {
		a.lastUp = &res
	}
}
