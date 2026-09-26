package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/billyriantono/dnsjos/internal/agent/apply"
	"github.com/billyriantono/dnsjos/internal/agent/blocklist"
	"github.com/billyriantono/dnsjos/internal/agent/cgk"
	"github.com/billyriantono/dnsjos/internal/agent/client"
	"github.com/billyriantono/dnsjos/internal/agent/collect"
	"github.com/billyriantono/dnsjos/internal/agent/dnsdist"
	"github.com/billyriantono/dnsjos/internal/agent/dnstap"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/dnsconf"
)

const (
	blocklistEvery = 60 * time.Second
	flushEvery     = 60 * time.Second
	dnstapCap      = 200000
)

type agent struct {
	o     Options
	cl    *client.Client
	sec   Secrets
	app   *apply.Applier
	bl    *blocklist.Syncer
	agg   *dnstap.Agg
	spool *dnstap.Spool
	host  string
	os    string
	opMu  sync.Mutex // serialises apply and restarts
	start time.Time

	mu         sync.Mutex
	cfg        *api.AgentConfig // newest config received
	seen       int              // its version (sent as ETag)
	applied    int
	applyErr   string
	blErr      string
	wantSHA    string
	cgkStatus  api.CGKStatus
	cgkForce   bool
	acks       []int64
	dnsdistVer string

	pollNow, forceNow, blNow, cgkNow, hbNow chan struct{}
}

// Run runs the agent until ctx is cancelled.
func Run(ctx context.Context, o Options) error {
	a, err := newAgent(ctx, o)
	if err != nil {
		return err
	}
	a.cgkStatus = a.cgkFiles()
	o.Log.Info("agent starting", "version", o.Version, "panel", a.cl.BaseURL, "root", o.Root, "no_systemd", o.NoSystemd)

	var wg sync.WaitGroup
	for _, f := range []func(context.Context){a.configLoop, a.blocklistLoop, a.heartbeatLoop, a.dnstapLoop, a.cgkLoop} {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	wg.Wait()
	o.Log.Info("agent stopped")
	return nil
}

func newAgent(ctx context.Context, o Options) (*agent, error) {
	c, err := loadConfig(o.path(ConfigPath))
	if err != nil {
		return nil, err
	}
	// dnsdist (user _dnsdist) must traverse the data dir to read the CDB; the
	// secrets inside stay 0600.
	if err := os.MkdirAll(o.path(DataDir), 0o711); err != nil {
		return nil, err
	}
	os.Chmod(o.path(DataDir), 0o711)
	sec, err := LoadSecrets(o.path(SecretsPath))
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	cl := client.New(c.PanelURL, c.NodeToken, o.Version)
	a := &agent{
		o: o, cl: cl, sec: sec, start: time.Now(),
		app: &apply.Applier{Dir: o.path(DnsdistDir), BackupDir: o.path(BackupDir), PreAdoptDir: o.path(DataDir),
			NoSystemd: o.NoSystemd, Log: o.Log},
		bl:  &blocklist.Syncer{Client: cl, Path: o.path(CDBPath)},
		agg: &dnstap.Agg{Cap: dnstapCap},
		os:  osName(), dnsdistVer: dnsdist.Version(ctx),
		pollNow: make(chan struct{}, 1), forceNow: make(chan struct{}, 1),
		blNow: make(chan struct{}, 1), cgkNow: make(chan struct{}, 1), hbNow: make(chan struct{}, 1),
	}
	a.host, _ = os.Hostname()
	a.spool = &dnstap.Spool{Dir: o.path(SpoolDir), Post: cl.PostBlocked, Log: o.Log}
	return a, nil
}

func (a *agent) config() *api.AgentConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

func (a *agent) runtime() api.NodeRuntime {
	return api.NodeRuntime{
		ConsoleKey: a.sec.ConsoleKey, WebPassword: a.sec.WebPassword, WebAPIKey: a.sec.WebAPIKey,
		CDBPath: a.o.path(CDBPath), DnstapAddr: dnsconf.DefaultDnstapAddr, Hostname: a.host,
	}
}

// ── config ──────────────────────────────────────────────────────────────────

func (a *agent) configLoop(ctx context.Context) {
	interval := func() time.Duration {
		if c := a.config(); c != nil && c.PollIntervalS > 0 {
			return time.Duration(c.PollIntervalS) * time.Second
		}
		return api.DefaultPollS * time.Second
	}
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		force := false
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.pollNow:
		case <-a.forceNow:
			force = true
		}
		a.pollConfig(ctx, force)
		t.Reset(interval())
	}
}

func (a *agent) pollConfig(ctx context.Context, force bool) {
	a.mu.Lock()
	ver := a.seen
	a.mu.Unlock()
	if force {
		ver = 0
	}
	cfg, err := a.cl.Config(ctx, ver)
	if errorCode(err) == "no_blocklist" && a.seedCDB() { // adopted node, no panel build: seed, report, retry once
		a.heartbeat(ctx)
		cfg, err = a.cl.Config(ctx, ver)
	}
	if err != nil {
		if ctx.Err() == nil {
			a.o.Log.Warn("fetching config failed", "err", err)
		}
		var se *client.StatusError
		if errors.As(err, &se) && se.Code == 409 { // effective config invalid, or no blocklist yet
			a.mu.Lock()
			a.applyErr = se.Body
			a.mu.Unlock()
		}
		return
	}
	if cfg == nil {
		return // 304
	}
	a.mu.Lock()
	a.cfg, a.seen = cfg, cfg.Version
	if cfg.Blocklist.SHA256 != "" {
		a.wantSHA = cfg.Blocklist.SHA256
	}
	a.mu.Unlock()
	poke(a.blNow)

	a.ensureCDB(ctx, cfg)
	a.opMu.Lock()
	changed, err := a.app.Apply(ctx, cfg.Spec, a.runtime(), force)
	a.opMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.applyErr = fmt.Sprintf("config v%d: %v", cfg.Version, err)
		a.o.Log.Error("config apply failed", "version", cfg.Version, "err", err)
		return
	}
	a.applied, a.applyErr = cfg.Version, ""
	if changed {
		a.dnsdistVer = dnsdist.Version(ctx)
		a.o.Log.Info("config applied", "version", cfg.Version, "profile", cfg.Profile)
		poke(a.hbNow) // let the panel see the new version right away
	}
	poke(a.cgkNow) // CGK loop re-reads the spec (enable/disable, interval)
}

// errorCode is the panel's error code of a failed call ("" when none).
func errorCode(err error) string {
	var se *client.StatusError
	var body api.ErrorBody
	if errors.As(err, &se) && json.Unmarshal([]byte(se.Body), &body) == nil {
		return body.Error.Code
	}
	return ""
}

// ── blocklist ───────────────────────────────────────────────────────────────

// ensureCDB makes sure a blocklist is installed before a config that blocks is
// applied: the panel's build first, else the adopted server's old CDB (SPEC §17).
func (a *agent) ensureCDB(ctx context.Context, cfg *api.AgentConfig) {
	if !cfg.Spec.Blocking.Enabled || a.bl.Local() != "" {
		return
	}
	if cfg.Blocklist.SHA256 != "" {
		if _, err := a.bl.Sync(ctx, cfg.Blocklist.SHA256); err != nil {
			a.o.Log.Warn("blocklist download before apply failed", "err", err)
		}
	}
	a.seedCDB()
}

// seedCDB copies the old /etc/dnsdist/db/blacklist.db when no CDB is installed; true
// when a CDB is installed afterwards.
func (a *agent) seedCDB() bool {
	ok, err := a.bl.Seed(a.o.path(OOTBCDB))
	switch {
	case ok:
		a.o.Log.Info("blocklist seeded from the adopted server", "src", a.o.path(OOTBCDB), "sha256", a.bl.Local())
	case err != nil && !os.IsNotExist(err):
		a.o.Log.Warn("seeding the blocklist failed", "err", err)
	}
	return a.bl.Local() != ""
}

func (a *agent) blocklistLoop(ctx context.Context) {
	every(ctx, func() time.Duration { return blocklistEvery }, a.blNow, func() {
		a.mu.Lock()
		want := a.wantSHA
		a.mu.Unlock()
		changed, err := a.bl.Sync(ctx, want)
		a.mu.Lock()
		defer a.mu.Unlock()
		if err != nil {
			if ctx.Err() == nil {
				a.blErr = err.Error()
				a.o.Log.Warn("blocklist sync failed", "err", err)
			}
			return
		}
		a.blErr = ""
		if changed {
			a.o.Log.Info("blocklist installed", "sha256", want)
		}
	})
}

// ── heartbeat + commands ────────────────────────────────────────────────────

func (a *agent) heartbeatLoop(ctx context.Context) {
	interval := func() time.Duration {
		if c := a.config(); c != nil && c.HeartbeatIntervalS > 0 {
			return time.Duration(c.HeartbeatIntervalS) * time.Second
		}
		return api.DefaultHeartbS * time.Second
	}
	every(ctx, interval, a.hbNow, func() { a.heartbeat(ctx) })
}

// webURL is the local dnsdist webserver; a wildcard listen address is reached over loopback.
func (a *agent) webURL() string {
	if a.o.DnsdistWeb != "" {
		return a.o.DnsdistWeb
	}
	listen := api.DefaultConfigSpec().Webserver.Listen
	if c := a.config(); c != nil && c.Spec.Webserver.Listen != "" {
		listen = c.Spec.Webserver.Listen
	}
	if ap, err := netip.ParseAddrPort(listen); err == nil && ap.Addr().IsUnspecified() {
		lo := netip.IPv6Loopback()
		if ap.Addr().Is4() {
			lo = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		}
		listen = netip.AddrPortFrom(lo, ap.Port()).String()
	}
	return "http://" + listen
}

func (a *agent) collectHeartbeat(ctx context.Context) *api.Heartbeat {
	hb := &api.Heartbeat{Time: time.Now().UTC(), AgentVersion: a.o.Version, OS: a.os,
		BlocklistSHA256: a.bl.Local(), System: collect.System(a.o.path(DataDir))}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	collect.Dnsdist(cctx, dnsdist.Web{URL: a.webURL(), APIKey: a.sec.WebAPIKey}, hb)
	cancel()
	a.mu.Lock()
	hb.DnsdistVersion, hb.AppliedConfigVersion, hb.ApplyError, hb.BlocklistError = a.dnsdistVer, a.applied, a.applyErr, a.blErr
	hb.CGK = a.cgkStatus
	hb.AckedCommands = slices.Clone(a.acks)
	a.mu.Unlock()
	return hb
}

func (a *agent) heartbeat(ctx context.Context) {
	hb := a.collectHeartbeat(ctx)
	a.mu.Lock()
	seen := a.seen
	a.mu.Unlock()

	ack, err := a.cl.Heartbeat(ctx, hb)
	if err != nil {
		if ctx.Err() == nil {
			a.o.Log.Warn("heartbeat failed", "err", err)
		}
		return
	}
	a.mu.Lock()
	a.acks = slices.DeleteFunc(a.acks, func(id int64) bool { return slices.Contains(hb.AckedCommands, id) })
	if ack.BlocklistSHA256 != "" {
		a.wantSHA = ack.BlocklistSHA256
	}
	a.mu.Unlock()
	if ack.ConfigVersion != 0 && ack.ConfigVersion != seen {
		poke(a.pollNow)
	}
	if ack.BlocklistSHA256 != "" && ack.BlocklistSHA256 != hb.BlocklistSHA256 {
		poke(a.blNow)
	}
	for _, c := range ack.Commands {
		a.command(ctx, c)
	}
}

// command dispatches a panel command; it is acked with the next heartbeat.
func (a *agent) command(ctx context.Context, c api.Command) {
	a.o.Log.Info("command received", "id", c.ID, "type", c.Type)
	switch c.Type {
	case api.CmdCGKRefresh:
		a.mu.Lock()
		a.cgkForce = true
		a.mu.Unlock()
		poke(a.cgkNow)
	case api.CmdReapply:
		poke(a.forceNow)
	case api.CmdRestartDnsdist:
		go func() {
			a.opMu.Lock()
			defer a.opMu.Unlock()
			if err := a.app.Restart(ctx); err != nil {
				a.o.Log.Error("restart dnsdist failed", "err", err)
			}
		}()
	default:
		a.o.Log.Warn("unknown command", "type", c.Type)
	}
	a.mu.Lock()
	a.acks = append(a.acks, c.ID)
	a.mu.Unlock()
}

// ── dnstap ──────────────────────────────────────────────────────────────────

func (a *agent) dnstapLoop(ctx context.Context) {
	go func() {
		for ctx.Err() == nil {
			l, err := net.Listen("tcp", dnsconf.DefaultDnstapAddr)
			if err == nil {
				err = dnstap.Serve(ctx, l, a.agg, a.o.Log)
			}
			if err != nil {
				a.o.Log.Error("dnstap listener failed, retrying in 30s", "err", err)
				select {
				case <-ctx.Done():
				case <-time.After(30 * time.Second):
				}
			}
		}
	}()
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final flush; whatever the panel does not take in time is spooled.
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			a.spool.Flush(fctx, a.agg.Take())
			cancel()
			return
		case <-t.C:
			a.spool.Flush(ctx, a.agg.Take())
		}
	}
}

// ── CGK ─────────────────────────────────────────────────────────────────────

func (a *agent) cgkPaths() (aliases, rewrite string) {
	d := a.o.path(DnsdistDir)
	return filepath.Join(d, dnsconf.FileCGKAliases), filepath.Join(d, dnsconf.FileCGKRewrite)
}

// cgkFiles reads the status of the lists on disk (used at start-up).
func (a *agent) cgkFiles() api.CGKStatus {
	al, rw := a.cgkPaths()
	s := api.CGKStatus{Aliases: len(cgk.ReadList(al)), RewriteRanges: len(cgk.ReadList(rw))}
	if fi, err := os.Stat(al); err == nil {
		t := fi.ModTime().UTC()
		s.LastRefresh = &t
	}
	return s
}

// cgkLoop refreshes every spec.cgk.refresh_interval_h (measured from the last
// refresh, which survives agent restarts via the file mtime) and on command.
func (a *agent) cgkLoop(ctx context.Context) {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.cgkNow:
		}
		wait := a.cgkDue()
		if wait == 0 {
			a.refreshCGK(ctx)
			wait = a.cgkDue()
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(max(wait, time.Minute))
	}
}

// cgkDue returns how long until the next refresh (0 = now); 1 h when CGK is off or
// no config is known yet.
func (a *agent) cgkDue() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg == nil || !a.cfg.Spec.CGK.Enabled || a.applied == 0 {
		return time.Hour
	}
	iv := time.Duration(max(a.cfg.Spec.CGK.RefreshIntervalH, 1)) * time.Hour
	if a.cgkForce || a.cgkStatus.LastRefresh == nil {
		return 0
	}
	return max(time.Until(a.cgkStatus.LastRefresh.Add(iv)), 0)
}

func (a *agent) refreshCGK(ctx context.Context) {
	cfg := a.config()
	spec := cfg.Spec.CGK
	aliasFile, rewriteFile := a.cgkPaths()
	now := time.Now().UTC()
	a.o.Log.Info("cgk refresh started")
	res, err := cgk.Measure(ctx, spec, cgk.NetProber{}, cgk.ReadList(rewriteFile), cgk.ReadList(aliasFile), rand.New(rand.NewPCG(uint64(now.UnixNano()), 0)))
	if ctx.Err() != nil {
		return
	}
	rep := api.CGKReport{MeasuredAt: now, OK: err == nil, Aliases: []string{}, RewriteRanges: []string{}, Pools: []api.CGKPool{}}
	if res != nil {
		rep.Pools = res.Pools
	}
	if err == nil {
		rep.Aliases, rep.RewriteRanges = res.Aliases, res.Rewrite
		err = errors.Join(
			apply.WriteFile(aliasFile, cgk.Format("Cloudflare IPs served from CGK, verified against real sites", now, res.Aliases), 0o644),
			apply.WriteFile(rewriteFile, cgk.Format("Cloudflare pools served outside CGK from this server", now, res.Rewrite), 0o644),
		)
		if err == nil {
			out, cerr := dnsdist.Console(ctx, a.app.Conf(), "cgkReload()")
			switch {
			case errors.Is(cerr, dnsdist.ErrNoBinary) && a.o.NoSystemd:
				rep.Message = "lists written; dnsdist not installed (test mode)"
			case cerr != nil:
				err = fmt.Errorf("cgkReload(): %w", cerr)
			default:
				rep.Message = out
			}
		}
		rep.OK = err == nil
	}
	if err != nil {
		rep.Message = err.Error()
		a.o.Log.Warn("cgk refresh failed", "err", err)
	} else {
		a.o.Log.Info("cgk refresh done", "aliases", len(res.Aliases), "rewrite", res.Rewrite)
	}

	a.mu.Lock()
	st := a.cgkFiles()
	st.LastRefresh = &now // also after a failure: retry at the next interval, not in a loop
	if err != nil {
		st.LastError = err.Error()
	}
	a.cgkStatus, a.cgkForce = st, false
	a.mu.Unlock()
	if perr := a.cl.PostCGK(ctx, rep); perr != nil && ctx.Err() == nil {
		a.o.Log.Warn("posting cgk report failed", "err", perr)
	}
}
