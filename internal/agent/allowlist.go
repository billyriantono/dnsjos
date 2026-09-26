package agent

import (
	"cmp"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/billyriantono/dnsjos/internal/agent/apply"
	"github.com/billyriantono/dnsjos/internal/agent/client"
	"github.com/billyriantono/dnsjos/internal/agent/dnsdist"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/dnsconf"
)

// wantAllowlist records the allowlist version announced in a heartbeat ack ("" from a
// panel without allowlist support) and wakes the allowlist loop when it is new.
func (a *agent) wantAllowlist(v string) {
	a.mu.Lock()
	a.allowWant = cmp.Or(v, a.allowWant)
	stale := a.allowWant != a.allowHave
	a.mu.Unlock()
	if stale {
		poke(a.alNow)
	}
}

// allowlistLoop fetches the allowlist once the first config is known and whenever the
// panel announces a new version, retrying every poll interval until it is applied.
func (a *agent) allowlistLoop(ctx context.Context) {
	every(ctx, func() time.Duration { return api.DefaultPollS * time.Second }, a.alNow, func() { a.syncAllowlist(ctx) })
}

// syncAllowlist writes the allowlist files for blocking.lua and calls
// dnsjosAllowReload() on the running dnsdist (no restart).
func (a *agent) syncAllowlist(ctx context.Context) {
	a.mu.Lock()
	want, have, old, cfg := a.allowWant, a.allowHave, a.allowOld, a.cfg
	a.mu.Unlock()
	// Without a config the running dnsdist may not have blocking.lua yet.
	if cfg == nil || want == have && (have != "" || old) {
		return
	}
	al, err := a.cl.Allowlist(ctx, have)
	var se *client.StatusError
	switch {
	case errors.As(err, &se) && se.Code == 404: // older panel: wait until one announces a version
		a.mu.Lock()
		a.allowOld = true
		a.mu.Unlock()
		return
	case err != nil:
		if ctx.Err() == nil {
			a.o.Log.Warn("fetching allowlist failed", "err", err)
		}
		return
	case al == nil: // 304: what we enforce is current, the announced version was stale
		a.mu.Lock()
		a.allowWant = have
		a.mu.Unlock()
		return
	}
	dir := a.o.path(DnsdistDir)
	lines := func(l []string) []byte {
		if len(l) == 0 {
			return nil
		}
		return []byte(strings.Join(l, "\n") + "\n")
	}
	if err := errors.Join(
		apply.WriteFile(filepath.Join(dir, dnsconf.FileAllowDomains), lines(al.Domains), 0o644),
		apply.WriteFile(filepath.Join(dir, dnsconf.FileAllowIPs), lines(al.IPs), 0o644),
	); err != nil {
		a.o.Log.Error("writing allowlist failed", "err", err)
		return
	}
	msg := "blocking disabled"
	if cfg.Spec.Blocking.Enabled {
		msg, err = dnsdist.Console(ctx, a.app.Conf(), "dnsjosAllowReload()")
		if err == nil && !strings.Contains(msg, "allowlist: ") { // a Lua error still exits 0
			err = errors.New(msg)
		}
		switch {
		case errors.Is(err, dnsdist.ErrNoBinary) && a.o.NoSystemd:
			msg = "dnsdist not installed (test mode)"
		case err != nil:
			if ctx.Err() == nil {
				a.o.Log.Warn("dnsjosAllowReload() failed, retrying", "version", al.Version, "err", err)
			}
			return
		}
	}
	a.mu.Lock()
	a.allowHave = al.Version
	if a.allowWant == "" {
		a.allowWant = al.Version
	}
	a.mu.Unlock()
	a.o.Log.Info("allowlist applied", "version", al.Version, "domains", len(al.Domains), "ips", len(al.IPs), "dnsdist", msg)
	poke(a.hbNow)
}
