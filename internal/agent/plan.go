package agent

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/billyriantono/dnsjos/internal/agent/apply"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Plan fetches the node's effective config, renders it into the staging dir, runs
// dnsdist --check-config and prints a summary plus a unified diff against the live
// files. It never swaps files or restarts dnsdist (SPEC §17).
func Plan(ctx context.Context, o Options, w io.Writer) error {
	a, err := newAgent(ctx, o)
	if err != nil {
		return err
	}
	cfg, err := a.cl.Config(ctx, 0)
	if errorCode(err) == "no_blocklist" && a.seedCDB() {
		// The panel hands out the config once it knows about the seeded CDB.
		ack, herr := a.cl.Heartbeat(ctx, a.collectHeartbeat(ctx))
		if herr != nil {
			return fmt.Errorf("reporting the seeded blocklist: %w", herr)
		}
		if len(ack.Commands) > 0 {
			fmt.Fprintf(w, "warning: %d queued command(s) were delivered to `plan` and ignored; queue them again\n", len(ack.Commands))
		}
		cfg, err = a.cl.Config(ctx, 0)
	}
	if err != nil {
		return fmt.Errorf("fetching config: %w", err)
	}
	if cfg == nil {
		return fmt.Errorf("fetching config: unexpected 304")
	}
	fmt.Fprint(w, summary(cfg, a.bl.Local(), a.o.path(CDBPath)))

	files, err := a.app.Stage(ctx, cfg.Spec, a.runtime())
	staging := filepath.Join(a.app.Dir, apply.StagingName)
	if err != nil {
		fmt.Fprintf(w, "check-config: FAILED (staged files kept in %s)\n", staging)
		return err
	}
	fmt.Fprintf(w, "check-config: OK (staged in %s)\n\n", staging)

	names := make([]string, 0, len(apply.Managed))
	for _, rel := range apply.Managed {
		if _, ok := files[rel]; ok || exists(filepath.Join(a.app.Dir, rel)) {
			names = append(names, rel)
		}
	}
	changed := 0
	for _, rel := range names {
		d, err := unifiedDiff(ctx, filepath.Join(a.app.Dir, rel), rel, files[rel], files[rel] != nil)
		if err != nil {
			return err
		}
		if d != "" {
			changed++
			fmt.Fprint(w, d)
		}
	}
	if changed == 0 {
		fmt.Fprintln(w, "no changes: the live files already match")
	} else {
		fmt.Fprintf(w, "\n%d file(s) would change; `dnsjos-agent run` applies them and restarts dnsdist\n", changed)
	}
	return nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// unifiedDiff runs diff -u between the live file (or /dev/null) and the new content
// (removed when !keep). "" when equal.
func unifiedDiff(ctx context.Context, cur, rel string, next []byte, keep bool) (string, error) {
	old := cur
	if !exists(cur) {
		old = os.DevNull
	}
	newPath := "-"
	if !keep {
		newPath = os.DevNull
	}
	cmd := exec.CommandContext(ctx, "diff", "-u", "--label", "live/"+rel, "--label", "new/"+rel, old, newPath)
	cmd.Stdin = bytes.NewReader(next)
	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
		return string(out), nil
	}
	if err != nil {
		return "", fmt.Errorf("diff %s: %w", rel, err)
	}
	return "", nil
}

func summary(cfg *api.AgentConfig, sha, cdb string) string {
	s := cfg.Spec
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	onoff := func(on bool) string {
		if on {
			return "on"
		}
		return "off"
	}
	l := s.Listen
	p("config:     v%d (profile %s)", cfg.Version, cfg.Profile)
	if l.Do53.Enabled {
		p("do53:       %s (x%d reuseport)", strings.Join(l.Do53.Addresses, ", "), l.Do53.ReusePortListeners)
	} else {
		p("do53:       off")
	}
	if l.DoH.Enabled {
		p("doh:        %s path %s", strings.Join(l.DoH.Addresses, ", "), l.DoH.Path)
	} else {
		p("doh:        off")
	}
	if l.DoT.Enabled {
		p("dot:        %s", strings.Join(l.DoT.Addresses, ", "))
	} else {
		p("dot:        off")
	}
	if l.DoH.Enabled || l.DoT.Enabled {
		p("tls:        cert %s key %s", l.TLS.CertFile, l.TLS.KeyFile)
	}
	p("acl:        %d prefixes", len(s.ACL))
	ups := make([]string, 0, len(s.Upstreams.Servers))
	for _, u := range s.Upstreams.Servers {
		ups = append(ups, fmt.Sprintf("%s w%d o%d", u.Address, u.Weight, u.Order))
	}
	p("upstreams:  %s: %s", s.Upstreams.Policy, strings.Join(ups, ", "))
	p("cache:      %s (max %d, stale_ttl %ds)", onoff(s.Cache.Enabled), s.Cache.MaxEntries, s.Cache.StaleTTL)
	bl := s.Blocking
	p("blocking:   %s (blockpage %s / %s, response IPs %s, dnstap %s)", onoff(bl.Enabled), bl.BlockpageIPv4, bl.BlockpageIPv6,
		onoff(bl.BlockResponseIPs), onoff(bl.LogBlocked))
	if sha == "" {
		sha = "MISSING"
	}
	p("blocklist:  %s (sha256 %s, panel %s)", cdb, sha, cmp.Or(cfg.Blocklist.SHA256, "none"))
	ab := s.Abuse
	p("abuse:      %s (%d qps / %d burst per client, dyn %d qps %d nxdomain/s %d servfail/s → %s %ds)", onoff(ab.Enabled),
		ab.PerClientQPS, ab.PerClientBurst, ab.DynQueryRate, ab.DynNXDomainRate, ab.DynServfailRate, ab.DynAction, ab.DynBlockS)
	p("cgk:        %s (%d rewrite pools, %d alias pools, every %dh)", onoff(s.CGK.Enabled), len(s.CGK.RewritePools),
		len(s.CGK.AliasPools), s.CGK.RefreshIntervalH)
	p("webserver:  %s (acl %s)", s.Webserver.Listen, strings.Join(s.Webserver.PrometheusACL, ", "))
	return b.String()
}
