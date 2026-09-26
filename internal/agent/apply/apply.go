// Package apply installs a rendered dnsdist config: render → check in a staging
// dir → back up → swap → restart → verify → roll back on failure (SPEC §9.1).
package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/billyriantono/dnsjos/internal/agent/dnsdist"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/dnsconf"
)

// Managed are the files the agent owns under the dnsdist dir (the CGK txt files
// belong to the prober and are never touched here).
var Managed = []string{dnsconf.FileConf, dnsconf.FileBlocking, dnsconf.FileAbuse, dnsconf.FileCGK}

const (
	StagingName = ".dnsjos-staging"
	keepBackups = 5
)

type Applier struct {
	Dir       string // /etc/dnsdist (root-prefixed in test mode)
	BackupDir string // /var/lib/dnsjos/backup
	NoSystemd bool   // test mode: no systemctl; no dnsdist binary → skip check/verify
	Log       *slog.Logger
	Verify    time.Duration // how long to wait for the console after a restart; default 20 s
	// PreAdoptDir receives the pre-adopt-<ts>.tar.gz snapshot of Dir taken before the
	// first apply over a foreign config ("" = no snapshot).
	PreAdoptDir string
}

// Conf is the path of the live dnsdist.conf.
func (a *Applier) Conf() string { return filepath.Join(a.Dir, dnsconf.FileConf) }

// Stage renders spec into Dir/.dnsjos-staging (module paths pointing there) and runs
// dnsdist --check-config on it. It returns the files as they are installed in Dir. The
// staging dir is left for inspection (`dnsjos-agent plan`); Apply removes it.
func (a *Applier) Stage(ctx context.Context, spec api.ConfigSpec, rt api.NodeRuntime) (map[string][]byte, error) {
	staging := filepath.Join(a.Dir, StagingName)
	rt.BaseDir = staging
	files, err := dnsconf.Render(spec, rt)
	if err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	os.RemoveAll(staging)
	gid, mode := a.owner()
	for rel, b := range files {
		if err := writeFile(filepath.Join(staging, rel), b, mode, gid); err != nil {
			return nil, err
		}
	}
	if err := a.check(ctx, filepath.Join(staging, dnsconf.FileConf)); err != nil {
		return nil, err
	}
	rt.BaseDir = a.Dir
	if files, err = dnsconf.Render(spec, rt); err != nil {
		return nil, fmt.Errorf("render: %w", err)
	}
	return files, nil
}

// Apply installs spec. It returns false without touching anything when the rendered
// files equal the installed ones and force is not set.
func (a *Applier) Apply(ctx context.Context, spec api.ConfigSpec, rt api.NodeRuntime, force bool) (bool, error) {
	defer os.RemoveAll(filepath.Join(a.Dir, StagingName))
	files, err := a.Stage(ctx, spec, rt)
	if err != nil {
		return false, err
	}
	if !force && a.installed(files) {
		return false, nil
	}
	snap, err := a.preAdopt()
	if err != nil {
		return false, fmt.Errorf("pre-adopt snapshot: %w", err)
	}
	backup, err := a.backup()
	if err != nil {
		return false, fmt.Errorf("backup: %w", err)
	}
	gid, mode := a.owner()
	err = a.swap(files, mode, gid)
	if err == nil {
		err = a.Restart(ctx)
	}
	if err == nil {
		return true, nil
	}
	a.Log.Error("applying config failed, rolling back", "err", err, "backup", backup, "pre_adopt", snap)
	var rerr error
	if snap != "" {
		rerr = restoreSnapshot(a.Dir, snap)
	} else {
		rerr = a.restore(backup, mode, gid)
	}
	if rerr != nil {
		return false, fmt.Errorf("%w; rollback failed: %v", err, rerr)
	}
	if rerr := a.Restart(ctx); rerr != nil {
		a.Log.Error("dnsdist did not come back after rollback", "err", rerr)
		return false, fmt.Errorf("%w; after rollback: %v", err, rerr)
	}
	return false, fmt.Errorf("%w (rolled back)", err)
}

// preAdopt archives the whole dnsdist dir to PreAdoptDir/pre-adopt-<ts>.tar.gz when the
// live dnsdist.conf was not written by dnsjos (first apply on an adopted or freshly
// installed node, SPEC §17). It returns "" when there is nothing to adopt.
func (a *Applier) preAdopt() (string, error) {
	b, err := os.ReadFile(a.Conf())
	if a.PreAdoptDir == "" || err != nil || bytes.HasPrefix(b, []byte(dnsconf.Header)) {
		return "", nil
	}
	p := filepath.Join(a.PreAdoptDir, "pre-adopt-"+time.Now().UTC().Format("20060102T150405.000Z")+".tar.gz")
	a.Log.Info("first apply over a foreign dnsdist config: archiving "+a.Dir, "snapshot", p)
	return p, snapshot(a.Dir, p)
}

// check validates conf with dnsdist --check-config.
func (a *Applier) check(ctx context.Context, conf string) error {
	err := dnsdist.CheckConfig(ctx, conf)
	if errors.Is(err, dnsdist.ErrNoBinary) && a.NoSystemd {
		a.Log.Warn("dnsdist not installed, skipping --check-config (test mode)")
		return nil
	}
	if err != nil {
		return fmt.Errorf("check-config: %w", err)
	}
	return nil
}

// Restart restarts dnsdist and waits until its console answers.
func (a *Applier) Restart(ctx context.Context) error {
	if !a.NoSystemd {
		rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		out, err := exec.CommandContext(rctx, "systemctl", "restart", "dnsdist").CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("systemctl restart dnsdist: %w: %s", err, bytes.TrimSpace(out))
		}
	}
	return a.WaitConsole(ctx)
}

// WaitConsole waits up to Verify (20 s) until the dnsdist console answers showVersion().
func (a *Applier) WaitConsole(ctx context.Context) error {
	wait := a.Verify
	if wait <= 0 {
		wait = 20 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		_, err := dnsdist.Console(ctx, a.Conf(), "showVersion()")
		if err == nil {
			return nil
		}
		if errors.Is(err, dnsdist.ErrNoBinary) && a.NoSystemd {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("dnsdist console not answering: %w", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

func (a *Applier) installed(files map[string][]byte) bool {
	for rel, b := range files {
		cur, err := os.ReadFile(filepath.Join(a.Dir, rel))
		if err != nil || !bytes.Equal(cur, b) {
			return false
		}
	}
	return true
}

func (a *Applier) swap(files map[string][]byte, mode os.FileMode, gid int) error {
	for _, rel := range Managed {
		p := filepath.Join(a.Dir, rel)
		b, ok := files[rel]
		if !ok { // module of a feature that is now off
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		if err := writeFile(p, b, mode, gid); err != nil {
			return err
		}
	}
	return nil
}

// backup copies the managed files that exist into BackupDir/<timestamp>/ and keeps the newest five.
func (a *Applier) backup() (string, error) {
	dir := filepath.Join(a.BackupDir, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, rel := range Managed {
		b, err := os.ReadFile(filepath.Join(a.Dir, rel))
		if os.IsNotExist(err) {
			continue
		}
		if err == nil {
			err = writeFile(filepath.Join(dir, rel), b, 0o600, -1)
		}
		if err != nil {
			return "", err
		}
	}
	if ents, err := os.ReadDir(a.BackupDir); err == nil && len(ents) > keepBackups {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, n := range names[:len(names)-keepBackups] {
			os.RemoveAll(filepath.Join(a.BackupDir, n))
		}
	}
	return dir, nil
}

// restore puts the backed-up files back; managed files absent from the backup are removed.
func (a *Applier) restore(dir string, mode os.FileMode, gid int) error {
	for _, rel := range Managed {
		p := filepath.Join(a.Dir, rel)
		b, err := os.ReadFile(filepath.Join(dir, rel))
		switch {
		case os.IsNotExist(err):
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return err
			}
		case err != nil:
			return err
		default:
			if err := writeFile(p, b, mode, gid); err != nil {
				return err
			}
		}
	}
	return nil
}

// owner picks the group and mode for rendered files: dnsdist runs as _dnsdist and the
// files carry the console key, so 0640 with the group of the existing dnsdist.conf
// (or _dnsdist); 0644 when no such group exists.
func (a *Applier) owner() (int, os.FileMode) {
	if fi, err := os.Stat(a.Conf()); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return int(st.Gid), 0o640
		}
	}
	if g, err := user.LookupGroup("_dnsdist"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			return gid, 0o640
		}
	}
	return -1, 0o644
}

// writeFile writes atomically (tmp + rename) with mode and, when gid >= 0, that group.
func writeFile(p string, b []byte, mode os.FileMode, gid int) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".dnsjos-tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, mode) // umask
	}
	if err == nil && gid >= 0 {
		_ = os.Chown(tmp, -1, gid) // best effort: fails harmlessly when not root (test mode)
	}
	if err == nil {
		err = os.Rename(tmp, p)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// WriteFile is writeFile for the agent's other files under the dnsdist dir.
func WriteFile(p string, b []byte, mode os.FileMode) error { return writeFile(p, b, mode, -1) }
