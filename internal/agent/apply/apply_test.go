package apply

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/dnsconf"
)

// fakeDnsdist fails --check-config for configs containing CHECKFAIL and the console
// (showVersion) for configs containing CONSOLEFAIL; every call is logged.
const fakeDnsdist = `#!/bin/sh
echo "$@" >> "$FAKE_LOG"
while [ $# -gt 0 ]; do
  case "$1" in
    -C) conf="$2"; shift ;;
    --check-config) check=1 ;;
    -e) cmd="$2"; shift ;;
  esac
  shift
done
if [ -n "$check" ]; then
  grep -q CHECKFAIL "$conf" && { echo "Fatal Lua error: boom"; exit 1; }
  echo "Configuration '$conf' OK!"; exit 0
fi
if [ -n "$cmd" ]; then
  grep -q CONSOLEFAIL "$conf" && { echo "Connection refused"; exit 1; }
  echo "dnsdist 2.0.10"; exit 0
fi
exit 0
`

func setup(t *testing.T, withBinary bool) (*Applier, string) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	os.MkdirAll(bin, 0o755)
	if withBinary {
		if err := os.WriteFile(filepath.Join(bin, "dnsdist"), []byte(fakeDnsdist), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(root, "calls.log")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+"/bin:/usr/bin")
	t.Setenv("FAKE_LOG", log)
	a := &Applier{
		Dir: filepath.Join(root, "etc/dnsdist"), BackupDir: filepath.Join(root, "var/lib/dnsjos/backup"),
		NoSystemd: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Verify: 1500 * time.Millisecond,
	}
	return a, log
}

func rt(root string) api.NodeRuntime {
	return api.NodeRuntime{ConsoleKey: "a2V5", WebPassword: "pw", WebAPIKey: "ak", CDBPath: root + "/current.cdb", Hostname: "n1"}
}

func spec(extra string) api.ConfigSpec {
	s := api.DefaultConfigSpec()
	s.Tuning.ExtraLua = extra
	return s
}

func read(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func backups(t *testing.T, a *Applier) int {
	e, _ := os.ReadDir(a.BackupDir)
	return len(e)
}

func TestApplyCheckSwapRollback(t *testing.T) {
	a, log := setup(t, true)
	ctx := context.Background()
	os.MkdirAll(a.Dir, 0o755)
	os.WriteFile(a.Conf(), []byte("-- packaged dnsdist.conf\n"), 0o640)

	changed, err := a.Apply(ctx, spec("-- v1"), rt(a.Dir), false)
	if err != nil || !changed {
		t.Fatalf("v1: %v %v", changed, err)
	}
	conf := read(t, a.Conf())
	if !strings.Contains(conf, "-- v1") || !strings.Contains(conf, `dofile("`+a.Dir+`/dnsjos/blocking.lua")`) {
		t.Fatalf("live conf must point at the live dir:\n%s", conf)
	}
	calls := read(t, log)
	if !strings.Contains(calls, "--check-config -C "+filepath.Join(a.Dir, StagingName, "dnsdist.conf")) ||
		!strings.Contains(calls, "-C "+a.Conf()+" -c -e showVersion()") {
		t.Fatalf("expected staging check and console verify, got:\n%s", calls)
	}
	if _, err := os.Stat(filepath.Join(a.Dir, StagingName)); !os.IsNotExist(err) {
		t.Fatal("staging dir left behind")
	}
	if b := backups(t, a); b != 1 {
		t.Fatalf("backups = %d", b)
	}
	if got := read(t, filepath.Join(a.BackupDir, mustOnly(t, a.BackupDir), "dnsdist.conf")); got != "-- packaged dnsdist.conf\n" {
		t.Fatalf("backup holds %q", got)
	}
	if fi, _ := os.Stat(a.Conf()); fi.Mode().Perm() != 0o640 {
		t.Fatalf("conf mode %v, want 0640 (it holds the console key)", fi.Mode().Perm())
	}

	// unchanged → nothing happens; forced → re-applied
	if changed, err := a.Apply(ctx, spec("-- v1"), rt(a.Dir), false); err != nil || changed {
		t.Fatalf("same spec: %v %v", changed, err)
	}
	if changed, err := a.Apply(ctx, spec("-- v1"), rt(a.Dir), true); err != nil || !changed {
		t.Fatalf("forced: %v %v", changed, err)
	}

	// check-config failure: live files untouched, no backup taken
	nb := backups(t, a)
	if _, err := a.Apply(ctx, spec("-- CHECKFAIL"), rt(a.Dir), false); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want check-config error, got %v", err)
	}
	if !strings.Contains(read(t, a.Conf()), "-- v1") || backups(t, a) != nb {
		t.Fatal("failed check must not touch the live config")
	}

	// dnsdist does not come back → rollback to v1 (whose console answers)
	s := spec("-- CONSOLEFAIL")
	s.CGK.Enabled = false
	_, err = a.Apply(ctx, s, rt(a.Dir), false)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("want rollback, got %v", err)
	}
	if !strings.Contains(read(t, a.Conf()), "-- v1") {
		t.Fatal("live config not restored")
	}
	if _, err := os.Stat(filepath.Join(a.Dir, dnsconf.FileCGK)); err != nil {
		t.Fatal("cgk.lua (removed by the failed config) not restored")
	}

	// a disabled feature's module is removed; backups are capped at 5
	for i := range 6 {
		s := spec("-- round " + string(rune('a'+i)))
		s.CGK.Enabled = false
		if _, err := a.Apply(ctx, s, rt(a.Dir), false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(a.Dir, dnsconf.FileCGK)); !os.IsNotExist(err) {
		t.Fatal("cgk.lua should be gone")
	}
	if b := backups(t, a); b != keepBackups {
		t.Fatalf("backups = %d, want %d", b, keepBackups)
	}
}

func TestApplyWithoutDnsdistInTestMode(t *testing.T) {
	a, _ := setup(t, false)
	if changed, err := a.Apply(context.Background(), spec(""), rt(a.Dir), false); err != nil || !changed {
		t.Fatalf("test mode without dnsdist: %v %v", changed, err)
	}
	a.NoSystemd = false
	if _, err := a.Apply(context.Background(), spec("-- x"), rt(a.Dir), false); err == nil {
		t.Fatal("production mode must refuse to apply unchecked config")
	}
}

func mustOnly(t *testing.T, dir string) string {
	e, err := os.ReadDir(dir)
	if err != nil || len(e) != 1 {
		t.Fatalf("want one entry in %s: %v %v", dir, e, err)
	}
	return e[0].Name()
}

// TestPreAdoptSnapshot: the first apply over a foreign config archives the whole dir
// and a failed first apply restores exactly that tree.
func TestPreAdoptSnapshot(t *testing.T) {
	a, _ := setup(t, true)
	a.PreAdoptDir = filepath.Join(filepath.Dir(a.BackupDir), "state")
	ctx := context.Background()
	tree := map[string]string{
		"dnsdist.conf": "-- ootb\n", "dnsdist.yml": "admin: {}\n", "cgk.lua": "-- old\n", "db/blacklist.db": "cdb",
	}
	for rel, body := range tree {
		os.MkdirAll(filepath.Dir(filepath.Join(a.Dir, rel)), 0o755)
		os.WriteFile(filepath.Join(a.Dir, rel), []byte(body), 0o640)
	}
	os.Symlink("dnsdist.yml", filepath.Join(a.Dir, "link.yml"))
	snaps := func() []string { m, _ := filepath.Glob(filepath.Join(a.PreAdoptDir, "pre-adopt-*.tar.gz")); return m }

	if _, err := a.Apply(ctx, spec("-- CONSOLEFAIL"), rt(a.Dir), false); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("want rollback, got %v", err)
	}
	if len(snaps()) != 1 {
		t.Fatalf("snapshots: %v", snaps())
	}
	var got []string
	filepath.WalkDir(a.Dir, func(p string, d os.DirEntry, err error) error {
		rel, _ := filepath.Rel(a.Dir, p)
		got = append(got, rel)
		return nil
	})
	if strings.Join(got, " ") != ". cgk.lua db db/blacklist.db dnsdist.conf dnsdist.yml link.yml" {
		t.Fatalf("tree after rollback: %v", got)
	}
	for rel, body := range tree {
		if read(t, filepath.Join(a.Dir, rel)) != body {
			t.Fatalf("%s not restored", rel)
		}
	}
	if l, _ := os.Readlink(filepath.Join(a.Dir, "link.yml")); l != "dnsdist.yml" {
		t.Fatalf("symlink not restored: %q", l)
	}

	if changed, err := a.Apply(ctx, spec("-- v1"), rt(a.Dir), false); err != nil || !changed {
		t.Fatalf("v1: %v %v", changed, err)
	}
	if _, err := a.Apply(ctx, spec("-- v2"), rt(a.Dir), false); err != nil {
		t.Fatal(err)
	}
	if len(snaps()) != 2 { // one per foreign-config attempt, none once dnsjos owns the conf
		t.Fatalf("snapshots: %v", snaps())
	}
}
