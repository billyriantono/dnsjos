package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/colinmarc/cdb"
	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/agent/apply"
	"github.com/billyriantono/dnsjos/internal/agent/blocklist"
	"github.com/billyriantono/dnsjos/internal/agent/client"
	"github.com/billyriantono/dnsjos/internal/shared/api"
	keys "github.com/billyriantono/dnsjos/internal/shared/cdb"
)

const (
	testPolicy = `dnsdist:
  Installed: 2.0.1-1pdns.bookworm
  Candidate: 2.0.2-1pdns.bookworm
  Version table:
     2.0.2-1pdns.bookworm 600
        600 https://repo.powerdns.com/debian bookworm-dnsdist-20/main amd64 Packages
 *** 2.0.1-1pdns.bookworm 600
        600 https://repo.powerdns.com/debian bookworm-dnsdist-20/main amd64 Packages
        100 /var/lib/dpkg/status
     1.7.3-2 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages`
	testMadison = `   dnsdist | 2.1.0-1pdns.bookworm | https://repo.powerdns.com/debian bookworm-dnsdist-21/main amd64 Packages
   dnsdist | 2.0.2-1pdns.bookworm | https://repo.powerdns.com/debian bookworm-dnsdist-20/main amd64 Packages
   dnsdist | 2.0.1-1pdns.bookworm | https://repo.powerdns.com/debian bookworm-dnsdist-20/main amd64 Packages
   dnsdist | 2.0.0-1pdns.bookworm | https://repo.powerdns.com/debian bookworm-dnsdist-20/main amd64 Packages
   dnsdist |    1.7.3-2 | http://deb.debian.org/debian bookworm/main amd64 Packages`
)

func TestParseInventory(t *testing.T) {
	inv := parseInventory(testPolicy, testMadison, "20")
	want := []string{"2.0.2-1pdns.bookworm", "2.0.1-1pdns.bookworm", "2.0.0-1pdns.bookworm"}
	if inv.Candidate != "2.0.2-1pdns.bookworm" || !slices.Equal(inv.Available, want) || inv.Series != "20" {
		t.Fatalf("%+v", inv)
	}
	if inv := parseInventory("dnsdist:\n  Installed: (none)\n  Candidate: (none)\n", "", "21"); inv.Candidate != "" || inv.Available == nil {
		t.Fatalf("%+v", inv)
	}
}

// fakeNode puts fake apt-get/apt-cache/dpkg-query/systemctl/dnsdist on PATH. The
// installed version lives in $state/version; installing $FAKE_BAD makes dnsdist inactive.
func fakeNode(t *testing.T, bad string) (a *agent, state string) {
	bin, state, root := t.TempDir(), t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(state, "policy"), []byte(testPolicy), 0o644)
	os.WriteFile(filepath.Join(state, "madison"), []byte(testMadison), 0o644)
	os.WriteFile(filepath.Join(state, "version"), []byte("2.0.1-1pdns.bookworm"), 0o644)
	scripts := map[string]string{
		"apt-get": `echo "$DEBIAN_FRONTEND $*" >>"$S/log"
case "$1" in install) for a; do case "$a" in dnsdist=*) printf %s "${a#dnsdist=}" >"$S/version";; esac; done;; esac`,
		"apt-cache":  `cat "$S/$1"`,
		"dpkg-query": `cat "$S/version"`,
		"systemctl":  `echo "systemctl $*" >>"$S/log"; [ "$(cat "$S/version")" != "$FAKE_BAD" ]`,
		"dnsdist":    `case "$*" in *--version*) echo "dnsdist 2";; *-c*) echo "dnsdist 2";; esac`,
	}
	for n, s := range scripts {
		os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\n"+s+"\n"), 0o755)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("S", state)
	t.Setenv("FAKE_BAD", bad)

	os.MkdirAll(filepath.Join(root, AptSourcesDir), 0o755)
	os.MkdirAll(filepath.Join(root, AptPrefsDir), 0o755)
	os.WriteFile(filepath.Join(root, AptSourcesDir, "pdns-dnsdist.list"), []byte(
		"deb [signed-by=/etc/apt/keyrings/dnsdist-20-pub.asc] https://repo.powerdns.com/debian bookworm-dnsdist-20 main\n"), 0o644)
	os.WriteFile(filepath.Join(root, AptSourcesDir, "debian.list"), []byte("deb http://deb.debian.org/debian bookworm main\n"), 0o644)
	os.WriteFile(filepath.Join(root, AptPrefsDir, "dnsdist-20"), []byte("Package: dnsdist*\nPin: origin repo.powerdns.com\nPin-Priority: 600\n"), 0o644)

	// Local "dnsdist" listener: the blocklisted name gets the blockpage.
	spec := api.DefaultConfigSpec()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		ip := "198.51.100.1"
		if q.Question[0].Name == "blocked.example.net." {
			ip = spec.Blocking.BlockpageIPv4
		}
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A " + ip)
		r.Answer = append(r.Answer, rr)
		w.WriteMsg(r)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	spec.Listen.Do53.Addresses = []string{pc.LocalAddr().String()}

	o := Options{Root: root, Version: "1.0.0", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	os.MkdirAll(filepath.Dir(o.path(CDBPath)), 0o755)
	f, _ := os.Create(o.path(CDBPath))
	w, _ := cdb.NewWriter(f, nil)
	w.Put(keys.IPv4Key(netip.MustParseAddr("203.0.113.5")), nil)
	w.Put(keys.DomainKey("blocked.example.net"), nil)
	w.Close()

	a = &agent{o: o, run: execRunner, cfg: &api.AgentConfig{Spec: spec},
		app:   &apply.Applier{Dir: o.path(DnsdistDir), Log: o.Log, Verify: time.Second},
		hbNow: make(chan struct{}, 1), invNow: make(chan struct{}, 1)}
	if err := a.refreshInventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, state
}

func read(t *testing.T, p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func TestUpgradeDnsdist(t *testing.T) {
	a, state := fakeNode(t, "")
	if a.inv.Series != "20" || len(a.inv.Available) != 3 || a.inv.At == nil {
		t.Fatalf("inventory %+v", a.inv)
	}
	if !strings.Contains(read(t, filepath.Join(state, "log")), "update -q -o Dir::Etc::sourcelist="+a.o.path(AptSourcesDir+"/pdns-dnsdist.list")+
		" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0") {
		t.Fatalf("apt-get update: %s", read(t, filepath.Join(state, "log")))
	}
	if n := firstBlockedName(a.o.path(CDBPath)); n != "blocked.example.net." {
		t.Fatalf("first blocked name %q", n)
	}
	a.upgrade(func() *api.UpgradeResult { return a.upgradeDnsdist(context.Background(), "2.0.2-1pdns.bookworm") })
	r := a.lastUp
	if r == nil || !r.OK || r.From != "2.0.1-1pdns.bookworm" || r.To != "2.0.2-1pdns.bookworm" || r.Kind != api.UpgradeDnsdist {
		t.Fatalf("result %+v", r)
	}
	log := read(t, filepath.Join(state, "log"))
	if !strings.Contains(log, "noninteractive install -y -q --only-upgrade -o Dpkg::Options::=--force-confold dnsdist=2.0.2-1pdns.bookworm") ||
		strings.Contains(log, "allow-downgrades") || !strings.Contains(log, "systemctl is-active dnsdist") {
		t.Fatalf("log:\n%s", log)
	}
	if a.dnsdistVer != "2.0.2-1pdns.bookworm" || a.upgrading || !strings.Contains(read(t, a.o.path(LastUpgradePath)), `"ok":true`) {
		t.Fatalf("ver %q upgrading %v", a.dnsdistVer, a.upgrading)
	}
}

// TestCommandUpgradeIsAwaited: Run waits on a.ops, so a stopping agent never exits
// while apt/dpkg is installing dnsdist.
func TestCommandUpgradeIsAwaited(t *testing.T) {
	a, _ := fakeNode(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	a.command(ctx, api.Command{ID: 1, Type: api.CmdUpgradeDnsdist, Version: "2.0.2-1pdns.bookworm"})
	cancel() // SIGTERM right after the command arrived
	a.ops.Wait()
	if r := a.lastUp; r == nil || !r.OK {
		t.Fatalf("upgrade not finished when ops.Wait returned: %+v", r)
	}
}

func TestUpgradeDnsdistRollsBack(t *testing.T) {
	a, state := fakeNode(t, "2.0.2-1pdns.bookworm")
	r := a.upgradeDnsdist(context.Background(), "2.0.2-1pdns.bookworm")
	if r.OK || !strings.Contains(r.Error, "not active") || !strings.Contains(r.Error, "rolled back to 2.0.1-1pdns.bookworm") {
		t.Fatalf("result %+v", r)
	}
	if v := read(t, filepath.Join(state, "version")); v != "2.0.1-1pdns.bookworm" {
		t.Fatalf("installed %q", v)
	}
	if !strings.Contains(read(t, filepath.Join(state, "log")), "--allow-downgrades dnsdist=2.0.1-1pdns.bookworm") {
		t.Fatal(read(t, filepath.Join(state, "log")))
	}
}

func TestUpgradeDnsdistRefusesUnknown(t *testing.T) {
	a, state := fakeNode(t, "")
	for _, v := range []string{"2.1.0-1pdns.bookworm", "9.9.9", ""} { // other series, unknown, empty
		if r := a.upgradeDnsdist(context.Background(), v); r.OK || !strings.Contains(r.Error, "not available") {
			t.Fatalf("%q: %+v", v, r)
		}
	}
	if strings.Contains(read(t, filepath.Join(state, "log")), "install") {
		t.Fatal("apt-get install ran")
	}
	a.upgrading = true // a second upgrade is refused while one runs
	a.upgrade(func() *api.UpgradeResult { t.Fatal("ran concurrently"); return nil })
}

func TestSetSeries(t *testing.T) {
	a, _ := fakeNode(t, "")
	if _, err := a.setSeries(context.Background(), "19"); err == nil {
		t.Fatal("unsupported series accepted")
	}
	if from, err := a.setSeries(context.Background(), "21"); err != nil || from != "20" {
		t.Fatal(from, err)
	}
	if got := read(t, a.o.path(AptSourcesDir+"/pdns-dnsdist.list")); got !=
		"deb [signed-by=/etc/apt/keyrings/dnsdist-20-pub.asc] https://repo.powerdns.com/debian bookworm-dnsdist-21 main\n" {
		t.Fatalf("list: %q", got)
	}
	if _, err := os.Stat(a.o.path(AptPrefsDir + "/dnsdist-20")); !os.IsNotExist(err) {
		t.Fatal("old pin kept")
	}
	if !strings.Contains(read(t, a.o.path(AptPrefsDir+"/dnsdist-21")), "Pin: origin repo.powerdns.com") {
		t.Fatal("new pin missing")
	}
	if a.inv.Series != "21" || !slices.Equal(a.inv.Available, []string{"2.1.0-1pdns.bookworm"}) {
		t.Fatalf("inventory %+v", a.inv)
	}
	bk, _ := filepath.Glob(a.o.path(AptBackupDir + "/*/*"))
	if len(bk) != 2 {
		t.Fatalf("backups %v", bk)
	}

	// the command reports its outcome as last_upgrade {kind: series}
	for _, c := range []struct {
		series string
		ok     bool
	}{{"20", true}, {"19", false}} {
		a.lastUp = nil
		a.command(context.Background(), api.Command{ID: 1, Type: api.CmdSetDnsdistSeries, Series: c.series})
		var r *api.UpgradeResult
		for deadline := time.Now().Add(5 * time.Second); r == nil && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			a.mu.Lock()
			r = a.lastUp
			a.mu.Unlock()
		}
		if r == nil || r.Kind != api.UpgradeSeries || r.To != c.series || r.OK != c.ok || (r.Error != "") == c.ok || r.At.IsZero() ||
			(c.ok && r.From != "21") {
			t.Fatalf("series %s: %+v", c.series, r)
		}
	}
}

func TestUpgradeAgent(t *testing.T) {
	newBin := []byte("#!/bin/sh\necho new agent\n")
	sum := sha256.Sum256(newBin)
	good := hex.EncodeToString(sum[:])
	shaBody := good
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dl/agent/linux/"+runtime.GOARCH, func(w http.ResponseWriter, r *http.Request) { w.Write(newBin) })
	mux.HandleFunc("GET /dl/agent/linux/"+runtime.GOARCH+".sha256", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, shaBody+"  dnsjos-agent\n")
	})
	mux.HandleFunc("POST /agent/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "{}") })
	panel := httptest.NewServer(mux)
	defer panel.Close()

	t.Setenv("PATH", t.TempDir())
	exe := filepath.Join(t.TempDir(), "dnsjos-agent")
	os.WriteFile(exe, []byte("old"), 0o755)
	executable = func() (string, error) { return exe, nil }
	defer func() { executable = os.Executable }()
	root := t.TempDir()
	var cause error
	a := &agent{o: Options{Root: root, Version: "1.0.0", DnsdistWeb: "http://127.0.0.1:1", Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		cl: client.New(panel.URL, "tok", "1.0.0"), run: execRunner, hbNow: make(chan struct{}, 1),
		stop: func(err error) { cause = err }}
	a.app = &apply.Applier{Dir: a.o.path(DnsdistDir), Log: a.o.Log}
	a.bl = &blocklist.Syncer{Path: a.o.path(CDBPath)}

	shaBody = strings.Repeat("0", 64)
	a.upgrade(func() *api.UpgradeResult { return a.upgradeAgent(context.Background()) })
	if a.lastUp == nil || a.lastUp.OK || !strings.Contains(a.lastUp.Error, "sha256 mismatch") || cause != nil {
		t.Fatalf("mismatch: %+v", a.lastUp)
	}
	if read(t, exe) != "old" {
		t.Fatal("binary replaced despite the mismatch")
	}
	if _, err := os.Stat(exe + ".new"); !os.IsNotExist(err) {
		t.Fatal(".new left behind")
	}

	shaBody = good
	if r := a.upgradeAgent(context.Background()); r != nil || !errors.Is(cause, ErrRestart) {
		t.Fatalf("result %+v cause %v", r, cause)
	}
	if read(t, exe) != string(newBin) || read(t, exe+".prev") != "old" {
		t.Fatal("binary not swapped")
	}
	b := &agent{o: a.o}
	b.o.Version = "1.1.0"
	if err := upgradeGuard(b.o); err != nil {
		t.Fatal(err)
	}
	b.loadLastUpgrade()
	if b.marker == nil || b.marker.Starts != 1 || b.lastUp == nil || b.lastUp.OK {
		t.Fatalf("before the first heartbeat: marker %+v last %+v", b.marker, b.lastUp)
	}
	b.confirmUpgrade() // first successful heartbeat
	if r := b.lastUp; r == nil || !r.OK || r.Kind != api.UpgradeAgent || r.From != "1.0.0" || r.To != "1.1.0" {
		t.Fatalf("after restart: %+v", r)
	}
	if _, err := os.Stat(a.o.path(AgentMarkerPath)); !os.IsNotExist(err) {
		t.Fatal("marker kept")
	}
}

// TestUpgradeGuard: a new agent that keeps restarting without a successful heartbeat
// is replaced by the previous binary, which reports the failed upgrade.
func TestUpgradeGuard(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "dnsjos-agent")
	executable = func() (string, error) { return exe, nil }
	var execd string
	orig := reexec
	reexec = func(p string) error { execd = p; return nil }
	defer func() { executable, reexec = os.Executable, orig }()
	o := Options{Root: t.TempDir(), Version: "1.1.0", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	marker := func(at time.Time) {
		os.WriteFile(exe, []byte("new"), 0o755)
		os.WriteFile(exe+".prev", []byte("old"), 0o755)
		writePrivate(o.path(AgentMarkerPath), []byte(`{"kind":"agent","from":"1.0.0","at":"`+at.Format(time.RFC3339)+`"}`))
	}

	marker(time.Now().Add(-10 * time.Minute)) // outside the window: never rolls back
	for range 6 {
		upgradeGuard(o)
	}
	if execd != "" || read(t, exe) != "new" {
		t.Fatal("rolled back outside the crash window")
	}

	marker(time.Now())
	for i := range crashStarts {
		if upgradeGuard(o); execd != "" {
			t.Fatalf("rolled back after %d starts", i+1)
		}
	}
	upgradeGuard(o)
	if real, _ := filepath.EvalSymlinks(exe); execd != real || read(t, exe) != "old" {
		t.Fatalf("exec %q, binary %q", execd, read(t, exe))
	}
	if _, err := os.Stat(o.path(AgentMarkerPath)); !os.IsNotExist(err) {
		t.Fatal("marker kept")
	}
	a := &agent{o: o}
	a.o.Version = "1.0.0"
	a.loadLastUpgrade()
	if r := a.lastUp; r == nil || r.OK || r.Kind != api.UpgradeAgent || r.From != "1.0.0" || r.To != "1.1.0" ||
		!strings.Contains(r.Error, "restored 1.0.0") || a.marker != nil {
		t.Fatalf("reported %+v", r)
	}
}
