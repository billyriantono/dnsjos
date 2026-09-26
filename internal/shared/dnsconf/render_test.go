package dnsconf

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

var testRT = api.NodeRuntime{
	ConsoleKey: "Y29uc29sZS1rZXktMzItYnl0ZXMtLS0tLS0tLS0tLS0=", WebPassword: "web-pass", WebAPIKey: "api-key",
	Hostname: "dns1.example",
}

func TestGolden(t *testing.T) {
	cases := map[string]func(s *api.ConfigSpec){
		"defaults": func(*api.ConfigSpec) {},
		"doh_dot": func(s *api.ConfigSpec) {
			s.Listen.DoH.Enabled, s.Listen.DoT.Enabled = true, true
			s.Listen.Do53.ReusePortListeners = 2
			s.Tuning.TCPWorkers = 8
		},
		"abuse_off": func(s *api.ConfigSpec) { s.Abuse.Enabled = false },
		"cgk_off":   func(s *api.ConfigSpec) { s.CGK.Enabled = false },
		"weights": func(s *api.ConfigSpec) {
			s.Upstreams.Policy = "wrandom"
			s.Upstreams.Servers = []api.Upstream{
				{Address: "10.0.0.1:53", Weight: 70, Order: 1, Sockets: 2, Name: "a"},
				{Address: "[2001:db8::1]:5353", Weight: 30, Order: 2, Sockets: 1},
			}
			s.Blocking.BlockResponseIPs, s.Blocking.LogBlocked = false, false
			s.Cache.Enabled = false
			s.Analytics.Enabled = false
		},
		"analytics_sampled": func(s *api.ConfigSpec) {
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled = false, false, false
			s.Analytics.SampleRate, s.Analytics.StreamAddr = 10, "[::1]:6101"
		},
		"extra_lua": func(s *api.ConfigSpec) {
			s.Tuning.ExtraLua = "-- custom\nsetVerbose(true)\n"
			s.Blocking.TXT = `He said "hi" \ bye`
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			spec := api.DefaultConfigSpec()
			mut(&spec)
			files, err := Render(spec, testRT)
			if err != nil {
				t.Fatal(err)
			}
			again, _ := Render(spec, testRT)
			var got bytes.Buffer
			keys := make([]string, 0, len(files))
			for k := range files {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				if !bytes.Equal(files[k], again[k]) {
					t.Fatalf("%s: not deterministic", k)
				}
				got.WriteString("==> " + k + " <==\n")
				got.Write(files[k])
			}
			golden := filepath.Join("testdata", name+".golden")
			if *update {
				os.MkdirAll("testdata", 0o755)
				if err := os.WriteFile(golden, got.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Errorf("%s differs from golden (run with -update)\n%s", name, got.String())
			}
		})
	}
}

func TestModulesFollowSpec(t *testing.T) {
	spec := api.DefaultConfigSpec()
	spec.Blocking.Enabled, spec.Abuse.Enabled, spec.CGK.Enabled, spec.Analytics.Enabled = false, false, false, false
	files, err := Render(spec, api.NodeRuntime{ConsoleKey: "k", WebPassword: "p", WebAPIKey: "a", BaseDir: "/tmp/stage/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || strings.Contains(string(files[FileConf]), "dofile") || strings.Contains(string(files[FileConf]), "Dnstap") {
		t.Fatalf("disabled modules rendered: %v", files)
	}
	spec = api.DefaultConfigSpec()
	files, _ = Render(spec, api.NodeRuntime{ConsoleKey: "k", WebPassword: "p", WebAPIKey: "a", BaseDir: "/tmp/stage/"})
	conf := string(files[FileConf])
	for _, want := range []string{`dofile("/tmp/stage/dnsjos/blocking.lua")`, `dofile("/tmp/stage/dnsjos/cgk.lua")`} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %s", want)
		}
	}
	if !strings.Contains(string(files[FileCGK]), `"/tmp/stage/dnsjos/cgk-aliases.txt"`) {
		t.Error("cgk data files not rooted at base_dir")
	}
	if _, err := Render(spec, api.NodeRuntime{}); err == nil {
		t.Error("missing secrets accepted")
	}
	spec.Analytics.StreamAddr = "127.0.0.1:6000"
	if _, err := Render(spec, testRT); err == nil || !strings.Contains(err.Error(), "blocked-query dnstap") {
		t.Errorf("analytics on the blocked stream: %v", err)
	}
	spec.Upstreams.Servers = nil
	if _, err := Render(spec, testRT); err == nil {
		t.Error("invalid spec rendered")
	}
}

func TestLuaString(t *testing.T) {
	for in, want := range map[string]string{
		``:                       `""`,
		`plain /dns-query`:       `"plain /dns-query"`,
		`a"b\c`:                  `"a\"b\\c"`,
		"x\n\")os.exit()--":      `"x\010\")os.exit()--"`,
		"\x00" + "1":             `"\0001"`, // 3-digit escape: the digit after it is not swallowed
		"é]]":                    `"\195\169]]"`,
		"\x7f\xff":               `"\127\255"`,
		"\x07example\x03com\x00": `"\007example\003com\000"`,
	} {
		if got := luaString(in); got != want {
			t.Errorf("luaString(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestAddrs(t *testing.T) {
	got, err := prefixes([]string{"10.1.2.3/8", "192.0.2.1", "2001:db8::1", "::1/128", "2001:DB8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.1/32", "2001:db8::1/128", "::1/128", "2001:db8::/32"}
	if !slices.Equal(got, want) {
		t.Errorf("prefixes = %v", got)
	}
	for _, bad := range []string{"10.0.0.0/33", "fe80::1%eth0", "host", `1.2.3.4"`} {
		if _, err := prefixes([]string{bad}); err == nil {
			t.Errorf("prefixes(%q) accepted", bad)
		}
	}
	for in, want := range map[string]string{"0.0.0.0:53": "0.0.0.0:53", "[::]:53": "[::]:53", "[2001:DB8::1]:853": "[2001:db8::1]:853"} {
		if got, err := addrPort(in); err != nil || got != want {
			t.Errorf("addrPort(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"1.2.3.4", "[fe80::1%eth0]:53", "a:53", ":53"} {
		if _, err := addrPort(bad); err == nil {
			t.Errorf("addrPort(%q) accepted", bad)
		}
	}
}

func TestWire(t *testing.T) {
	soa, err := soaWire("blocked.invalid. nobody.blocked.invalid. 1 3600 1200 604800 10800")
	if err != nil {
		t.Fatal(err)
	}
	want := "\x07blocked\x07invalid\x00\x06nobody\x07blocked\x07invalid\x00" +
		"\x00\x00\x00\x01\x00\x00\x0e\x10\x00\x00\x04\xb0\x00\x09\x3a\x80\x00\x00\x2a\x30"
	if string(soa) != want {
		t.Errorf("soa = %q", soa)
	}
	for _, bad := range []string{"a. b. 1 2 3 4", "a. b. x 2 3 4 5", "a. b. 1 2 3 4 4294967296", "a..b c. 1 2 3 4 5"} {
		if _, err := soaWire(bad); err == nil {
			t.Errorf("soaWire(%q) accepted", bad)
		}
	}
	if w, _ := dnsWire("."); string(w) != "\x00" {
		t.Errorf("root = %q", w)
	}
	if _, err := dnsWire(strings.Repeat("a", 64) + ".com"); err == nil {
		t.Error("64-byte label accepted")
	}
}

func TestMaskSecrets(t *testing.T) {
	files, err := Render(api.DefaultConfigSpec(), api.NodeRuntime{ConsoleKey: `k"ey\`, WebPassword: "hunter2", WebAPIKey: "sekrit"})
	if err != nil {
		t.Fatal(err)
	}
	conf := MaskSecrets(files)[FileConf]
	for _, s := range []string{"hunter2", "sekrit", `k\"ey`} {
		if strings.Contains(conf, s) {
			t.Errorf("secret %q not masked", s)
		}
	}
	if strings.Count(conf, Mask) != 3 {
		t.Errorf("want 3 masks:\n%s", conf)
	}
}

// TestCheckConfig runs dnsdist --check-config on rendered configs when dnsdist is installed.
func TestCheckConfig(t *testing.T) {
	bin, err := exec.LookPath("dnsdist")
	if err != nil {
		t.Skip("dnsdist not on PATH")
	}
	for name, mut := range map[string]func(*api.ConfigSpec){
		"defaults": func(*api.ConfigSpec) {},
		"all_off": func(s *api.ConfigSpec) {
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled, s.Cache.Enabled, s.Analytics.Enabled = false, false, false, false, false
		},
		"analytics_sampled": func(s *api.ConfigSpec) { s.Analytics.SampleRate = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			spec := api.DefaultConfigSpec()
			mut(&spec)
			rt := testRT
			rt.BaseDir, rt.CDBPath = dir, filepath.Join(dir, "missing.cdb")
			files, err := Render(spec, rt)
			if err != nil {
				t.Fatal(err)
			}
			for rel, b := range files {
				os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755)
				os.WriteFile(filepath.Join(dir, rel), b, 0o644)
			}
			out, err := exec.Command(bin, "--check-config", "-C", filepath.Join(dir, FileConf)).CombinedOutput()
			if err != nil || !strings.Contains(string(out), "Configuration OK") {
				t.Fatalf("check-config: %v\n%s", err, out)
			}
		})
	}
}
