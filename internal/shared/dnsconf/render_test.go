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
		"dualstack": func(s *api.ConfigSpec) {
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled, s.Analytics.Enabled = false, false, false, false
			s.DualStack.Enabled = true
		},
		"fastest_ip": func(s *api.ConfigSpec) {
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled, s.Analytics.Enabled = false, false, false, false
			s.SpeedCheck.FastestIP, s.SpeedCheck.MaxReplyIPNum = true, 4
		},
		"ip_alias": func(s *api.ConfigSpec) {
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled, s.Analytics.Enabled = false, false, false, false
			s.IPAlias = api.IPAlias{Enabled: true, Rules: []api.IPAliasRule{
				{Name: "cf", MatchPools: []string{"104.16.0.0/13", "172.64.0.0/13"},
					Targets: []string{"172.64.52.159", "172.64.87.224"}, Exclude: []string{"cftunnel.com"}},
				{Name: "cf6", MatchPools: []string{"2606:4700::/32"},
					Targets: []string{"2606:4700:3030::6810:3459"}},
			}}
		},
		"fastest_response": func(s *api.ConfigSpec) { // §6.11: overwrite with the Top N
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled, s.Analytics.Enabled = false, false, false, false
			s.SpeedCheck.FastestIP = true
			s.SpeedCheck.AnswerMode, s.SpeedCheck.MaxResponse = api.AnswerModeFastestResponse, 3
		},
		"cname": func(s *api.ConfigSpec) { // §6.11: smartdns cname /domain/target
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled, s.Analytics.Enabled = false, false, false, false
			s.CName = api.CNames{Enabled: true, Rules: []api.CNameRule{
				{Name: "Mirror.Example.Com.", Target: "fast.example.net"},
				{Name: "cdn.example.id", Target: "Edge.Example.Net."},
			}}
		},
		"response_ips": func(s *api.ConfigSpec) { // opt-in (off by default)
			s.Abuse.Enabled, s.CGK.Enabled, s.Analytics.Enabled = false, false, false
			s.Blocking.BlockResponseIPs = true
		},
		"blockpage_multi": func(s *api.ConfigSpec) { // multi-IP fallback: all answered
			s.Blocking.BlockpageIPv4 = "103.155.190.72, 103.155.190.73"
			s.Blocking.BlockpageIPv6 = "2001:db8::10, 2001:db8::11"
		},
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
		"dnssec_off": func(s *api.ConfigSpec) {
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled, s.Analytics.Enabled = false, false, false, false
			s.DNSSEC.DisableValidation = true
			s.DNSSEC.Exclude = []string{"ignored.example"} // validation is off for everything anyway
		},
		"dnssec_exclude": func(s *api.ConfigSpec) {
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled, s.Analytics.Enabled = false, false, false, false
			s.DNSSEC.Exclude = []string{"go.id", "Broken.Example.", "broken.example"}
		},
		"ecs": func(s *api.ConfigSpec) {
			s.Blocking.Enabled, s.Abuse.Enabled, s.CGK.Enabled, s.Analytics.Enabled = false, false, false, false
			s.Upstreams.Policy = "firstAvailable"
			s.Upstreams.ECSPrefixV4, s.Upstreams.ECSPrefixV6 = 20, 48
			s.Upstreams.Servers = []api.Upstream{
				{Address: "8.8.8.8:53", Weight: 1, Order: 1, Sockets: 4, Name: "google", ECS: true},
				{Address: "1.1.1.1:53", Weight: 1, Order: 2, Sockets: 4, Name: "cloudflare"}, // ignores ECS
			}
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

func TestIPAliasLargePacketUsesSlices(t *testing.T) {
	spec := api.DefaultConfigSpec()
	spec.Blocking.Enabled, spec.Abuse.Enabled, spec.CGK.Enabled, spec.Analytics.Enabled = false, false, false, false
	spec.IPAlias = api.IPAlias{Enabled: true, Rules: []api.IPAliasRule{{
		Name: "cf", MatchPools: []string{"104.16.0.0/13"}, Targets: []string{"172.64.52.159"},
	}}}
	files, err := Render(spec, testRT)
	if err != nil {
		t.Fatal(err)
	}
	lua := string(files[FileIPAlias])
	if strings.Contains(lua, "local bytes = { p:byte(1, #p) }") {
		t.Fatal("ip-alias still expands the entire packet with string.byte")
	}
	for _, want := range []string{"p:sub(last, rd - 1)", "p:sub(last)", "local out, last, nt"} {
		if !strings.Contains(lua, want) {
			t.Fatalf("ip-alias large-packet splice missing %q", want)
		}
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

func TestBlockpageIPs(t *testing.T) {
	got, err := parseBlockpageIPs("103.155.190.72, 103.155.190.73", true)
	if err != nil || len(got) != 2 {
		t.Fatalf("parse multi v4 = %v, %v", got, err)
	}
	if spoofAddrs(got) != `{"103.155.190.72", "103.155.190.73"}` {
		t.Errorf("spoof multi = %s", spoofAddrs(got))
	}
	one, err := parseBlockpageIPs("192.0.2.10", true)
	if err != nil || spoofAddrs(one) != `"192.0.2.10"` {
		t.Errorf("single must stay a bare string: %v, %v", one, err)
	}
	for _, bad := range []string{"", "nope", "::1", "192.0.2.1, 2001:db8::1",
		"192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, 192.0.2.5, 192.0.2.6, 192.0.2.7, 192.0.2.8, 192.0.2.9"} {
		if _, err := parseBlockpageIPs(bad, true); err == nil {
			t.Errorf("parseBlockpageIPs(%q) accepted", bad)
		}
	}
	if _, err := parseBlockpageIPs("1.2.3.4", false); err == nil {
		t.Error("v6 field accepted v4")
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

func TestHashCredential(t *testing.T) {
	h := hashCredential("secret")
	if !strings.HasPrefix(h, "$scrypt$ln=10,p=1,r=8$") || h != hashCredential("secret") || h == hashCredential("secret2") {
		t.Fatalf("want a deterministic, per-secret dnsdist scrypt hash, got %q", h)
	}
	if hashCredential(h) != h {
		t.Error("an already-hashed credential must pass through")
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
		"whashed_no_stale":  func(s *api.ConfigSpec) { s.Upstreams.Policy, s.Cache.StaleTTL = "whashed", 0 },
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
			// Plain logging prints "Configuration '<file>' OK!", structured logging "Configuration OK".
			if o := string(out); err != nil || !strings.Contains(o, "' OK!") && !strings.Contains(o, "Configuration OK") {
				t.Fatalf("check-config: %v\n%s", err, out)
			}
		})
	}
}
