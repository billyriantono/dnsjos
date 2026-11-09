package tproxy

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func spec() api.ConfigSpec {
	s := api.DefaultConfigSpec()
	s.Listen.TProxy = api.TProxy{
		Enabled:    true,
		Port:       5300,
		Sources:    []string{"10.0.0.0/8", "2001:db8::/32"},
		ExcludeDst: []string{"4.4.4.4", "2001:4860:4860::8888"},
		Interfaces: []string{"eth0", "eth1.100"},
	}
	return s
}

func tproxySpec() api.ConfigSpec {
	s := spec()
	s.Listen.TProxy.Mode = api.TProxyModeTProxy
	return s
}

func TestRenderDisabled(t *testing.T) {
	f, err := Render(api.DefaultConfigSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.NFT)+len(f.Script)+len(f.Unit)+len(f.Cleanup)+len(f.RelayUnit) != 0 {
		t.Fatalf("disabled tproxy rendered files: %+v", f)
	}
}

func TestRenderTProxyMode(t *testing.T) {
	f, err := Render(tproxySpec())
	if err != nil {
		t.Fatal(err)
	}
	nft := string(f.NFT)
	for _, want := range []string{
		"type filter hook prerouting priority mangle",
		"fib daddr type local return",
		"tproxy ip to :5300 meta mark set 0x5315 accept",
		"tproxy ip6 to :5300 meta mark set 0x5315 accept",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("tproxy rules missing %q:\n%s", want, nft)
		}
	}
	if strings.Contains(nft, "redirect to") {
		t.Errorf("tproxy mode must not use REDIRECT:\n%s", nft)
	}
	for _, want := range []string{"ip rule add", "ip route add local 0.0.0.0/0", "table 5315"} {
		if !strings.Contains(string(f.Script), want) {
			t.Errorf("apply script missing %q:\n%s", want, f.Script)
		}
	}
	if !strings.Contains(string(f.Cleanup), "ip rule del") ||
		!strings.Contains(string(f.Cleanup), "ip route flush table 5315") {
		t.Errorf("cleanup script incomplete:\n%s", f.Cleanup)
	}
	relay := string(f.RelayUnit)
	if !strings.Contains(relay, "tproxy-relay") ||
		!strings.Contains(relay, "--port 5300") ||
		!strings.Contains(relay, "--dnsdist 127.0.0.1:5301") {
		t.Errorf("relay unit incomplete:\n%s", relay)
	}
	if !strings.Contains(string(f.Unit), "Requires="+RelayUnitName) {
		t.Errorf("nft unit must require the relay:\n%s", f.Unit)
	}
}

func TestRenderRules(t *testing.T) {
	f, err := Render(spec())
	if err != nil {
		t.Fatal(err)
	}
	nft := string(f.NFT)
	for _, want := range []string{
		"table inet dnsjos_tproxy",
		"type nat hook prerouting priority dstnat",
		"iifname \"lo\" return",
		"ip daddr @exclude4 return",
		"ip6 daddr @exclude6 return",
		"ip saddr != @source4 return",
		"ip6 saddr != @source6 return",
		"iifname != @ifaces return",
		"meta l4proto { tcp, udp } th dport 53 redirect to :5300",
		"10.0.0.0/8",
		"2001:db8::/32",
		"4.4.4.4",
		"2001:4860:4860::8888",
		"\"eth0\"",
		"\"eth1.100\"",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("nft rules missing %q:\n%s", want, nft)
		}
	}
	if strings.Contains(nft, "1.1.1.1") || strings.Contains(nft, "8.8.8.8") {
		t.Errorf("upstreams must not bypass the redirect:\n%s", nft)
	}
	if !strings.Contains(string(f.Script), "nft -f "+NFTFile) {
		t.Errorf("script does not load %s:\n%s", NFTFile, f.Script)
	}
	if !strings.Contains(string(f.Unit), "ExecStart="+ScriptPath) ||
		!strings.Contains(string(f.Unit), "ExecStop=") {
		t.Errorf("unit does not install and remove the table:\n%s", f.Unit)
	}
}

func TestRenderWithoutSources(t *testing.T) {
	s := spec()
	s.Listen.TProxy.Sources = nil
	f, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(f.NFT), "saddr != @source") {
		t.Fatalf("empty sources must not restrict clients:\n%s", f.NFT)
	}
}

func TestRenderWithoutInterfaces(t *testing.T) {
	s := spec()
	s.Listen.TProxy.Interfaces = nil
	f, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(f.NFT), "ifaces") {
		t.Fatalf("empty interfaces must not restrict ingress:\n%s", f.NFT)
	}
}

func TestRenderTProxyRPFilter(t *testing.T) {
	s := tproxySpec()
	s.Listen.TProxy.DisableRPFilter = true
	f, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	script := string(f.Script)
	if !strings.Contains(script, "RP_STATE=/var/lib/dnsjos/dnsjos-tproxy-rpfilter.state") ||
		!strings.Contains(script, "echo 0 > \"$f\"") ||
		!strings.Contains(script, "for i in eth0 eth1.100; do") {
		t.Errorf("apply script does not disable rp_filter per interface:\n%s", script)
	}
	cleanup := string(f.Cleanup)
	if !strings.Contains(cleanup, "while IFS='=' read -r f v") ||
		!strings.Contains(cleanup, "printf '%s\\n' \"$v\" > \"$f\"") {
		t.Errorf("cleanup script does not restore rp_filter:\n%s", cleanup)
	}
	// The generated scripts must be valid POSIX shell.
	if _, err := exec.LookPath("sh"); err == nil {
		for name, body := range map[string][]byte{"apply": f.Script, "cleanup": f.Cleanup} {
			p := filepath.Join(t.TempDir(), name+".sh")
			if err := os.WriteFile(p, body, 0o700); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("sh", "-n", p).CombinedOutput(); err != nil {
				t.Errorf("%s script is not valid shell: %v\n%s\n%s", name, err, out, body)
			}
		}
	}
}

func TestRenderTProxyAllInterfacesRPFilter(t *testing.T) {
	s := tproxySpec()
	s.Listen.TProxy.Interfaces = nil
	s.Listen.TProxy.DisableRPFilter = true
	f, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.Script), "for f in /proc/sys/net/ipv4/conf/*/rp_filter; do") {
		t.Errorf("apply script does not cover every interface:\n%s", f.Script)
	}
}

func TestRenderTProxyKeepsRPFilterByDefault(t *testing.T) {
	f, err := Render(tproxySpec())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(f.Script), "rp_filter") {
		t.Errorf("rp_filter must be opt-in:\n%s", f.Script)
	}
}

// TestRenderNFTValid asks nft to parse the generated rules when it is available.
func TestRenderNFTValid(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	for name, s := range map[string]api.ConfigSpec{"redirect": spec(), "tproxy": tproxySpec()} {
		t.Run(name, func(t *testing.T) {
			f, err := Render(s)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(t.TempDir(), "rules.nft")
			if err := os.WriteFile(p, f.NFT, 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command("nft", "-c", "-f", p).CombinedOutput(); err != nil {
				t.Fatalf("nft -c rejected the rules: %v\n%s\n%s", err, out, f.NFT)
			}
		})
	}
}

func TestApplyTestModeWritesAndRemoves(t *testing.T) {
	root := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	if err := Apply(ctx, root, spec(), true, log); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{NFTFile, ScriptPath, UnitPath} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Fatalf("%s not written: %v", p, err)
		}
	}
	if err := Apply(ctx, root, api.DefaultConfigSpec(), true, log); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{NFTFile, ScriptPath, UnitPath} {
		if _, err := os.Stat(filepath.Join(root, p)); !os.IsNotExist(err) {
			t.Fatalf("%s not removed: %v", p, err)
		}
	}
}

func TestApplyTestModeTProxyFiles(t *testing.T) {
	root := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	if err := Apply(ctx, root, tproxySpec(), true, log); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{NFTFile, ScriptPath, CleanupPath, UnitPath, RelayUnitPath} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Fatalf("%s not written: %v", p, err)
		}
	}
	if err := Apply(ctx, root, api.DefaultConfigSpec(), true, log); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{NFTFile, ScriptPath, CleanupPath, UnitPath, RelayUnitPath} {
		if _, err := os.Stat(filepath.Join(root, p)); !os.IsNotExist(err) {
			t.Fatalf("%s not removed: %v", p, err)
		}
	}
}

func TestProxyHeader(t *testing.T) {
	v4src := netip.MustParseAddrPort("192.0.2.10:12345")
	v4dst := netip.MustParseAddrPort("8.8.8.8:53")
	v6src := netip.MustParseAddrPort("[2001:db8::1]:12345")
	v6dst := netip.MustParseAddrPort("[2001:4860:4860::8888]:53")
	cases := []struct {
		name string
		src  netip.AddrPort
		dst  netip.AddrPort
		tcp  bool
		fam  byte
		alen int
	}{
		{"v4udp", v4src, v4dst, false, proxyFamUDP4, 12},
		{"v4tcp", v4src, v4dst, true, proxyFamTCP4, 12},
		{"v6udp", v6src, v6dst, false, proxyFamUDP6, 36},
		{"v6tcp", v6src, v6dst, true, proxyFamTCP6, 36},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := proxyHeader(c.src, c.dst, c.tcp)
			if string(h[:12]) != proxyV2Signature || h[12] != proxyV2Version || h[13] != c.fam {
				t.Fatalf("bad header prefix: %x", h[:14])
			}
			if int(binary.BigEndian.Uint16(h[14:16])) != c.alen {
				t.Fatalf("length = %d, want %d", binary.BigEndian.Uint16(h[14:16]), c.alen)
			}
			if int(binary.BigEndian.Uint16(h[len(h)-4:len(h)-2])) != int(c.src.Port()) ||
				int(binary.BigEndian.Uint16(h[len(h)-2:])) != int(c.dst.Port()) {
				t.Fatalf("ports wrong: %x", h[len(h)-4:])
			}
			if len(h) != 16+c.alen {
				t.Fatalf("header length = %d, want %d", len(h), 16+c.alen)
			}
			// The address block must carry the original source and destination.
			if c.src.Addr().Is4() {
				if !reflect.DeepEqual(h[16:20], c.src.Addr().AsSlice()) ||
					!reflect.DeepEqual(h[20:24], c.dst.Addr().AsSlice()) {
					t.Fatalf("v4 addresses wrong: %x", h[16:24])
				}
			} else {
				if !reflect.DeepEqual(h[16:32], c.src.Addr().AsSlice()) ||
					!reflect.DeepEqual(h[32:48], c.dst.Addr().AsSlice()) {
					t.Fatalf("v6 addresses wrong: %x", h[16:48])
				}
			}
		})
	}
}
