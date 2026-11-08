package tproxy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
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

func TestRenderDisabled(t *testing.T) {
	f, err := Render(api.DefaultConfigSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.NFT)+len(f.Script)+len(f.Unit) != 0 {
		t.Fatalf("disabled tproxy rendered files: %+v", f)
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

// TestRenderNFTValid asks nft to parse the generated rules when it is available.
func TestRenderNFTValid(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	f, err := Render(spec())
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
