package cgk

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type fake struct {
	mu      sync.Mutex
	fetched []string // ips probed
}

var (
	poolA = netip.MustParsePrefix("104.20.0.0/16") // served from SIN for the evidence IP → rewrite
	poolB = netip.MustParsePrefix("104.21.0.0/16") // all CGK → keep
	poolC = netip.MustParsePrefix("172.66.0.0/16") // no answer, previously rewritten → rewrite
	poolD = netip.MustParsePrefix("104.24.0.0/16") // no answer, not previously rewritten → keep
	alias = netip.MustParsePrefix("104.16.0.0/16") // CGK; even last octet answers like the real site
	sin   = netip.MustParsePrefix("104.17.0.0/16") // served from SIN → never an alias
)

func (f *fake) Resolve(_ context.Context, name string) []string {
	switch name {
	case "site1.test":
		return []string{"104.20.1.1", "8.8.8.8"}
	case "offpool.test":
		return []string{"1.2.3.4"}
	case "down.test":
		return []string{"104.21.5.5"}
	}
	return nil
}

func (f *fake) Fetch(_ context.Context, host, ip, path string) (string, time.Duration, string) {
	f.mu.Lock()
	f.fetched = append(f.fetched, ip)
	f.mu.Unlock()
	a := netip.MustParseAddr(ip)
	last := a.As4()[3]
	if host != TraceHost {
		switch {
		case host == "down.test":
			return "000", 0, ""
		case ip == "104.20.1.1" || last%2 == 0:
			return "200", 0, ""
		}
		return "403", 0, ""
	}
	t := time.Duration(last) * time.Millisecond
	switch {
	case ip == "104.20.1.1":
		return "200", t, "fl=1\ncolo=SIN\n"
	case poolA.Contains(a), poolB.Contains(a), alias.Contains(a):
		return "200", t, "h=www.cloudflare.com\ncolo=CGK\nhttp=http/2\n"
	case sin.Contains(a):
		return "200", t, "colo=SIN\n"
	}
	return "000", t, ""
}

func spec() api.CGK {
	return api.CGK{
		Enabled:       true,
		RewritePools:  []string{poolA.String(), poolB.String(), poolC.String(), poolD.String()},
		AliasPools:    []string{alias.String(), sin.String()},
		TestSites:     []string{"site1.test", "offpool.test", "down.test"},
		AliasesWanted: 3, MinOK: 2, RefreshIntervalH: 6,
	}
}

func TestMeasure(t *testing.T) {
	f := &fake{}
	prev := []string{poolC.String()}
	current := []string{"104.16.0.10", "1.1.1.1"} // 1.1.1.1 is outside the alias pools
	res, err := Measure(context.Background(), spec(), f, prev, current, rand.New(rand.NewPCG(1, 2)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sites) != 1 || res.Sites["site1.test"] != "200" {
		t.Fatalf("sites: %v", res.Sites)
	}
	if !slices.Equal(res.Rewrite, []string{poolA.String(), poolC.String()}) {
		t.Fatalf("rewrite: %v", res.Rewrite)
	}
	if len(res.Aliases) != 3 {
		t.Fatalf("aliases: %v", res.Aliases)
	}
	lastOctet := func(ip string) int { return int(netip.MustParseAddr(ip).As4()[3]) }
	for i, ip := range res.Aliases {
		if a := netip.MustParseAddr(ip); !alias.Contains(a) || lastOctet(ip)%2 != 0 {
			t.Fatalf("alias %s does not qualify", ip)
		}
		if i > 0 && lastOctet(res.Aliases[i-1]) > lastOctet(ip) {
			t.Fatalf("aliases not fastest-first: %v", res.Aliases)
		}
	}
	if slices.Contains(f.fetched, "1.1.1.1") {
		t.Fatal("a current alias outside alias_pools was probed")
	}
	if !slices.Contains(f.fetched, "104.16.0.10") {
		t.Fatal("the current alias inside alias_pools was not re-probed")
	}
	if len(res.Pools) != 4 || !slices.Equal(res.Pools[0].Colos, []string{"CGK", "SIN"}) || len(res.Pools[2].Colos) != 0 {
		t.Fatalf("pools: %+v", res.Pools)
	}

	// Missing rewrite file → the spec's pools are the previous state: C and D stay rewritten.
	res, err = Measure(context.Background(), spec(), &fake{}, nil, nil, rand.New(rand.NewPCG(1, 2)))
	if err != nil || !slices.Equal(res.Rewrite, []string{poolA.String(), poolC.String(), poolD.String()}) {
		t.Fatalf("no previous file: %v %v", res.Rewrite, err)
	}
}

func TestMeasureGuards(t *testing.T) {
	s := spec()
	s.MinOK = 50
	s.AliasesWanted = 50
	if _, err := Measure(context.Background(), s, &fake{}, nil, nil, rand.New(rand.NewPCG(1, 2))); err == nil || !strings.Contains(err.Error(), "min_ok") {
		t.Fatalf("min_ok guard: %v", err)
	}
	s = spec()
	s.TestSites = []string{"offpool.test", "down.test", "nxdomain.test"}
	if _, err := Measure(context.Background(), s, &fake{}, nil, nil, rand.New(rand.NewPCG(1, 2))); err == nil || !strings.Contains(err.Error(), "test site") {
		t.Fatalf("no usable site: %v", err)
	}
}

func TestSampleAndFiles(t *testing.T) {
	rnd := rand.New(rand.NewPCG(3, 4))
	n := netip.MustParsePrefix("188.114.96.0/20")
	for _, ip := range sample(n, 1000, rnd) {
		a := netip.MustParseAddr(ip)
		if !n.Contains(a) || ip == "188.114.96.0" || ip == "188.114.111.255" {
			t.Fatalf("bad sample %s", ip)
		}
	}
	p := filepath.Join(t.TempDir(), "cgk-aliases.txt")
	if ReadList(p) != nil {
		t.Fatal("missing file must read as nil")
	}
	os.WriteFile(p, Format("why", time.Now(), []string{"1.2.3.4", "5.6.7.8 # note"}), 0o644)
	if got := ReadList(p); !slices.Equal(got, []string{"1.2.3.4", "5.6.7.8"}) {
		t.Fatalf("ReadList: %v", got)
	}
	os.WriteFile(p, Format("why", time.Now(), nil), 0o644)
	if got := ReadList(p); got == nil || len(got) != 0 {
		t.Fatalf("empty file must be non-nil empty: %#v", got)
	}
}
