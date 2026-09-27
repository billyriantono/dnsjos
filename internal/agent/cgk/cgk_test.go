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
	res, err := Measure(context.Background(), spec(), f, prev, current, nil, rand.New(rand.NewPCG(1, 2)))
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
	res, err = Measure(context.Background(), spec(), &fake{}, nil, nil, nil, rand.New(rand.NewPCG(1, 2)))
	if err != nil || !slices.Equal(res.Rewrite, []string{poolA.String(), poolC.String(), poolD.String()}) {
		t.Fatalf("no previous file: %v %v", res.Rewrite, err)
	}
}

func TestMeasureGuards(t *testing.T) {
	s := spec()
	s.MinOK = 50
	s.AliasesWanted = 50
	if _, err := Measure(context.Background(), s, &fake{}, nil, nil, nil, rand.New(rand.NewPCG(1, 2))); err == nil || !strings.Contains(err.Error(), "min_ok") {
		t.Fatalf("min_ok guard: %v", err)
	}
	s = spec()
	s.TestSites = []string{"offpool.test", "down.test", "nxdomain.test"}
	if _, err := Measure(context.Background(), s, &fake{}, nil, nil, nil, rand.New(rand.NewPCG(1, 2))); err == nil || !strings.Contains(err.Error(), "test site") {
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

// fake6 serves the IPv6 half: 2606:4700:3030::/44 from SIN, 2606:4700::6810:0/110 from CGK
// answering like the real site; with down set nothing answers over IPv6.
type fake6 struct{ down bool }

func (fake6) Resolve(context.Context, string) []string { return []string{"2606:4700:3033::6815:3764"} }

func (f fake6) Fetch(_ context.Context, host, ip, _ string) (string, time.Duration, string) {
	a := netip.MustParseAddr(ip)
	if f.down || !a.Is6() {
		return "000", 0, ""
	}
	sinPool, aliasPool := netip.MustParsePrefix("2606:4700:3030::/44"), netip.MustParsePrefix("2606:4700::6810:0/110")
	switch {
	case host == TraceHost && sinPool.Contains(a):
		return "200", 0, "colo=SIN\n"
	case host == TraceHost && aliasPool.Contains(a):
		return "200", time.Duration(a.As16()[15]) * time.Millisecond, "colo=CGK\n"
	case aliasPool.Contains(a):
		return "200", 0, ""
	}
	return "000", 0, ""
}

func TestMeasure6(t *testing.T) {
	s := spec()
	s.RewritePools = append(s.RewritePools, "2606:4700:3030::/44", "2606:4700:10::/48")
	s.AliasPools = append(s.AliasPools, "2606:4700::6810:0/110")
	pools, _ := parsePrefixes([]string{"2606:4700:3030::/44", "2606:4700:10::/48"})
	aliases, _ := parsePrefixes([]string{"2606:4700::6810:0/110"})
	run := func(p Prober) *Result {
		res := &Result{Sites: map[string]string{"site1.test": "301"}} // aliases answer 200: a skipped redirect still qualifies
		colo := func(ip string) (string, time.Duration) {
			_, t, body := p.Fetch(context.Background(), TraceHost, ip, "/cdn-cgi/trace")
			if c, ok := strings.CutPrefix(strings.TrimSpace(body), "colo="); ok {
				return c, t
			}
			return "", t
		}
		measure6(context.Background(), s, p, res, pools, aliases, nil, nil, colo, rand.New(rand.NewPCG(3, 4)))
		return res
	}
	res := run(fake6{})
	if res.IPv6 != api.CGKIPv6OK || len(res.Aliases6) != s.AliasesWanted {
		t.Fatalf("ipv6 %q aliases6 %v", res.IPv6, res.Aliases6)
	}
	for _, a := range res.Aliases6 {
		if !netip.MustParsePrefix("2606:4700::6810:0/110").Contains(netip.MustParseAddr(a)) {
			t.Fatalf("alias %s outside the alias pool", a)
		}
	}
	// the SIN pool is rewritten; 2606:4700:10::/48 gave no answer and was never rewritten
	if strings.Join(res.Rewrite, ",") != "2606:4700:3030::/44" {
		t.Fatalf("rewrite %v", res.Rewrite)
	}
	res = run(fake6{down: true})
	if res.IPv6 != api.CGKIPv6NoConnectivity || res.Aliases6 != nil || res.Rewrite != nil {
		t.Fatalf("no IPv6: %+v", res)
	}
	for _, ip := range sample6(netip.MustParsePrefix("2606:4700:3030::/44"), 20, rand.New(rand.NewPCG(1, 1))) {
		a := netip.MustParseAddr(ip).As16()
		if v4 := netip.AddrFrom4([4]byte(a[12:])); !cfV4[0].Contains(v4) && !cfV4[1].Contains(v4) {
			t.Fatalf("sample %s does not embed a Cloudflare IPv4 address", ip)
		}
	}
}
