// Package cgk re-measures Cloudflare routing from this node and picks which shared
// pools to rewrite to CGK (Jakarta) aliases. Port of the original cgk-refresh prober.
package cgk

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const (
	TraceHost   = "www.cloudflare.com"
	poolSamples = 10 // random IPs sampled per rewrite pool
	candPerPool = 8  // random alias candidates per alias pool
	workers     = 32
)

// Prober does the network work; tests use a fake.
type Prober interface {
	// Resolve returns the A records of name.
	Resolve(ctx context.Context, name string) []string
	// Fetch GETs https://host+path with host pinned to ip. code is "000" when there
	// is no HTTP answer (like curl's %{http_code}); connect is the TCP connect time.
	Fetch(ctx context.Context, host, ip, path string) (code string, connect time.Duration, body string)
}

// Result is one measurement. Rewrite ⊆ spec.RewritePools (both families), Aliases and
// Aliases6 ⊆ spec.AliasPools.
type Result struct {
	Sites    map[string]string // test site → HTTP status of its real IP
	Rewrite  []string
	Aliases  []string
	Aliases6 []string
	Pools    []api.CGKPool // colos seen per rewrite pool
	IPv6     string        // api.CGKIPv6* status of the IPv6 half
}

// Measure runs the selection. prevRewrite is the current rewrite list (nil when the
// file does not exist yet: the spec's pools are the cgk.lua fallback), current the
// current aliases. It fails, meaning "keep the current lists", when no test site is
// usable or fewer than MinOK aliases qualify.
func Measure(ctx context.Context, spec api.CGK, p Prober, prevRewrite, current, current6 []string, rnd *rand.Rand) (*Result, error) {
	allPools, err := parsePrefixes(spec.RewritePools)
	if err != nil {
		return nil, fmt.Errorf("rewrite_pools: %w", err)
	}
	allAliasPools, err := parsePrefixes(spec.AliasPools)
	if err != nil {
		return nil, fmt.Errorf("alias_pools: %w", err)
	}
	pools, pools6 := byFamily(allPools)
	aliasPools, aliasPools6 := byFamily(allAliasPools)
	poolOf := func(ip string) (netip.Prefix, bool) {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return netip.Prefix{}, false
		}
		for _, n := range pools {
			if n.Contains(a) {
				return n, true
			}
		}
		return netip.Prefix{}, false
	}
	res := &Result{Sites: map[string]string{}}

	// 1. test sites that really sit on the shared pools, with their real answers;
	// their IPs are also evidence for the pool they are in.
	evidence := map[netip.Prefix][]string{}
	for _, s := range spec.TestSites {
		var ips []string
		for _, ip := range p.Resolve(ctx, s) {
			if n, ok := poolOf(ip); ok {
				ips = append(ips, ip)
				evidence[n] = append(evidence[n], ip)
			}
		}
		if len(ips) > 0 {
			if code, _, _ := p.Fetch(ctx, s, ips[0], "/"); code != "000" {
				res.Sites[s] = code
			}
		}
	}
	if len(res.Sites) == 0 {
		return res, errors.New("no usable test site on Cloudflare shared pools; keeping current lists")
	}

	// 2. a pool is rewritten when any sample is served outside CGK; a pool that gives
	// no answer at all keeps its previous state.
	prev := spec.RewritePools
	if prevRewrite != nil {
		prev = prevRewrite
	}
	prevNets, _ := parsePrefixes(prev)
	colo := func(ip string) (string, time.Duration) {
		_, t, body := p.Fetch(ctx, TraceHost, ip, "/cdn-cgi/trace")
		for _, l := range strings.Split(body, "\n") {
			if c, ok := strings.CutPrefix(strings.TrimSpace(l), "colo="); ok && c != "" {
				return c, t
			}
		}
		return "", t
	}
	type poolJob struct {
		net netip.Prefix
		ips []string
	}
	jobs := make([]poolJob, len(pools))
	var all []string
	for i, n := range pools {
		jobs[i] = poolJob{n, append(sample(n, poolSamples, rnd), evidence[n]...)}
		all = append(all, jobs[i].ips...)
	}
	colos := parallel(all, func(ip string) string { c, _ := colo(ip); return c })
	for _, j := range jobs {
		seen := map[string]bool{}
		for _, ip := range j.ips {
			if c := colos[ip]; c != "" {
				seen[c] = true
			}
		}
		cs := sortedKeys(seen)
		res.Pools = append(res.Pools, api.CGKPool{Net: j.net.String(), Colos: cs})
		switch {
		case len(cs) == 0:
			if slices.ContainsFunc(prevNets, func(p netip.Prefix) bool { return subnetOf(j.net, p) }) {
				res.Rewrite = append(res.Rewrite, j.net.String())
			}
		case len(cs) > 1 || cs[0] != "CGK":
			res.Rewrite = append(res.Rewrite, j.net.String())
		}
	}

	// 3. alias candidates: current aliases still inside the alias pools + random
	// samples of each alias pool. A candidate qualifies when served from CGK and
	// answering every test site with the same status as the real IP; fastest win.
	cands := map[string]bool{}
	for _, ip := range current {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() &&
			slices.ContainsFunc(aliasPools, func(p netip.Prefix) bool { return p.Contains(a) }) {
			cands[a.String()] = true
		}
	}
	for _, n := range aliasPools {
		for _, ip := range sample(n, candPerPool, rnd) {
			cands[ip] = true
		}
	}
	type good struct {
		t  time.Duration
		ip string
	}
	qualified := parallel(sortedKeys(cands), func(ip string) *good {
		c, t := colo(ip)
		if c != "CGK" {
			return nil
		}
		for s, want := range res.Sites {
			if code, _, _ := p.Fetch(ctx, s, ip, "/"); code != want {
				return nil
			}
		}
		return &good{t, ip}
	})
	var ok []good
	for _, g := range qualified {
		if g != nil {
			ok = append(ok, *g)
		}
	}
	sort.Slice(ok, func(i, j int) bool {
		if ok[i].t != ok[j].t {
			return ok[i].t < ok[j].t
		}
		return ok[i].ip < ok[j].ip
	})
	for _, g := range ok[:min(len(ok), spec.AliasesWanted)] {
		res.Aliases = append(res.Aliases, g.ip)
	}
	if len(res.Aliases) < spec.MinOK {
		return res, fmt.Errorf("only %d aliases qualified (< min_ok %d); keeping current lists", len(res.Aliases), spec.MinOK)
	}
	measure6(ctx, spec, p, res, pools6, aliasPools6, prevNets, current6, colo, rnd)
	return res, nil
}

// measure6 is the IPv6 half (SPEC §6.7): the same rules as IPv4, but it never fails the
// run. Without IPv6 connectivity (no v6 sample answers) or with fewer than MinOK v6
// aliases nothing is rewritten over IPv6, so AAAA answers keep their real addresses.
func measure6(ctx context.Context, spec api.CGK, p Prober, res *Result, pools, aliasPools, prevNets []netip.Prefix,
	current []string, colo func(string) (string, time.Duration), rnd *rand.Rand) {
	if len(pools) == 0 || len(aliasPools) == 0 {
		res.IPv6 = api.CGKIPv6NotConfigured
		return
	}
	evidence := map[netip.Prefix][]string{}
	for _, s := range spec.TestSites {
		for _, ip := range p.Resolve(ctx, s) {
			if a, err := netip.ParseAddr(ip); err == nil && a.Is6() {
				for _, n := range pools {
					if n.Contains(a) {
						evidence[n] = append(evidence[n], ip)
					}
				}
			}
		}
	}
	type poolJob struct {
		net netip.Prefix
		ips []string
	}
	jobs := make([]poolJob, len(pools))
	var all []string
	for i, n := range pools {
		jobs[i] = poolJob{n, append(sample6(n, poolSamples, rnd), evidence[n]...)}
		all = append(all, jobs[i].ips...)
	}
	colos := parallel(all, func(ip string) string { c, _ := colo(ip); return c })
	var rewrite []string
	var pr []api.CGKPool
	up := false
	for _, j := range jobs {
		seen := map[string]bool{}
		for _, ip := range j.ips {
			if c := colos[ip]; c != "" {
				seen[c] = true
			}
		}
		cs := sortedKeys(seen)
		up = up || len(cs) > 0
		pr = append(pr, api.CGKPool{Net: j.net.String(), Colos: cs})
		switch {
		case len(cs) == 0:
			if slices.ContainsFunc(prevNets, func(p netip.Prefix) bool { return subnetOf(j.net, p) }) {
				rewrite = append(rewrite, j.net.String())
			}
		case len(cs) > 1 || cs[0] != "CGK":
			rewrite = append(rewrite, j.net.String())
		}
	}
	res.Pools = append(res.Pools, pr...)
	if !up {
		res.IPv6 = api.CGKIPv6NoConnectivity
		return
	}

	cands := map[string]bool{}
	for _, ip := range current {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is6() &&
			slices.ContainsFunc(aliasPools, func(p netip.Prefix) bool { return p.Contains(a) }) {
			cands[a.String()] = true
		}
	}
	for _, n := range aliasPools {
		for _, ip := range sample6(n, candPerPool, rnd) {
			cands[ip] = true
		}
	}
	type good struct {
		t  time.Duration
		ip string
	}
	qualified := parallel(sortedKeys(cands), func(ip string) *good {
		c, t := colo(ip)
		if c != "CGK" {
			return nil
		}
		for s, want := range res.Sites {
			if code, _, _ := p.Fetch(ctx, s, ip, "/"); !sameOutcome(code, want) {
				return nil
			}
		}
		return &good{t, ip}
	})
	var ok []good
	for _, g := range qualified {
		if g != nil {
			ok = append(ok, *g)
		}
	}
	sort.Slice(ok, func(i, j int) bool {
		if ok[i].t != ok[j].t {
			return ok[i].t < ok[j].t
		}
		return ok[i].ip < ok[j].ip
	})
	if len(ok) < spec.MinOK {
		res.IPv6 = api.CGKIPv6TooFewAliases
		return
	}
	for _, g := range ok[:min(len(ok), spec.AliasesWanted)] {
		res.Aliases6 = append(res.Aliases6, g.ip)
	}
	res.Rewrite = append(res.Rewrite, rewrite...)
	res.IPv6 = api.CGKIPv6OK
}

// sameOutcome: two HTTP statuses mean the same to a user when they are equal or both
// "working" (2xx/3xx) — a site may skip a redirect on one edge address (seen: a site
// answering 301 via its real IPv6 and 200 via a CGK IPv6 alias). "000" (no answer) and
// errors must match exactly.
func sameOutcome(a, b string) bool {
	works := func(c string) bool { return len(c) == 3 && (c[0] == '2' || c[0] == '3') }
	return a == b || works(a) && works(b)
}

// byFamily splits prefixes into IPv4 and IPv6.
func byFamily(list []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range list {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

// cfV4 are Cloudflare IPv4 ranges whose addresses Cloudflare embeds in the low 32 bits of
// its IPv6 addresses (2606:4700:3033::6815:3764 ↔ 104.21.55.100); random low bits are
// mostly unbound.
var cfV4 = []netip.Prefix{netip.MustParsePrefix("104.16.0.0/12"), netip.MustParsePrefix("172.64.0.0/13")}

// sample6 picks k addresses of an IPv6 prefix: for prefixes up to /96 the prefix plus a
// random address of cfV4 in the low 32 bits, for longer prefixes random host bits.
func sample6(n netip.Prefix, k int, rnd *rand.Rand) []string {
	if !n.Addr().Is6() || n.Bits() > 126 {
		return nil
	}
	base := n.Masked().Addr().As16()
	out := make([]string, k)
	for i := range out {
		b := base
		if n.Bits() <= 96 {
			v4 := cfV4[rnd.IntN(len(cfV4))]
			s4 := sample(v4, 1, rnd)[0]
			a4 := netip.MustParseAddr(s4).As4()
			copy(b[12:], a4[:])
		} else {
			host := 128 - n.Bits() // < 32
			v := rnd.Uint32N(uint32(1)<<host-1) + 1
			for j := 0; j < 4; j++ {
				b[15-j] |= byte(v >> (8 * j))
			}
		}
		out[i] = netip.AddrFrom16(b).String()
	}
	return out
}

// parallel runs f over items with a bounded worker pool.
func parallel[T any](items []string, f func(string) T) map[string]T {
	return parallelN(items, workers, f)
}

func parallelN[T any](items []string, n int, f func(string) T) map[string]T {
	out := make(map[string]T, len(items))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, n)
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			v := f(it)
			mu.Lock()
			out[it] = v
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// sample picks n random host addresses of an IPv4 prefix (never network/broadcast).
func sample(n netip.Prefix, k int, rnd *rand.Rand) []string {
	if !n.Addr().Is4() || n.Bits() > 30 {
		return nil
	}
	size := uint32(1) << (32 - n.Bits())
	b := n.Masked().Addr().As4()
	base := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	out := make([]string, k)
	for i := range out {
		v := base + 1 + rnd.Uint32N(size-2)
		out[i] = netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}).String()
	}
	return out
}

func subnetOf(n, p netip.Prefix) bool { return p.Bits() <= n.Bits() && p.Contains(n.Addr()) }

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ReadList reads a cgk-*.txt file (comments and blank lines ignored); nil when missing.
func ReadList(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := []string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l, _, _ := strings.Cut(sc.Text(), "#")
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// Format renders a cgk-*.txt file.
func Format(why string, at time.Time, items []string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n# written by dnsjos-agent %s\n", why, at.Format(time.RFC3339))
	for _, it := range items {
		b.WriteString(it + "\n")
	}
	return []byte(b.String())
}
