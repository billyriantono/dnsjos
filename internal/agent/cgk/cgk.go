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

// Result is one measurement. Rewrite ⊆ spec.RewritePools, Aliases ⊆ spec.AliasPools.
type Result struct {
	Sites   map[string]string // test site → HTTP status of its real IP
	Rewrite []string
	Aliases []string
	Pools   []api.CGKPool // colos seen per rewrite pool
}

// Measure runs the selection. prevRewrite is the current rewrite list (nil when the
// file does not exist yet: the spec's pools are the cgk.lua fallback), current the
// current aliases. It fails, meaning "keep the current lists", when no test site is
// usable or fewer than MinOK aliases qualify.
func Measure(ctx context.Context, spec api.CGK, p Prober, prevRewrite, current []string, rnd *rand.Rand) (*Result, error) {
	pools, err := parsePrefixes(spec.RewritePools)
	if err != nil {
		return nil, fmt.Errorf("rewrite_pools: %w", err)
	}
	aliasPools, err := parsePrefixes(spec.AliasPools)
	if err != nil {
		return nil, fmt.Errorf("alias_pools: %w", err)
	}
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
	return res, nil
}

// parallel runs f over items with a bounded worker pool.
func parallel[T any](items []string, f func(string) T) map[string]T {
	out := make(map[string]T, len(items))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
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
