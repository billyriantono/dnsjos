// Package dualstack measures, from this node, whether names answer faster over IPv4 or
// IPv6: smartdns' dualstack-ip-selection (SPEC §6.8). dualstack.lua reports the names
// clients get AAAA answers for (dsSeen()); the agent speed-checks both families like
// smartdns (speed-check-mode, every address, fastest wins) and lists the names whose
// AAAA (or, with allow_force_aaaa, A) answers dualstack.lua must drop.
package dualstack

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const (
	checks      = 100 // names measured per run, busiest first
	workers     = 16
	perFamily   = 16 // addresses probed per family (smartdns probes every address)
	okRecheck   = 6 * time.Hour
	dropRecheck = time.Hour // routes change: give the dropped family another chance soon
	forget      = 7 * 24 * time.Hour
	// smartdns' DNS_PING_TIMEOUT (950 ms, counted from the first probe, never below 200 ms
	// per probe) and DNS_PING_CHECK_INTERVAL (the next method starts 100 ms later; its
	// docs say 200 ms, the code uses 100).
	probeTimeout    = 950 * time.Millisecond
	minProbeTimeout = 200 * time.Millisecond
	checkInterval   = 100 * time.Millisecond
)

// Answer is a name's addresses per family with the lowest TTL of each RRset.
type Answer struct {
	V4, V6     []string
	TTL4, TTL6 uint32
}

// Prober does the network work; tests use a fake.
type Prober interface {
	Resolve(ctx context.Context, name string) Answer
	// Probe returns the round trip of one speed check to ip, -1 when it fails.
	Probe(ctx context.Context, c api.SpeedCheck, ip string) time.Duration
}

// Entry is one measured name. V4/V6 are the fastest speed checks, -1 = unreachable or
// no address; Has4/Has6 whether the family had addresses at all.
type Entry struct {
	Hits      int64         `json:"hits"`
	LastSeen  time.Time     `json:"last_seen"`
	CheckedAt time.Time     `json:"checked_at"`
	V4        time.Duration `json:"v4"`
	V6        time.Duration `json:"v6"`
	Has4      bool          `json:"has4"`
	Has6      bool          `json:"has6"`
	TTL4      uint32        `json:"ttl4"`
	TTL6      uint32        `json:"ttl6"`
}

// State is the agent's memory of measured names, persisted between runs.
type State map[string]*Entry

// Params are the spec's knobs, parsed.
type Params struct {
	Threshold      time.Duration
	AllowForceAAAA bool
	Checks         []api.SpeedCheck
	Exclude        []string
}

// ParamsOf reads a validated spec section.
func ParamsOf(d api.DualStack) Params {
	c, _ := api.ParseSpeedCheckMode(d.SpeedCheckMode)
	ex := make([]string, len(d.Exclude))
	for i, e := range d.Exclude {
		ex[i] = strings.ToLower(strings.TrimSuffix(e, "."))
	}
	thr := d.ThresholdMs
	if thr == 0 {
		thr = 10
	}
	return Params{time.Duration(thr) * time.Millisecond, d.AllowForceAAAA, c, ex}
}

// dropAAAA and dropA are smartdns' _dns_server_force_dualstack: both families have
// addresses, the kept family answered, and the dropped one failed or is slower by at
// least the threshold.
func (e *Entry) dropAAAA(thr time.Duration) bool {
	return !e.CheckedAt.IsZero() && e.Has4 && e.Has6 && e.V4 >= 0 && (e.V6 < 0 || e.V4+thr <= e.V6)
}

func (e *Entry) dropA(thr time.Duration) bool {
	return !e.CheckedAt.IsZero() && e.Has4 && e.Has6 && e.V6 >= 0 && (e.V4 < 0 || e.V6+thr <= e.V4)
}

// ParseSeen parses dsSeen() output ("name count" per line).
func ParseSeen(out string) map[string]int64 {
	m := map[string]int64{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		if n, err := strconv.ParseInt(f[1], 10, 64); err == nil && f[0] != "" {
			m[strings.ToLower(strings.TrimSuffix(f[0], "."))] += n
		}
	}
	return m
}

// Update merges seen into st, forgets names nobody asked for in a week (and excluded
// names) and measures the busiest names that are due.
func Update(ctx context.Context, p Prober, st State, seen map[string]int64, pr Params, now time.Time) {
	for n, hits := range seen {
		if excluded(n, pr.Exclude) {
			continue
		}
		e := st[n]
		if e == nil {
			e = &Entry{}
			st[n] = e
		}
		e.Hits, e.LastSeen = e.Hits+hits, now
	}
	var due []string
	for n, e := range st {
		if now.Sub(e.LastSeen) > forget || excluded(n, pr.Exclude) {
			delete(st, n)
			continue
		}
		every := okRecheck
		if e.dropAAAA(pr.Threshold) || pr.AllowForceAAAA && e.dropA(pr.Threshold) {
			every = dropRecheck
		}
		if e.CheckedAt.IsZero() || now.Sub(e.CheckedAt) > every {
			due = append(due, n)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if a, b := st[due[i]].Hits, st[due[j]].Hits; a != b {
			return a > b
		}
		return due[i] < due[j]
	})
	due = due[:min(len(due), checks)]

	res := make([]Entry, len(due))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, n := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			a := p.Resolve(ctx, n)
			res[i] = Entry{Has4: len(a.V4) > 0, Has6: len(a.V6) > 0, TTL4: a.TTL4, TTL6: a.TTL6,
				V4: speed(ctx, p, pr.Checks, a.V4), V6: speed(ctx, p, pr.Checks, a.V6)}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	for i, n := range due {
		e, r := st[n], res[i]
		e.V4, e.V6, e.Has4, e.Has6, e.TTL4, e.TTL6, e.CheckedAt = r.V4, r.V6, r.Has4, r.Has6, r.TTL4, r.TTL6, now
	}
}

// speed is smartdns' speed check (_dns_server_second_ping_check): every address with the
// first method; each later method starts checkInterval after the previous one unless an
// address already answered. Every answer within smartdns' timeout (950 ms from the start,
// at least 200 ms per probe) counts and the fastest wins; -1 when nothing answered.
func speed(ctx context.Context, p Prober, checks []api.SpeedCheck, ips []string) time.Duration {
	ips = ips[:min(len(ips), perFamily)]
	best := time.Duration(-1)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var once sync.Once
	answered := make(chan struct{})
	start := time.Now()
methods:
	for k, c := range checks {
		if k > 0 {
			select {
			case <-answered:
				break methods
			case <-ctx.Done():
				break methods
			case <-time.After(checkInterval):
			}
		}
		pctx, cancel := context.WithTimeout(ctx, max(probeTimeout-time.Since(start), minProbeTimeout))
		for _, ip := range ips {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if t := p.Probe(pctx, c, ip); t >= 0 {
					mu.Lock()
					if best < 0 || t < best {
						best = t
					}
					mu.Unlock()
					once.Do(func() { close(answered) })
				}
			}()
		}
		defer cancel()
	}
	wg.Wait()
	return best
}

// Item is one listed name with the TTL of the dropped RRset.
type Item struct {
	Name string
	TTL  uint32
}

// Lists returns the names whose AAAA (preferV4) and A (preferV6, only with
// allow_force_aaaa) answers are dropped, sorted, excluded names left out.
func (st State) Lists(pr Params) (preferV4, preferV6 []Item) {
	preferV4, preferV6 = []Item{}, []Item{}
	for n, e := range st {
		if excluded(n, pr.Exclude) { // not forgotten yet: Update runs first on the next drain
			continue
		}
		if e.dropAAAA(pr.Threshold) {
			preferV4 = append(preferV4, Item{n, e.TTL6})
		} else if pr.AllowForceAAAA && e.dropA(pr.Threshold) {
			preferV6 = append(preferV6, Item{n, e.TTL4})
		}
	}
	for _, l := range [][]Item{preferV4, preferV6} {
		sort.Slice(l, func(i, j int) bool { return l[i].Name < l[j].Name })
	}
	return preferV4, preferV6
}

// Lines formats a list for dualstack.lua ("name ttl").
func Lines(items []Item) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = fmt.Sprintf("%s %d", it.Name, it.TTL)
	}
	return out
}

func excluded(name string, exclude []string) bool {
	for _, x := range exclude {
		if name == x || strings.HasSuffix(name, "."+x) {
			return true
		}
	}
	return false
}

// IPv6Ready reports whether this node has an IPv6 route at all (smartdns disables every
// IPv6 feature without one): otherwise every IPv6 check fails and all AAAA would be dropped.
func IPv6Ready() bool {
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53") // no packet is sent
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// NetProber resolves through Resolver (ip:port, the node's upstream) and probes over the
// network.
type NetProber struct{ Resolver string }

func (p NetProber) Resolve(ctx context.Context, name string) Answer {
	var a Answer
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), t)
		c := &dns.Client{Timeout: 3 * time.Second}
		r, _, err := c.ExchangeContext(ctx, m, p.Resolver)
		if err != nil {
			continue
		}
		for _, rr := range r.Answer {
			ttl := rr.Header().Ttl
			switch v := rr.(type) {
			case *dns.A:
				if len(a.V4) == 0 || ttl < a.TTL4 {
					a.TTL4 = ttl
				}
				a.V4 = append(a.V4, v.A.String())
			case *dns.AAAA:
				if len(a.V6) == 0 || ttl < a.TTL6 {
					a.TTL6 = ttl
				}
				a.V6 = append(a.V6, v.AAAA.String())
			}
		}
	}
	return a
}

func (NetProber) Probe(ctx context.Context, c api.SpeedCheck, ip string) time.Duration {
	if c.Port == 0 {
		return ping(ctx, ip)
	}
	d := &net.Dialer{Timeout: probeTimeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(c.Port)))
	if err != nil {
		return -1
	}
	t := time.Since(start)
	conn.Close()
	return t
}

// Checked counts the names measured at least once.
func (st State) Checked() int {
	n := 0
	for _, e := range st {
		if !e.CheckedAt.IsZero() {
			n++
		}
	}
	return n
}
