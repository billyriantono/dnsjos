package speedcheck

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Fastest-IP answers (SPEC §6.9). fastest-ip.lua reports names whose A or AAAA answers
// hold several addresses (fipSeen()); the agent measures every address and writes the
// times, and fastest-ip.lua applies smartdns' choice to each upstream answer.
const (
	checks  = 100 // names measured per run, busiest first
	workers = 16
	recheck = time.Hour
	forget  = 7 * 24 * time.Hour
)

// Entry is one measured name: every address's time, -1 = no answer.
type Entry struct {
	Hits      int64                    `json:"hits"`
	LastSeen  time.Time                `json:"last_seen"`
	CheckedAt time.Time                `json:"checked_at"`
	Times     map[string]time.Duration `json:"times"`
}

// State is the agent's memory of measured names, persisted between runs.
type State map[string]*Entry

// Update merges seen into st, forgets names nobody asked for in a week (and excluded
// names) and measures the busiest names that are due. IPv6 addresses are only measured
// when ipv6 (the node has an IPv6 route).
func Update(ctx context.Context, p Prober, st State, seen map[string]int64, methods []api.SpeedCheckMethod,
	exclude []string, ipv6 bool, now time.Time) {
	for n, hits := range seen {
		if Excluded(n, exclude) {
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
		if now.Sub(e.LastSeen) > forget || Excluded(n, exclude) {
			delete(st, n)
			continue
		}
		if e.CheckedAt.IsZero() || now.Sub(e.CheckedAt) > recheck {
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

	res := make([]map[string]time.Duration, len(due))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, n := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			a := p.Resolve(ctx, n)
			t := Measure(ctx, p, methods, a.V4) // A and AAAA are separate requests in smartdns
			if ipv6 {
				for ip, d := range Measure(ctx, p, methods, a.V6) {
					t[ip] = d
				}
			}
			res[i] = t
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	for i, n := range due {
		st[n].Times, st[n].CheckedAt = res[i], now
	}
}

// Lines formats the list for fastest-ip.lua: "name ip time ip time …", times in 0.1 ms
// (smartdns' unit), -1 = no answer; names without any answering address are left out.
func (st State) Lines() []string {
	out := []string{}
	for n, e := range st {
		if Fastest(e.Times) < 0 {
			continue
		}
		ips := make([]string, 0, len(e.Times))
		for ip := range e.Times {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		var b strings.Builder
		b.WriteString(n)
		for _, ip := range ips {
			t := int64(-1)
			if d := e.Times[ip]; d >= 0 {
				t = max(int64(d/(100*time.Microsecond)), 1) // smartdns: rtt 0 counts as 1
			}
			fmt.Fprintf(&b, " %s %d", ip, t)
		}
		out = append(out, b.String())
	}
	sort.Strings(out)
	return out
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
