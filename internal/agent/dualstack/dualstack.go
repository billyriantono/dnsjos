// Package dualstack measures, from this node, whether names answer faster over IPv4 or
// IPv6: smartdns' dualstack-ip-selection (SPEC §6.8). dualstack.lua reports the names
// clients get AAAA answers for (dsSeen()); the agent speed-checks both families with
// package speedcheck and lists the names whose AAAA (or, with allow_force_aaaa, A)
// answers dualstack.lua must drop.
package dualstack

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/billyriantono/dnsjos/internal/agent/speedcheck"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const (
	checks      = 100 // names measured per run, busiest first
	workers     = 16
	okRecheck   = 6 * time.Hour
	dropRecheck = time.Hour // routes change: give the dropped family another chance soon
	forget      = 7 * 24 * time.Hour
)

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
	Methods        []api.SpeedCheckMethod
	Exclude        []string
}

// ParamsOf reads a validated spec: its dualstack section and speed_check.mode.
func ParamsOf(s api.ConfigSpec) Params {
	m, _ := api.ParseSpeedCheckMode(s.SpeedCheck.Mode)
	thr := s.DualStack.ThresholdMs
	if thr == 0 {
		thr = 10
	}
	return Params{time.Duration(thr) * time.Millisecond, s.DualStack.AllowForceAAAA, m, speedcheck.Names(s.DualStack.Exclude)}
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

// Update merges seen into st, forgets names nobody asked for in a week (and excluded
// names) and measures the busiest names that are due.
func Update(ctx context.Context, p speedcheck.Prober, st State, seen map[string]int64, pr Params, now time.Time) {
	for n, hits := range seen {
		if speedcheck.Excluded(n, pr.Exclude) {
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
		if now.Sub(e.LastSeen) > forget || speedcheck.Excluded(n, pr.Exclude) {
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
				V4: speedcheck.Fastest(speedcheck.Measure(ctx, p, pr.Methods, a.V4)),
				V6: speedcheck.Fastest(speedcheck.Measure(ctx, p, pr.Methods, a.V6))}
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
		if speedcheck.Excluded(n, pr.Exclude) { // not forgotten yet: Update runs first on the next drain
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
