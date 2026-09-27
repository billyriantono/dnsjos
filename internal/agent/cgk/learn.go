package cgk

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Automatic exclusion learning (SPEC §6.6). cgk.lua records every rewritten name with
// its real Cloudflare IP and the alias it got; the agent drains that list (cgkSeen())
// and checks the busiest names through both addresses. A name is excluded when its real
// IP does not serve HTTPS for it (a Spectrum or other non-HTTP app: the alias cannot
// carry it either) or the alias answers differently (IP-bound config, WAF rules on the
// address, …; 2xx and 3xx count as the same outcome, see sameOutcome). A mismatch must
// repeat once before it counts.
const (
	learnChecks     = 40 // names checked per run, busiest first
	learnWorkers    = 8
	okRecheck       = 24 * time.Hour
	excludedRecheck = 7 * 24 * time.Hour
	forgetOK        = 7 * 24 * time.Hour  // unseen this long: drop an ok verdict
	forgetExcluded  = 30 * 24 * time.Hour // unseen this long: drop an exclusion
)

// retryDelay separates a mismatch from its confirmation (tests set it to 0).
var retryDelay = 3 * time.Second

// Seen is one line of cgkSeen().
type Seen struct {
	Name, RealIP, AliasIP string
	Hits                  int64
}

// ParseSeen parses cgkSeen() output ("name real-ip alias-ip count" per line).
func ParseSeen(out string) []Seen {
	var s []Seen
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 4 {
			continue
		}
		n, err := strconv.ParseInt(f[3], 10, 64)
		if err != nil || f[0] == "" {
			continue
		}
		s = append(s, Seen{Name: strings.ToLower(strings.TrimSuffix(f[0], ".")), RealIP: f[1], AliasIP: f[2], Hits: n})
	}
	return s
}

// LearnState is the agent's memory of checked names, persisted between runs.
type LearnState map[string]*api.CGKLearned

// Learn merges seen into st, checks the names that are due and reports whether the set
// of excluded names changed.
func Learn(ctx context.Context, p Prober, st LearnState, seen []Seen, now time.Time) (changed bool) {
	for _, s := range seen {
		e := st[s.Name]
		if e == nil {
			e = &api.CGKLearned{Name: s.Name}
			st[s.Name] = e
		}
		if s.RealIP != "-" { // "-": an excluded name, not rewritten, only counted
			e.RealIP, e.AliasIP = s.RealIP, s.AliasIP
		}
		e.Hits, e.LastSeen = e.Hits+s.Hits, now
	}
	for n, e := range st { // forget names nobody asks for any more (or never rewritten)
		if e.RealIP == "" {
			delete(st, n)
			continue
		}
		if age := now.Sub(e.LastSeen); !e.Excluded && age > forgetOK || e.Excluded && age > forgetExcluded {
			delete(st, n)
			changed = changed || e.Excluded
		}
	}

	var due []*api.CGKLearned
	for _, e := range st {
		age := now.Sub(e.CheckedAt)
		if e.CheckedAt.IsZero() || !e.Excluded && age > okRecheck || e.Excluded && age > excludedRecheck {
			due = append(due, e)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if due[i].Hits != due[j].Hits {
			return due[i].Hits > due[j].Hits
		}
		return due[i].Name < due[j].Name
	})
	due = due[:min(len(due), learnChecks)]

	names := make([]string, len(due))
	byName := map[string]*api.CGKLearned{}
	for i, e := range due {
		names[i], byName[e.Name] = e.Name, e
	}
	type verdict struct {
		real, alias string
		bad         bool
	}
	check := func(e *api.CGKLearned) verdict {
		real, _, _ := p.Fetch(ctx, e.Name, e.RealIP, "/")
		alias, _, _ := p.Fetch(ctx, e.Name, e.AliasIP, "/")
		return verdict{real, alias, real == "000" || !sameOutcome(real, alias)}
	}
	results := parallelN(names, learnWorkers, func(n string) verdict {
		v := check(byName[n])
		if v.bad { // confirm: one flaky answer must not exclude a site
			select {
			case <-ctx.Done():
				return verdict{}
			case <-time.After(retryDelay):
			}
			if again := check(byName[n]); !again.bad {
				return again
			}
		}
		return v
	})
	if ctx.Err() != nil {
		return changed
	}
	for n, v := range results {
		e := byName[n]
		changed = changed || e.Excluded != v.bad
		e.RealCode, e.AliasCode, e.Excluded, e.CheckedAt = v.real, v.alias, v.bad, now
	}
	return changed
}

// Excluded returns the excluded entries, busiest first.
func (st LearnState) Excluded() []api.CGKLearned {
	out := []api.CGKLearned{}
	for _, e := range st {
		if e.Excluded {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Checked counts the names with a verdict.
func (st LearnState) Checked() int {
	n := 0
	for _, e := range st {
		if !e.CheckedAt.IsZero() {
			n++
		}
	}
	return n
}
