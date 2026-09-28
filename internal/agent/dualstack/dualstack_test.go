package dualstack

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const ms = time.Millisecond

// fake answers per "method ip" ("ping 8.8.8.8", "tcp:443 8.8.8.8"); missing = no answer.
type fake struct {
	dns  map[string]Answer
	rtt  map[string]time.Duration
	mu   sync.Mutex
	asks int
}

func (f *fake) Resolve(_ context.Context, name string) Answer {
	f.mu.Lock()
	f.asks++
	f.mu.Unlock()
	return f.dns[name]
}

func (f *fake) Probe(_ context.Context, c api.SpeedCheck, ip string) time.Duration {
	k := "ping " + ip
	if c.Port != 0 {
		k = fmt.Sprintf("tcp:%d %s", c.Port, ip)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.rtt[k]; ok {
		return t
	}
	return -1
}

func names(items []Item) []string {
	var out []string
	for _, it := range items {
		out = append(out, fmt.Sprintf("%s/%d", it.Name, it.TTL))
	}
	return out
}

func TestUpdate(t *testing.T) {
	ans := func(v4, v6 []string) Answer { return Answer{V4: v4, V6: v6, TTL4: 300, TTL6: 60} }
	f := &fake{
		dns: map[string]Answer{
			"dns.google":    ans([]string{"8.8.8.8"}, []string{"2001:4860:4860::8888"}), // v6 routed abroad
			"close.test":    ans([]string{"192.0.2.1"}, []string{"2001:db8::1"}),        // within the threshold
			"v6down.test":   ans([]string{"192.0.2.2"}, []string{"2001:db8::2"}),        // v6 answers nothing
			"v4down.test":   ans([]string{"192.0.2.3"}, []string{"2001:db8::3"}),        // v4 answers nothing
			"multi.test":    ans([]string{"192.0.2.4", "192.0.2.5"}, []string{"2001:db8::4"}),
			"fallback.test": ans([]string{"192.0.2.6"}, []string{"2001:db8::6"}), // no ICMP: tcp:80 decides
			"v4only.test":   ans([]string{"192.0.2.7"}, nil),                     // nothing to drop
			"skip.example":  ans([]string{"192.0.2.8"}, []string{"2001:db8::8"}), // excluded
		},
		rtt: map[string]time.Duration{
			"ping 8.8.8.8": 5 * ms, "ping 2001:4860:4860::8888": 150 * ms,
			"ping 192.0.2.1": 20 * ms, "ping 2001:db8::1": 25 * ms,
			"ping 192.0.2.2":   20 * ms,
			"ping 2001:db8::3": 90 * ms,
			"ping 192.0.2.4":   80 * ms, "ping 192.0.2.5": 10 * ms, "ping 2001:db8::4": 30 * ms, // fastest v4 counts
			"tcp:80 192.0.2.6": 50 * ms, "tcp:80 2001:db8::6": 20 * ms, "tcp:443 192.0.2.6": 1 * ms, // tcp:443 never reached
			"ping 192.0.2.7": 1 * ms,
			"ping 192.0.2.8": 1 * ms, "ping 2001:db8::8": 100 * ms,
		},
	}
	seen := ParseSeen("dns.google. 3\nclose.test 1\nv6down.test 1\nv4down.test 1\nmulti.test 1\nfallback.test 1\nv4only.test 1\nsub.skip.example 1\nskip.example 1\nbad line here\n")
	st := State{}
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	pr := ParamsOf(api.DualStack{ThresholdMs: 10, Exclude: []string{"Skip.Example."}})
	Update(context.Background(), f, st, seen, pr, now)

	v4, v6 := st.Lists(pr)
	if want := []string{"dns.google/60", "multi.test/60", "v6down.test/60"}; !slices.Equal(names(v4), want) || len(v6) != 0 {
		t.Fatalf("lists = %v %v, want %v []", names(v4), names(v6), want)
	}
	pr.AllowForceAAAA = true // dualstack-ip-allow-force-AAAA: A dropped when IPv6 wins
	if _, v6 := st.Lists(pr); !slices.Equal(names(v6), []string{"fallback.test/300", "v4down.test/300"}) {
		t.Errorf("force AAAA: %v", names(v6))
	}
	pr.AllowForceAAAA, pr.Threshold = false, 200*ms
	if v4, _ := st.Lists(pr); !slices.Equal(names(v4), []string{"v6down.test/60"}) {
		t.Errorf("a higher threshold keeps only the broken IPv6: %v", names(v4))
	}
	pr.Threshold = 10 * ms

	f.asks = 0 // nothing is due 30 min later
	Update(context.Background(), f, st, nil, pr, now.Add(30*time.Minute))
	if f.asks != 0 {
		t.Errorf("re-measured %d names too early", f.asks)
	}
	f.rtt["ping 2001:4860:4860::8888"] = 6 * ms // IPv6 route fixed: re-checked after an hour
	Update(context.Background(), f, st, map[string]int64{"dns.google": 1}, pr, now.Add(61*time.Minute))
	if v4, _ := st.Lists(pr); slices.Contains(names(v4), "dns.google/60") || f.asks != 3 {
		t.Errorf("after the fix: %v (%d re-measured, want the 3 listed names)", names(v4), f.asks)
	}
	Update(context.Background(), f, st, map[string]int64{"dns.google": 1}, pr, now.Add(8*24*time.Hour))
	if len(st) != 1 || st["dns.google"] == nil {
		t.Errorf("names unseen for a week not forgotten: %v", st)
	}
}

func TestParseSpeedCheckMode(t *testing.T) {
	c, err := api.ParseSpeedCheckMode("")
	if err != nil || !slices.Equal(c, []api.SpeedCheck{{}, {Port: 80}, {Port: 443}}) {
		t.Errorf("default = %v %v", c, err)
	}
	if c, err := api.ParseSpeedCheckMode(" none "); err != nil || c == nil || len(c) != 0 {
		t.Errorf("none = %v %v", c, err)
	}
	for _, bad := range []string{"icmp", "tcp:", "tcp:0", "tcp:70000", "ping,,tcp:80", "none,ping"} {
		if _, err := api.ParseSpeedCheckMode(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestPing needs ICMP (unprivileged sockets on macOS/Linux with ping_group_range, or root).
func TestPing(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	if d := ping(context.Background(), "127.0.0.1"); d < 0 {
		t.Skip("ICMP sockets not permitted here")
	}
	if d := ping(context.Background(), "192.0.2.123"); d >= 0 { // TEST-NET-1: never answers
		t.Errorf("ping of an unroutable address answered in %v", d)
	}
}

// sleeper answers each method after a real delay (missing = never), recording what ran.
type sleeper struct {
	after map[int]time.Duration // port (0 = ping) → answer time
	mu    sync.Mutex
	ran   []int
}

func (s *sleeper) Resolve(context.Context, string) Answer { return Answer{} }
func (s *sleeper) Probe(ctx context.Context, c api.SpeedCheck, _ string) time.Duration {
	s.mu.Lock()
	s.ran = append(s.ran, c.Port)
	s.mu.Unlock()
	d, ok := s.after[c.Port]
	if !ok {
		<-ctx.Done() // the per-probe timeout
		return -1
	}
	select {
	case <-time.After(d):
		return d
	case <-ctx.Done():
		return -1
	}
}

// TestSpeedStaggered: like smartdns, tcp:80 starts 100 ms in when ping has not answered and
// the fastest answer of either wins; a ping answering first means tcp never starts.
func TestSpeedStaggered(t *testing.T) {
	checks, _ := api.ParseSpeedCheckMode("")
	s := &sleeper{after: map[int]time.Duration{0: 300 * ms, 80: 20 * ms}}
	if got := speed(context.Background(), s, checks, []string{"192.0.2.1"}); got != 20*ms {
		t.Errorf("slow ping + fast tcp:80 = %v, want 20ms", got)
	}
	if !slices.Equal(s.ran, []int{0, 80}) {
		t.Errorf("methods run = %v, want ping then tcp:80 (tcp:443 not needed)", s.ran)
	}
	s = &sleeper{after: map[int]time.Duration{0: 30 * ms, 80: 1 * ms}}
	if got := speed(context.Background(), s, checks, []string{"192.0.2.1"}); got != 30*ms || !slices.Equal(s.ran, []int{0}) {
		t.Errorf("fast ping = %v after %v, want 30ms after ping only", got, s.ran)
	}
	s = &sleeper{after: map[int]time.Duration{}}
	start := time.Now()
	if got := speed(context.Background(), s, checks, []string{"192.0.2.1"}); got != -1 || !slices.Equal(s.ran, []int{0, 80, 443}) {
		t.Errorf("nothing answers = %v after %v", got, s.ran)
	}
	if el := time.Since(start); el > 1200*ms {
		t.Errorf("gave up after %v, want ≈950ms", el)
	}
}
