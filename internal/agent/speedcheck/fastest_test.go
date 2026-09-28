package speedcheck

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// table answers ICMP per address (missing = never) and resolves from dns.
type table struct {
	dns  map[string]Answer
	rtt  map[string]time.Duration
	mu   sync.Mutex
	asks int
}

func (f *table) Resolve(_ context.Context, name string) Answer {
	f.mu.Lock()
	f.asks++
	f.mu.Unlock()
	return f.dns[name]
}

func (f *table) Probe(ctx context.Context, m api.SpeedCheckMethod, ip string) time.Duration {
	if t, ok := f.rtt[ip]; ok && m.Port == 0 {
		return t
	}
	<-ctx.Done()
	return -1
}

func TestFastestUpdate(t *testing.T) {
	f := &table{
		dns: map[string]Answer{
			"multi.test": {V4: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, V6: []string{"2001:db8::1"}},
			"dead.test":  {V4: []string{"192.0.2.9", "192.0.2.10"}},
			"skip.test":  {V4: []string{"192.0.2.5", "192.0.2.6"}},
		},
		rtt: map[string]time.Duration{"192.0.2.1": 12300 * time.Microsecond, "192.0.2.2": 4 * ms, "2001:db8::1": 7 * ms,
			"192.0.2.5": ms, "192.0.2.6": ms},
	}
	methods, _ := api.ParseSpeedCheckMode("ping")
	st := State{}
	now := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	seen := ParseSeen("multi.test 4\ndead.test 1\nwww.skip.test 1\n")
	Update(context.Background(), f, st, seen, methods, Names([]string{"Skip.Test."}), false, now)
	// 0.1 ms units; unanswered = -1; IPv6 not probed without an IPv6 route; dead.test (no
	// answering address) and excluded names are not listed.
	want := []string{"multi.test 192.0.2.1 123 192.0.2.2 40 192.0.2.3 -1"}
	if got := st.Lines(); !slices.Equal(got, want) {
		t.Fatalf("Lines = %q, want %q", got, want)
	}
	if st.Checked() != 2 || st["www.skip.test"] != nil {
		t.Errorf("checked %d, state %v", st.Checked(), st)
	}

	Update(context.Background(), f, st, nil, methods, nil, true, now.Add(61*time.Minute)) // due again, now with IPv6
	if got := st.Lines(); !slices.Equal(got, []string{"multi.test 192.0.2.1 123 192.0.2.2 40 192.0.2.3 -1 2001:db8::1 70"}) {
		t.Errorf("with IPv6: %q", got)
	}
	f.asks = 0
	Update(context.Background(), f, st, nil, methods, nil, true, now.Add(90*time.Minute))
	if f.asks != 0 {
		t.Errorf("re-measured %d names within the hour", f.asks)
	}
}
