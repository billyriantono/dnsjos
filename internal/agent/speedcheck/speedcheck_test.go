package speedcheck

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const ms = time.Millisecond

func TestParseSpeedCheckMode(t *testing.T) {
	c, err := api.ParseSpeedCheckMode("")
	if err != nil || !slices.Equal(c, []api.SpeedCheckMethod{{}, {Port: 80}, {Port: 443}}) {
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
func (s *sleeper) Probe(ctx context.Context, c api.SpeedCheckMethod, _ string) time.Duration {
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
	if got := Fastest(Measure(context.Background(), s, checks, []string{"192.0.2.1"})); got != 20*ms {
		t.Errorf("slow ping + fast tcp:80 = %v, want 20ms", got)
	}
	if !slices.Equal(s.ran, []int{0, 80}) {
		t.Errorf("methods run = %v, want ping then tcp:80 (tcp:443 not needed)", s.ran)
	}
	s = &sleeper{after: map[int]time.Duration{0: 30 * ms, 80: 1 * ms}}
	if got := Fastest(Measure(context.Background(), s, checks, []string{"192.0.2.1"})); got != 30*ms || !slices.Equal(s.ran, []int{0}) {
		t.Errorf("fast ping = %v after %v, want 30ms after ping only", got, s.ran)
	}
	s = &sleeper{after: map[int]time.Duration{}}
	start := time.Now()
	if got := Fastest(Measure(context.Background(), s, checks, []string{"192.0.2.1"})); got != -1 || !slices.Equal(s.ran, []int{0, 80, 443}) {
		t.Errorf("nothing answers = %v after %v", got, s.ran)
	}
	if el := time.Since(start); el > 1200*ms {
		t.Errorf("gave up after %v, want ≈950ms", el)
	}
}
