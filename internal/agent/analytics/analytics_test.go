package analytics

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// checkBounds verifies the Space-Saving guarantees against the true counts.
func checkBounds(t *testing.T, s *Sketch, truth map[string]int64, n int64, k int) {
	t.Helper()
	top := s.Top()
	got := map[string]api.AnalyticsTopItem{}
	var sum int64
	for _, it := range top {
		got[it.Name] = it
		sum += it.Count
		tr := truth[it.Name]
		if it.Count-it.Error > tr || tr > it.Count {
			t.Fatalf("%s: true %d outside [%d, %d]", it.Name, tr, it.Count-it.Error, it.Count)
		}
		if it.Error > n/int64(k) {
			t.Fatalf("%s: error %d > N/K = %d", it.Name, it.Error, n/int64(k))
		}
	}
	if sum != n {
		t.Fatalf("sum of counters %d != N %d", sum, n)
	}
	for name, c := range truth {
		if _, ok := got[name]; c > n/int64(k) && !ok {
			t.Fatalf("heavy hitter %s (%d > N/K = %d) missing", name, c, n/int64(k))
		}
	}
	if len(top) > k {
		t.Fatalf("%d counters > K %d", len(top), k)
	}
}

func TestSketchExactBelowK(t *testing.T) {
	s := NewSketch(10)
	truth := map[string]int64{}
	for i := range 1000 {
		name := fmt.Sprintf("n%d", i%7)
		s.Add(name, 3)
		truth[name] += 3
	}
	for _, it := range s.Top() {
		if it.Error != 0 || it.Count != truth[it.Name] {
			t.Fatalf("%+v, want exact %d", it, truth[it.Name])
		}
	}
	checkBounds(t, s, truth, 3000, 10)
}

func TestSketchZipf(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	z := rand.NewZipf(r, 1.2, 1, 20000)
	for _, k := range []int{50, 200} {
		s := NewSketch(k)
		truth := map[string]int64{}
		var n int64
		for range 300000 {
			name := fmt.Sprintf("d%d.example", z.Uint64())
			w := int64(1 + r.IntN(3)) // weighted adds, as with sample_rate > 1
			s.Add(name, w)
			truth[name] += w
			n += w
		}
		checkBounds(t, s, truth, n, k)
		if top := s.Top(); top[0].Name != "d0.example" || top[1].Name != "d1.example" {
			t.Fatalf("K=%d: top %v", k, top[:2])
		}
	}
}

// TestSketchAdversarial: planted heavy hitters inside a stream of unique names.
func TestSketchAdversarial(t *testing.T) {
	s := NewSketch(100)
	truth := map[string]int64{}
	var n int64
	for i := range 200000 {
		name := fmt.Sprintf("u%d", i)
		if i%10 == 0 {
			name = fmt.Sprintf("hot%d", i%3) // ~6667 each, above N/K = 2000
		}
		s.Add(name, 1)
		truth[name]++
		n++
	}
	checkBounds(t, s, truth, n, 100)
}

func msg(name string, qtype uint16, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Response, m.Rcode = true, rcode
	return m
}

func TestAgg(t *testing.T) {
	a := &Agg{Loc: time.UTC}
	d1 := time.Date(2026, 9, 26, 23, 59, 0, 0, time.UTC)
	a.Observe(d1, msg("www.Example.com.", dns.TypeA, dns.RcodeSuccess)) // not configured: ignored
	a.Configure(2, 100)
	a.Observe(d1, msg("www.Example.com.", dns.TypeA, dns.RcodeSuccess))
	a.Observe(d1, msg("mail.example.com.", dns.TypeAAAA, dns.RcodeSuccess))
	a.Observe(d1, msg("nope.example.invalid.", dns.TypeA, dns.RcodeNameError))
	a.Observe(d1, msg("broken.example.co.uk.", 65280, dns.RcodeServerFailure))
	a.Observe(d1, msg(".", dns.TypeNS, dns.RcodeSuccess))
	q := msg("query.example.", dns.TypeA, 0)
	q.Response = false
	a.Observe(d1, q) // queries are not counted
	a.Observe(d1.Add(2*time.Minute), msg("next.example.org.", dns.TypeA, dns.RcodeSuccess))
	a.Observe(d1, msg("late.example.org.", dns.TypeA, dns.RcodeSuccess)) // late: counts for the new day

	b := a.Take()
	if len(b) != 2 || b[0].Day != "2026-09-26" || b[1].Day != "2026-09-27" {
		t.Fatalf("batches %+v", b)
	}
	d := b[0]
	if d.Total != 10 || d.SampleRate != 2 || d.ByQType["A"] != 4 || d.ByQType["AAAA"] != 2 || d.ByQType["TYPE65280"] != 2 ||
		d.ByRcode["NOERROR"] != 6 || d.ByRcode["NXDOMAIN"] != 2 || d.ByRcode["SERVFAIL"] != 2 {
		t.Fatalf("day 1: %+v", d)
	}
	names := func(items []api.AnalyticsTopItem) map[string]int64 {
		m := map[string]int64{}
		for _, it := range items {
			m[it.Name] = it.Count
		}
		return m
	}
	if g := names(d.Tops[api.AnalyticsQueried]); g["www.example.com"] != 2 || g["."] != 2 || len(g) != 5 {
		t.Fatalf("queried %v", g)
	}
	if g := names(d.Tops[api.AnalyticsQueriedGrouped]); g["example.com"] != 4 || g["example.invalid"] != 2 || g["example.co.uk"] != 2 || g["."] != 2 {
		t.Fatalf("grouped %v", g)
	}
	if g := names(d.Tops[api.AnalyticsNXDomain]); len(g) != 1 || g["nope.example.invalid"] != 2 {
		t.Fatalf("nxdomain %v", g)
	}
	if g := names(d.Tops[api.AnalyticsServfail]); len(g) != 1 || g["broken.example.co.uk"] != 2 {
		t.Fatalf("servfail %v", g)
	}
	if b[1].Total != 4 || len(b[1].Tops[api.AnalyticsQueried]) != 2 {
		t.Fatalf("day 2: %+v", b[1])
	}
	for _, x := range b {
		if err := x.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.Take()) != 0 {
		t.Fatal("Take must reset")
	}

	// a sample-rate change closes the window: one rate per batch
	a.Observe(d1.Add(time.Hour), msg("a.example.", dns.TypeA, 0))
	a.Configure(1, 100)
	a.Observe(d1.Add(time.Hour), msg("a.example.", dns.TypeA, 0))
	if b := a.Take(); len(b) != 2 || b[0].SampleRate != 2 || b[0].Total != 2 || b[1].SampleRate != 1 || b[1].Total != 1 {
		t.Fatalf("rate change: %+v", b)
	}
	a.Configure(1, 0) // off
	a.Observe(d1.Add(time.Hour), msg("a.example.", dns.TypeA, 0))
	if b := a.Take(); len(b) != 0 {
		t.Fatalf("disabled: %+v", b)
	}
}

func TestBatchesSplit(t *testing.T) {
	a := &Agg{}
	a.Configure(1, maxBatchItems+500)
	for i := range maxBatchItems + 500 {
		a.add("2026-09-27", fmt.Sprintf("n%d.example%d.com", i, i), "A", "NOERROR")
	}
	b := a.Take()
	total, items := int64(0), 0
	for i, x := range b {
		n := 0
		for _, it := range x.Tops {
			n += len(it)
		}
		if n > maxBatchItems || (i > 0 && x.Total != 0) || x.Validate() != nil {
			t.Fatalf("batch %d: %d items, total %d, %v", i, n, x.Total, x.Validate())
		}
		total += x.Total
		items += n
	}
	if len(b) != 3 || total != maxBatchItems+500 || items != 2*(maxBatchItems+500) {
		t.Fatalf("%d batches, total %d, items %d", len(b), total, items)
	}
}

// TestBoundedMemory: a million distinct names keep every sketch at K entries.
func TestBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	const k = 5000
	a := &Agg{}
	a.Configure(1, k)
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	r := rand.New(rand.NewPCG(3, 4))
	for range 1_000_000 {
		rc := "NOERROR"
		if r.IntN(4) == 0 {
			rc = "NXDOMAIN"
		}
		a.add("2026-09-27", fmt.Sprintf("%x.%x.example", r.Uint64(), r.Uint32()), "A", rc)
	}
	var after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&after)
	a.mu.Lock()
	for kind, s := range a.cur.tops {
		if s.Len() > k || len(s.idx) != s.Len() {
			t.Errorf("%s: %d counters, %d indexed, K %d", kind, s.Len(), len(s.idx), k)
		}
	}
	a.mu.Unlock()
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 16<<20 {
		t.Fatalf("heap grew by %d MiB for 4 sketches of %d", grew>>20, k)
	}
	if b := a.Take(); b[0].Total != 1_000_000 {
		t.Fatalf("total %d", b[0].Total)
	}
}
