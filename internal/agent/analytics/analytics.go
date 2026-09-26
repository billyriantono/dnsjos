package analytics

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// maxBatchItems and maxBatchBytes keep each POST well under api.AnalyticsMaxBody,
// also with long names.
const (
	maxBatchItems = 40000
	maxBatchBytes = 8 << 20
)

// window is one flush window of one day at one sample rate.
type window struct {
	day              string
	rate             int
	total            int64
	byQType, byRcode map[string]int64
	tops             map[string]*Sketch
}

func newWindow(day string, rate, k int) *window {
	w := &window{day: day, rate: rate, byQType: map[string]int64{}, byRcode: map[string]int64{}, tops: map[string]*Sketch{}}
	for _, kind := range api.AnalyticsKinds {
		w.tops[kind] = NewSketch(k)
	}
	return w
}

// Agg aggregates responses into the current window; memory is bounded by 4 × TopK
// names plus the (small) qtype/rcode maps, whatever the number of distinct names.
type Agg struct {
	Loc *time.Location // day boundary; default time.Local

	mu       sync.Mutex
	rate, k  int
	cur      *window
	finished []*window // closed by a day rollover or a config change, not yet taken
}

// Configure sets the sample rate and sketch size (topK 0 = off); a change closes the
// current window so every batch has one sample rate.
func (a *Agg) Configure(sampleRate, topK int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sampleRate != a.rate || topK != a.k {
		a.closeWindow()
		a.rate, a.k = max(sampleRate, 1), max(topK, 0)
	}
}

func (a *Agg) closeWindow() {
	if a.cur != nil && a.cur.total > 0 {
		a.finished = append(a.finished, a.cur)
	}
	a.cur = nil
}

// Observe counts one dnstap response (a dnstap.Observer); queries are ignored.
func (a *Agg) Observe(t time.Time, m *dns.Msg) {
	if !m.Response {
		return
	}
	q := m.Question[0]
	qtype, ok := dns.TypeToString[q.Qtype]
	if !ok {
		qtype = fmt.Sprintf("TYPE%d", q.Qtype)
	}
	rcode, ok := dns.RcodeToString[m.Rcode]
	if !ok {
		rcode = fmt.Sprintf("RCODE%d", m.Rcode)
	}
	name := strings.ToLower(q.Name)
	if name != "." {
		name = strings.TrimSuffix(name, ".")
	}
	loc := a.Loc
	if loc == nil {
		loc = time.Local
	}
	a.add(t.In(loc).Format(time.DateOnly), name, qtype, rcode)
}

func (a *Agg) add(day, name, qtype, rcode string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.k == 0 {
		return // not configured: analytics disabled
	}
	if a.cur == nil || day > a.cur.day { // late messages of an ended day count for today
		a.closeWindow()
		a.cur = newWindow(day, a.rate, a.k)
	}
	w, n := a.cur, int64(a.rate)
	w.total += n
	w.byQType[qtype] += n
	w.byRcode[rcode] += n
	if len(name) > 255 { // escaped binary labels; the panel rejects such names
		return
	}
	w.tops[api.AnalyticsQueried].Add(name, n)
	group, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		group = name
	}
	w.tops[api.AnalyticsQueriedGrouped].Add(group, n)
	switch rcode {
	case "NXDOMAIN":
		w.tops[api.AnalyticsNXDomain].Add(name, n)
	case "SERVFAIL":
		w.tops[api.AnalyticsServfail].Add(name, n)
	}
}

// Take closes the current window and returns every closed window as POST-sized
// batches, oldest day first.
func (a *Agg) Take() []api.AnalyticsBatch {
	a.mu.Lock()
	a.closeWindow()
	ws := a.finished
	a.finished = nil
	a.mu.Unlock()
	var out []api.AnalyticsBatch
	for _, w := range ws {
		out = append(out, w.batches()...)
	}
	return out
}

// batches splits a window: the first batch carries the totals, the tops are spread
// over as many batches as needed (the panel adds them up).
func (w *window) batches() []api.AnalyticsBatch {
	b := api.AnalyticsBatch{Day: w.day, Total: w.total, ByQType: w.byQType, ByRcode: w.byRcode, SampleRate: w.rate,
		Tops: map[string][]api.AnalyticsTopItem{}}
	out := []api.AnalyticsBatch{}
	n, size := 0, 0
	for _, kind := range api.AnalyticsKinds {
		for _, it := range w.tops[kind].Top() {
			raw, _ := json.Marshal(it)
			if n == maxBatchItems || size+len(raw)+1 > maxBatchBytes {
				out = append(out, b)
				b = api.AnalyticsBatch{Day: w.day, ByQType: map[string]int64{}, ByRcode: map[string]int64{}, SampleRate: w.rate,
					Tops: map[string][]api.AnalyticsTopItem{}}
				n, size = 0, 0
			}
			b.Tops[kind] = append(b.Tops[kind], it)
			n, size = n+1, size+len(raw)+1
		}
	}
	return append(out, b)
}
