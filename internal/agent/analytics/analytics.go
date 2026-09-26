package analytics

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
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

// dayTops holds one local day's sketches; they live across flushes (tops protocol
// v2, "cumulative") under a random epoch that is new on agent start, on day rollover
// and when top_k changes, so the panel can fold an older epoch's counts away.
type dayTops struct {
	day, epoch string
	tops       map[string]*Sketch
	sent       map[string]map[string]api.AnalyticsTopItem // kind → name → last item sent; ⊆ sketch after a flush
}

func newDayTops(day string, k int) *dayTops {
	d := &dayTops{day: day, epoch: rand.Text(), tops: map[string]*Sketch{}, sent: map[string]map[string]api.AnalyticsTopItem{}}
	for _, kind := range api.AnalyticsKinds {
		d.tops[kind], d.sent[kind] = NewSketch(k), map[string]api.AnalyticsTopItem{}
	}
	return d
}

// Agg aggregates responses: per-day sketches (memory bounded by 4 × TopK names plus
// what was last sent of them) and the totals since the last flush.
type Agg struct {
	Loc *time.Location // day boundary; default time.Local

	mu               sync.Mutex
	rate, k          int
	cur              *dayTops
	total            int64
	byQType, byRcode map[string]int64
	finished         []api.AnalyticsBatch // flushed, not yet taken
}

// Configure sets the sample rate and sketch size (topK 0 = off); a change flushes so
// every batch has one sample rate, and a new top_k starts a new sketch (and epoch).
func (a *Agg) Configure(sampleRate, topK int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sampleRate, topK = max(sampleRate, 1), max(topK, 0)
	if sampleRate != a.rate || topK != a.k {
		a.flush()
		if topK != a.k {
			a.cur = nil
		}
		a.rate, a.k = sampleRate, topK
	}
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
		a.flush()
		a.cur = newDayTops(day, a.k)
	}
	if a.byQType == nil {
		a.byQType, a.byRcode = map[string]int64{}, map[string]int64{}
	}
	n := int64(a.rate)
	a.total += n
	a.byQType[qtype] += n
	a.byRcode[rcode] += n
	if len(name) > 255 { // escaped binary labels; the panel rejects such names
		return
	}
	d := a.cur
	d.tops[api.AnalyticsQueried].Add(name, n)
	group, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		group = name
	}
	d.tops[api.AnalyticsQueriedGrouped].Add(group, n)
	switch rcode {
	case "NXDOMAIN":
		d.tops[api.AnalyticsNXDomain].Add(name, n)
	case "SERVFAIL":
		d.tops[api.AnalyticsServfail].Add(name, n)
	}
}

// Take flushes and returns every pending batch, oldest first.
func (a *Agg) Take() []api.AnalyticsBatch {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flush()
	out := a.finished
	a.finished = nil
	return out
}

// flush turns the totals since the last flush and the top items whose (count, error)
// changed since they were last sent (plus names evicted since) into POST-sized
// batches: the first carries the totals, the tops are spread over as many as needed.
func (a *Agg) flush() {
	d := a.cur
	if d == nil {
		return
	}
	newBatch := func() api.AnalyticsBatch {
		return api.AnalyticsBatch{Day: d.day, ByQType: map[string]int64{}, ByRcode: map[string]int64{}, SampleRate: a.rate,
			Tops: map[string][]api.AnalyticsTopItem{}, Epoch: d.epoch, TopsMode: api.AnalyticsTopsCumulative, Evicted: map[string][]string{}}
	}
	b := newBatch()
	if a.total > 0 {
		b.Total, b.ByQType, b.ByRcode = a.total, a.byQType, a.byRcode
		a.total, a.byQType, a.byRcode = 0, map[string]int64{}, map[string]int64{}
	}
	n, size := 0, 0
	room := func(v any) { // start a new batch when v does not fit
		raw, _ := json.Marshal(v)
		if n == maxBatchItems || size+len(raw)+1 > maxBatchBytes {
			a.finished = append(a.finished, b)
			b, n, size = newBatch(), 0, 0
		}
		n, size = n+1, size+len(raw)+1
	}
	for _, kind := range api.AnalyticsKinds {
		sk, sent := d.tops[kind], d.sent[kind]
		for _, it := range sk.Top() {
			if sent[it.Name] != it {
				sent[it.Name] = it
				room(it)
				b.Tops[kind] = append(b.Tops[kind], it)
			}
		}
		var gone []string
		for name := range sent {
			if _, ok := sk.idx[name]; !ok {
				gone = append(gone, name)
			}
		}
		slices.Sort(gone)
		for _, name := range gone {
			delete(sent, name)
			room(name)
			b.Evicted[kind] = append(b.Evicted[kind], name)
		}
	}
	if n > 0 || b.Total > 0 {
		a.finished = append(a.finished, b)
	}
}
