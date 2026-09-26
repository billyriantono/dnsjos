// Package analytics aggregates dnsdist's analytics dnstap stream (every response)
// into per-day totals and Space-Saving top-K sketches (SPEC §19).
package analytics

import (
	"cmp"
	"container/heap"
	"slices"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Sketch is a Space-Saving top-K counter (Metwally et al.): at most K names are kept;
// a new name replaces the smallest counter and inherits its count as error. Every
// name with a true count > N/K is present, and each count over-estimates the true
// count by at most its Error (≤ N/K), N being the sum of all weights.
type Sketch struct {
	k   int
	idx map[string]int // name → position in h
	h   ssHeap
}

func NewSketch(k int) *Sketch {
	idx := make(map[string]int, k)
	return &Sketch{k: k, idx: idx, h: ssHeap{idx: idx}}
}

// Add counts name with weight w (> 0).
func (s *Sketch) Add(name string, w int64) {
	if i, ok := s.idx[name]; ok {
		s.h.items[i].Count += w
		heap.Fix(&s.h, i)
		return
	}
	if len(s.h.items) < s.k {
		heap.Push(&s.h, api.AnalyticsTopItem{Name: name, Count: w})
		return
	}
	m := s.h.items[0]
	delete(s.idx, m.Name)
	s.h.items[0] = api.AnalyticsTopItem{Name: name, Count: m.Count + w, Error: m.Count}
	s.idx[name] = 0
	heap.Fix(&s.h, 0)
}

func (s *Sketch) Len() int { return len(s.h.items) }

// Top returns the counters, largest first (ties by name).
func (s *Sketch) Top() []api.AnalyticsTopItem {
	out := slices.Clone(s.h.items)
	slices.SortFunc(out, func(a, b api.AnalyticsTopItem) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Name, b.Name))
	})
	return out
}

// ssHeap is a min-heap on Count that keeps idx in sync.
type ssHeap struct {
	items []api.AnalyticsTopItem
	idx   map[string]int
}

func (h ssHeap) Len() int           { return len(h.items) }
func (h ssHeap) Less(i, j int) bool { return h.items[i].Count < h.items[j].Count }
func (h ssHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.idx[h.items[i].Name], h.idx[h.items[j].Name] = i, j
}
func (h *ssHeap) Push(x any) {
	it := x.(api.AnalyticsTopItem)
	h.idx[it.Name] = len(h.items)
	h.items = append(h.items, it)
}
func (h *ssHeap) Pop() any { panic("unused") }
