package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Analytics is the ConfigSpec section for fleet query analytics (SPEC §19).
type Analytics struct {
	Enabled    bool   `json:"enabled"`
	SampleRate int    `json:"sample_rate"` // log 1 in N responses; counts are multiplied back by N
	TopK       int    `json:"top_k"`       // Space-Saving sketch size per kind and day
	StreamAddr string `json:"stream_addr"` // dnstap framestream listener of the agent
}

func DefaultAnalytics() Analytics {
	return Analytics{Enabled: true, SampleRate: 1, TopK: 5000, StreamAddr: "127.0.0.1:6001"}
}

// UnmarshalJSON fills sections missing from specs stored before they existed with their
// defaults (a missing "analytics" would otherwise decode to an invalid zero value).
func (s *ConfigSpec) UnmarshalJSON(b []byte) error {
	type plain ConfigSpec
	p := plain{Analytics: DefaultAnalytics()}
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*s = ConfigSpec(p)
	return nil
}

// Top-list kinds of AnalyticsBatch.Tops and GET /api/v1/analytics?kind=.
const (
	AnalyticsQueried        = "queried"         // raw qname
	AnalyticsQueriedGrouped = "queried_grouped" // registered domain (eTLD+1), raw name when none
	AnalyticsNXDomain       = "nxdomain"        // qname of NXDOMAIN answers
	AnalyticsServfail       = "servfail"        // qname of SERVFAIL answers
)

var AnalyticsKinds = []string{AnalyticsQueried, AnalyticsQueriedGrouped, AnalyticsNXDomain, AnalyticsServfail}

// AnalyticsMaxBody caps the POST /agent/v1/analytics request body.
const AnalyticsMaxBody = 10 << 20

// AnalyticsTopItem is one Space-Saving counter; Error is its over-estimate bound
// (the true count lies in [Count-Error, Count]).
type AnalyticsTopItem struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
	Error int64  `json:"error"`
}

// AnalyticsBatch is POST /agent/v1/analytics: one node's delta since the previous batch
// for one local day. Counts are already multiplied by SampleRate.
type AnalyticsBatch struct {
	Day        string                        `json:"day"` // YYYY-MM-DD
	Total      int64                         `json:"total"`
	ByQType    map[string]int64              `json:"by_qtype"` // "A", "AAAA", … (TYPE123 when unknown)
	ByRcode    map[string]int64              `json:"by_rcode"` // "NOERROR", "NXDOMAIN", "SERVFAIL", …
	SampleRate int                           `json:"sample_rate"`
	Tops       map[string][]AnalyticsTopItem `json:"tops"` // kind → items
}

// Validate checks an agent batch before the panel stores it.
func (b AnalyticsBatch) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if _, err := time.Parse(time.DateOnly, b.Day); err != nil {
		bad("day: %q is not YYYY-MM-DD", b.Day)
	}
	if b.Total < 0 {
		bad("total: must be >= 0")
	}
	if b.SampleRate < 1 || b.SampleRate > 1000 {
		bad("sample_rate: must be 1..1000, got %d", b.SampleRate)
	}
	for field, m := range map[string]map[string]int64{"by_qtype": b.ByQType, "by_rcode": b.ByRcode} {
		for k, v := range m {
			if k == "" || len(k) > 32 || v < 0 {
				bad("%s: bad entry %q=%d", field, k, v)
			}
		}
	}
	for kind, items := range b.Tops {
		if !slices.Contains(AnalyticsKinds, kind) {
			bad("tops: unknown kind %q", kind)
			continue
		}
		for i, it := range items {
			if it.Name == "" || len(it.Name) > 255 || it.Count < 0 || it.Error < 0 || it.Error > it.Count {
				bad("tops.%s[%d]: bad item %q count=%d error=%d", kind, i, it.Name, it.Count, it.Error)
			}
		}
	}
	return errors.Join(errs...)
}

// AnalyticsQuery documents GET /api/v1/analytics and /analytics.csv parameters:
// from/to are dates YYYY-MM-DD (default: the last 7 days), node_id optional (all nodes),
// kind ∈ AnalyticsKinds (default queried), limit 1..1000 (default 100).
const (
	AnalyticsDefaultDays  = 7
	AnalyticsDefaultLimit = 100
	AnalyticsMaxLimit     = 1000 // ended days are trimmed to the top 1000 per kind
)

// AnalyticsReport is GET /api/v1/analytics.
type AnalyticsReport struct {
	From    string              `json:"from"` // YYYY-MM-DD
	To      string              `json:"to"`
	Total   int64               `json:"total"`
	ByQType map[string]int64    `json:"by_qtype"`
	ByRcode map[string]int64    `json:"by_rcode"`
	ByDay   []AnalyticsDay      `json:"by_day"` // every day of the range, zeros included
	Top     []AnalyticsTopEntry `json:"top"`
}

type AnalyticsDay struct {
	Day   string `json:"day"`
	Total int64  `json:"total"`
}

// AnalyticsTopEntry: Share = Count / Total for queried kinds, / by_rcode[NXDOMAIN|SERVFAIL]
// for nxdomain/servfail (0..1). Approximate when any contributing row was sampled or has
// a non-zero Space-Saving error.
type AnalyticsTopEntry struct {
	Rank        int     `json:"rank"` // 1-based
	Name        string  `json:"name"`
	Count       int64   `json:"count"`
	Share       float64 `json:"share"`
	Approximate bool    `json:"approximate"`
}
