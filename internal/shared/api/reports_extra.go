package api

import "time"

// MetricSample is a MetricPoint plus values derived for its step. Its JSON is a superset
// of MetricPoint, so clients typed against Metrics keep working.
type MetricSample struct {
	MetricPoint
	QPS           float64 `json:"qps"`             // queries / step seconds
	CacheHitRatio float64 `json:"cache_hit_ratio"` // cache_hits / (cache_hits + cache_misses), 0..1
}

// MetricSeries is what GET /overview/metrics and GET /nodes/{id}/metrics return: Metrics
// with derived fields per point. Empty buckets are present with zero values.
type MetricSeries struct {
	From   time.Time      `json:"from"`
	To     time.Time      `json:"to"`
	StepS  int            `json:"step_s"`
	Points []MetricSample `json:"points"`
}
