package api

// Contract items for SPEC §10 routes that reuse existing DTOs:
//   POST /profiles/{id}/preview          → RenderedConfig (spec echoed back, files rendered with masked secrets)
//   GET  /profiles/{id}/versions/{a}/diff/{b} → ConfigVersionDiff (both versions + changes)
//   GET  /nodes/{id}/cgk                 → *CGKReport (latest report, JSON null when none yet)
//   POST /nodes/{id}/commands            → 202 Command (queued)
//   GET  /overview/metrics               → MetricSeries (all nodes summed per step)
//   GET  /nodes/{id}/metrics             → MetricSeries

// CSV export kinds for GET /api/v1/reports/blocked.csv?kind=.
const (
	CSVSummary = "summary" // node_id,node_name,count
	CSVMonthly = "monthly" // month,count
	CSVTop     = "top"     // qname,count
)

var CSVKinds = []string{CSVSummary, CSVMonthly, CSVTop}
