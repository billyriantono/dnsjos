package api

// UpgradeSeries is the UpgradeResult.Kind the agent reports for a set_dnsdist_series
// command (From/To are series, e.g. "20" → "21"). It is not an UpgradeRun kind.
const UpgradeSeries = "series"
