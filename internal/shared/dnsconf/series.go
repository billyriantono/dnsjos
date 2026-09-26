package dnsconf

// SupportedSeries are the PowerDNS dnsdist repo series (…-dnsdist-<series>) the renderer
// produces valid config for; the panel refuses set_dnsdist_series for anything else (SPEC §18).
var SupportedSeries = []string{"20", "21"}
