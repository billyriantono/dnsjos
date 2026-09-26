//go:build ui

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Well-known public names; the grouped list folds subdomains into their registered domain.
var popular = strings.Fields(`www.google.com google.com youtube.com i.ytimg.com graph.facebook.com
	www.facebook.com api.whatsapp.net web.whatsapp.com www.instagram.com scontent.cdninstagram.com
	www.tiktok.com api.tiktokv.com www.wikipedia.org en.wikipedia.org example.com www.example.com
	api.example.org cdn.example.net time.cloudflare.com one.one.one.one`)

// seedAnalytics posts 45 days of analytics batches (SPEC §19) for a node; dns3 samples 1 in 10.
func seedAnalytics(n *node, i int) {
	rate := 1
	if i == 2 {
		rate = 10
	}
	for d := range 45 {
		day := time.Now().AddDate(0, 0, -d).Format(time.DateOnly)
		scale := int64(100_000 + 20_000*i + (d*7919)%40_000)
		b := api.AnalyticsBatch{Day: day, SampleRate: rate, Total: scale * 10,
			ByQType: map[string]int64{"A": scale * 5, "AAAA": scale * 3, "HTTPS": scale, "PTR": scale / 2, "TXT": scale / 4, "MX": scale / 8, "TYPE65": scale / 8},
			ByRcode: map[string]int64{"NOERROR": scale*10 - scale*8/10 - scale/50, "NXDOMAIN": scale * 8 / 10, "SERVFAIL": scale / 50},
			Tops:    map[string][]api.AnalyticsTopItem{}}
		grouped := map[string]int64{}
		for k, name := range popular {
			c := scale * 3 / int64(k+2)
			var e int64
			if k > 15 {
				e = c / 20 // long-tail Space-Saving error → approximate
			}
			b.Tops[api.AnalyticsQueried] = append(b.Tops[api.AnalyticsQueried], api.AnalyticsTopItem{Name: name, Count: c, Error: e})
			parts := strings.Split(name, ".")
			grouped[strings.Join(parts[max(0, len(parts)-2):], ".")] += c
		}
		for name, c := range grouped {
			b.Tops[api.AnalyticsQueriedGrouped] = append(b.Tops[api.AnalyticsQueriedGrouped], api.AnalyticsTopItem{Name: name, Count: c})
		}
		for k := range 15 {
			b.Tops[api.AnalyticsNXDomain] = append(b.Tops[api.AnalyticsNXDomain],
				api.AnalyticsTopItem{Name: fmt.Sprintf("host%d.corp.invalid", k), Count: scale * 8 / 10 / int64(k+3)})
			b.Tops[api.AnalyticsServfail] = append(b.Tops[api.AnalyticsServfail],
				api.AnalyticsTopItem{Name: fmt.Sprintf("ns%d.broken.example", k), Count: scale / 50 / int64(k+2)})
		}
		call(hc, "POST", "/agent/v1/analytics", n.token, b, nil)
	}
}
