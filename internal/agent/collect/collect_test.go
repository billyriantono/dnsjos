package collect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/billyriantono/dnsjos/internal/agent/dnsdist"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

func TestCounters(t *testing.T) {
	c, lat := Counters(map[string]float64{
		"queries": 100, "responses": 90, "cache-hits": 40, "cache-misses": 60,
		"dnsjos-blocked": 7, "dnsjos-response-ip-blocked": 2, "dyn-blocked": 3, "rule-drop": 4,
		"servfail-responses": 5, "frontend-nxdomain": 6, "rule-nxdomain": 99, "frontend-noerror": 80,
		"cgk-rewrites": 11, "latency-avg1000": 2500,
	})
	want := api.Counters{Queries: 100, Responses: 90, CacheHits: 40, CacheMisses: 60, Blocked: 9, DynBlocked: 3,
		RuleDrops: 4, Servfail: 5, NXDomain: 6, NoError: 80, CGKRewrites: 11}
	if c != want || lat != 2.5 {
		t.Fatalf("got %+v %v", c, lat)
	}
	if c, _ := Counters(map[string]float64{"rule-nxdomain": 8}); c.NXDomain != 8 {
		t.Fatalf("rule-nxdomain fallback: %+v", c)
	}
}

func TestDnsdist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path + "?" + r.URL.RawQuery {
		case "/jsonstat?command=stats":
			w.Write([]byte(`{"queries": 10, "uptime": 42, "latency-avg1000": 1000, "version": "x"}`))
		case "/api/v1/servers/localhost?":
			w.Write([]byte(`{"servers":[{"address":"1.1.1.1:53","name":"cf","pools":[""],"state":"UP","weight":10,"order":1,"qps":3.5,"latency":1.25,"queries":9,"drops":1}]}`))
		case "/jsonstat?command=dynblocklist":
			w.Write([]byte(`{"10.0.0.1/32":{"reason":"query flood","seconds":250,"blocks":12,"warning":false},"10.0.0.2/32":{"reason":"x","seconds":5,"blocks":0,"warning":true}}`))
		}
	}))
	defer srv.Close()

	var hb api.Heartbeat
	Dnsdist(context.Background(), dnsdist.Web{URL: srv.URL, APIKey: "k"}, &hb)
	if !hb.DnsdistRunning || hb.Counters.Queries != 10 || hb.UptimeS != 42 || hb.LatencyAvgMs != 1 {
		t.Fatalf("stats: %+v", hb)
	}
	if len(hb.Backends) != 1 || hb.Backends[0] != (api.BackendStat{Address: "1.1.1.1:53", Name: "cf", State: "up",
		Weight: 10, Order: 1, QPS: 3.5, LatencyMs: 1.25, Queries: 9, Drops: 1}) {
		t.Fatalf("backends: %+v", hb.Backends)
	}
	stages := map[string]string{}
	for _, d := range hb.DynBlocks {
		stages[d.Client] = d.Stage
	}
	if len(stages) != 2 || stages["10.0.0.1/32"] != "blocked" || stages["10.0.0.2/32"] != "warning" {
		t.Fatalf("dynblocks: %+v", hb.DynBlocks)
	}

	hb = api.Heartbeat{}
	Dnsdist(context.Background(), dnsdist.Web{URL: srv.URL, APIKey: "wrong"}, &hb)
	srv.Close()
	Dnsdist(context.Background(), dnsdist.Web{URL: srv.URL, APIKey: "k"}, &hb)
	if hb.DnsdistRunning || hb.Counters != (api.Counters{}) {
		t.Fatalf("unreachable dnsdist: %+v", hb)
	}
}
