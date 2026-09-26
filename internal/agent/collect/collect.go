// Package collect gathers dnsdist and host statistics for the heartbeat.
package collect

import (
	"bufio"
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/billyriantono/dnsjos/internal/agent/dnsdist"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// Counter mapping, dnsdist /jsonstat stat name → api.Counters field. All are raw,
// monotonically increasing dnsdist values:
//
//	queries       ← queries             (UDP+TCP queries received)
//	responses     ← responses           (responses received from backends)
//	cache_hits    ← cache-hits
//	cache_misses  ← cache-misses
//	blocked       ← dnsjos-blocked + dnsjos-response-ip-blocked (blocking.lua metrics)
//	dyn_blocked   ← dyn-blocked         (queries dropped/truncated by dynamic blocks)
//	rule_drops    ← rule-drop           (dropped by rules, incl. the per-client qps cap)
//	servfail      ← servfail-responses  (SERVFAIL answers received from backends)
//	nxdomain      ← frontend-nxdomain   (NXDOMAIN sent to clients; rule-nxdomain as fallback)
//	noerror       ← frontend-noerror    (NOERROR sent to clients)
//	cgk_rewrites  ← cgk-rewrites        (cgk.lua metric)
//
// latency_avg_ms ← latency-avg1000 (µs, average over the last 1000 answers) / 1000.
func Counters(s map[string]float64) (api.Counters, float64) {
	n := func(k string) int64 { return int64(s[k]) }
	nx := n("frontend-nxdomain")
	if _, ok := s["frontend-nxdomain"]; !ok {
		nx = n("rule-nxdomain")
	}
	return api.Counters{
		Queries:     n("queries"),
		Responses:   n("responses"),
		CacheHits:   n("cache-hits"),
		CacheMisses: n("cache-misses"),
		Blocked:     n("dnsjos-blocked") + n("dnsjos-response-ip-blocked"),
		DynBlocked:  n("dyn-blocked"),
		RuleDrops:   n("rule-drop"),
		Servfail:    n("servfail-responses"),
		NXDomain:    nx,
		NoError:     n("frontend-noerror"),
		CGKRewrites: n("cgk-rewrites"),
	}, s["latency-avg1000"] / 1000
}

// Backends maps the webserver's server list (state lowercased: "up"/"down").
func Backends(list []dnsdist.Server) []api.BackendStat {
	out := make([]api.BackendStat, 0, len(list))
	for _, s := range list {
		out = append(out, api.BackendStat{
			Address: s.Address, Name: s.Name, Pool: strings.Join(s.Pools, ","), State: strings.ToLower(s.State),
			Weight: s.Weight, Order: s.Order, QPS: s.QPS, LatencyMs: s.Latency, Queries: s.Queries, Drops: s.Drops,
		})
	}
	return out
}

// maxDynBlocks matches the panel's heartbeat limit.
const maxDynBlocks = 20000

func DynBlocks(m map[string]dnsdist.DynBlockEntry) []api.DynBlock {
	out := make([]api.DynBlock, 0, min(len(m), maxDynBlocks))
	for client, e := range m {
		st := "blocked"
		if e.Warning {
			st = "warning"
		}
		out = append(out, api.DynBlock{Client: client, Reason: e.Reason, Stage: st, SecondsLeft: e.Seconds, Blocks: e.Blocks})
	}
	if len(out) > maxDynBlocks { // keep the worst offenders
		sort.Slice(out, func(i, j int) bool { return out[i].Blocks > out[j].Blocks })
		out = out[:maxDynBlocks]
	}
	return out
}

// Dnsdist fills the dnsdist part of hb. When the webserver is unreachable dnsdist is
// reported as not running with zero counters.
func Dnsdist(ctx context.Context, w dnsdist.Web, hb *api.Heartbeat) {
	stats, err := w.Stats(ctx)
	if err != nil {
		hb.DnsdistRunning = false
		return
	}
	hb.DnsdistRunning = true
	hb.Counters, hb.LatencyAvgMs = Counters(stats)
	hb.UptimeS = int64(stats["uptime"])
	if s, err := w.Servers(ctx); err == nil {
		hb.Backends = Backends(s)
	}
	if d, err := w.DynBlocks(ctx); err == nil {
		hb.DynBlocks = DynBlocks(d)
	}
}

// System reads load and memory from /proc (zeros where absent) and free disk space of diskPath.
func System(diskPath string) api.SystemStats {
	var s api.SystemStats
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			s.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, _ := strings.Cut(sc.Text(), ":")
			kb, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			switch k {
			case "MemTotal":
				s.MemTotalMB = kb / 1024
			case "MemAvailable":
				s.MemAvailMB = kb / 1024
			}
		}
		f.Close()
	}
	var st syscall.Statfs_t
	if syscall.Statfs(diskPath, &st) == nil {
		s.DiskFreeMB = int64(uint64(st.Bavail) * uint64(st.Bsize) / (1 << 20))
	}
	return s
}
