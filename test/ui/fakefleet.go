//go:build ui

// fakefleet seeds a running panel with realistic data for UI checks: it enrolls three fake
// agents (dns1..dns3), heartbeats every 5 s with growing counters, posts CGK reports and
// blocked-domain batches spanning last year, and adds a blocklist source served locally.
//
//	go run -tags ui ./test/ui -panel http://127.0.0.1:28080 -email admin@example.com -password admin-pass-1
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

var (
	panel  = flag.String("panel", "http://127.0.0.1:28080", "panel base URL")
	email  = flag.String("email", "admin@example.com", "admin email")
	passwd = flag.String("password", "admin-pass-1", "admin password")
	hc     = &http.Client{Timeout: 10 * time.Second}
)

// call sends JSON with the CSRF header and decodes the response into out (if non-nil).
func call(c *http.Client, method, path, bearer string, in, out any) int {
	var body bytes.Buffer
	if in != nil {
		json.NewEncoder(&body).Encode(in)
	}
	req, _ := http.NewRequest(method, *panel+path, &body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "dnsjos")
	req.Header.Set(api.AgentHeader, "0.1.0-fake")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("%s %s: %v", method, path, err)
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e api.ErrorBody
		json.NewDecoder(resp.Body).Decode(&e)
		log.Printf("%s %s: %d %+v", method, path, resp.StatusCode, e)
	} else if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

var words = strings.Fields(`judi slot gacor togel poker casino bet88 maxwin sbobet domino qq bandar
	pinjol cepat cair film bokep nonton streaming xxx proxy vpn free crack warez torrent bola`)

func domain(i int) string {
	return fmt.Sprintf("%s%s%d.%s", words[i%len(words)], words[(i*7)%len(words)], i,
		[]string{"com", "net", "xyz", "site", "online", "id"}[i%6])
}

// sourceServer serves a blocklist domain file on a random loopback port.
func sourceServer() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for i := range 2500 {
			fmt.Fprintln(w, domain(i))
		}
	}))
	return "http://" + ln.Addr().String() + "/domains.txt"
}

type node struct {
	name, id, token string
	c               api.Counters
	cfg, acked      int
	sha             string
	cmds            []int64
	down            bool // one backend down → degraded
}

func main() {
	flag.Parse()
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	if call(admin, "POST", "/api/v1/auth/login", "", api.LoginRequest{Email: *email, Password: *passwd}, nil) != 200 {
		log.Fatal("login failed")
	}

	// Blocklist: keep the seeded internet sources off, add a local one, build now.
	var srcs api.List[api.BlocklistSource]
	call(admin, "GET", "/api/v1/blocklist/sources", "", nil, &srcs)
	f := false
	for _, s := range srcs.Items {
		call(admin, "PATCH", "/api/v1/blocklist/sources/"+s.ID, "", api.BlocklistSourcePatch{Enabled: &f}, nil)
	}
	call(admin, "POST", "/api/v1/blocklist/sources", "", api.BlocklistSourceCreate{
		Name: "Local test feed", Kind: api.SourceURLDomains, URL: sourceServer()}, nil)
	call(admin, "POST", "/api/v1/blocklist/sources", "", api.BlocklistSourceCreate{
		Name: "Manual additions", Kind: api.SourceManualDomains, Content: "bad.example\nworse.example\n"}, nil)
	call(admin, "POST", "/api/v1/blocklist/builds", "", nil, nil)

	var nodes []*node
	for i, name := range []string{"dns1", "dns2", "dns3"} {
		var tok api.EnrollmentTokenCreated
		call(admin, "POST", "/api/v1/enrollment-tokens", "", api.EnrollmentTokenCreate{
			NodeName: name, Labels: map[string]string{"site": []string{"jkt", "jkt", "sby"}[i]}, TTLHours: 24}, &tok)
		var er api.EnrollResponse
		if call(hc, "POST", "/agent/v1/enroll", "", api.EnrollRequest{Token: tok.Token, Hostname: name + ".example.net",
			OS: "Debian 12", Arch: "amd64", AgentVersion: "0.1.0-fake", DnsdistVersion: "2.0.1",
			PublicIP: fmt.Sprintf("203.0.113.%d", 10+i)}, &er) != 200 {
			log.Fatalf("enroll %s failed", name)
		}
		n := &node{name: name, id: er.NodeID, token: er.NodeToken, down: i == 2}
		n.c.Queries = int64(rand.IntN(5e6))
		nodes = append(nodes, n)
		seed(n, i)
	}
	log.Printf("enrolled %d nodes; heartbeating every 5s", len(nodes))
	for tick := 0; ; tick++ {
		for i, n := range nodes {
			heartbeat(n, i, tick)
		}
		if tick%60 == 59 { // fresh CGK report every ~5 min
			for _, n := range nodes {
				cgk(n)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

// seed posts a CGK report and a year of blocked-domain batches for a node.
func seed(n *node, i int) {
	cgk(n)
	seedAnalytics(n, i)
	today := time.Now().UTC()
	var items []api.BlockedItem
	for d := 0; d < 420; d += 1 + d/30 { // dense recently, sparse back into last year
		day := today.AddDate(0, 0, -d).Format("2006-01-02")
		for k := range 25 {
			j := (d*13 + k*k + i*5) % 300
			items = append(items, api.BlockedItem{Day: day, QName: domain(j),
				QType: []string{"A", "AAAA", "HTTPS"}[k%3], Count: int64(1 + (300-j)*(k+1)%97)})
		}
	}
	for len(items) > 0 {
		k := min(len(items), 1000)
		call(hc, "POST", "/agent/v1/blocked", n.token, api.BlockedBatch{Items: items[:k]}, nil)
		items = items[k:]
	}
}

func cgk(n *node) {
	call(hc, "POST", "/agent/v1/cgk", n.token, api.CGKReport{MeasuredAt: time.Now().UTC(), OK: true,
		Message:       "8 aliases from 3 pools",
		Aliases:       []string{"104.16.0.1", "104.16.1.1", "104.17.2.3", "104.18.4.5", "172.64.0.9", "172.64.3.3", "104.21.5.5", "104.22.7.7"},
		RewriteRanges: []string{"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"},
		Pools: []api.CGKPool{{Net: "104.16.0.0/13", Colos: []string{"CGK", "SIN"}},
			{Net: "172.64.0.0/13", Colos: []string{"CGK"}}, {Net: "104.24.0.0/14", Colos: []string{"SIN", "KUL"}}}}, nil)
}

func heartbeat(n *node, i, tick int) {
	q := int64(2000+1500*i) * 5 * int64(90+rand.IntN(20)) / 100
	hits := q * int64(55+rand.IntN(15)) / 100
	blocked := q * int64(2+rand.IntN(4)) / 100
	c := &n.c
	c.Queries += q
	c.Responses += q - q/500
	c.CacheHits += hits
	c.CacheMisses += q - hits
	c.Blocked += blocked
	c.DynBlocked += int64(rand.IntN(40))
	c.RuleDrops += int64(rand.IntN(10))
	c.Servfail += q / 800
	c.NXDomain += q / 12
	c.NoError += q - q/12 - q/800
	c.CGKRewrites += q / 30

	state := func(k int) string {
		if n.down && k == 1 {
			return "down"
		}
		return "up"
	}
	var backends []api.BackendStat
	for k, up := range []struct{ addr, name string }{{"1.1.1.1:53", "cloudflare"}, {"8.8.8.8:53", "google"}, {"9.9.9.9:53", "quad9"}} {
		backends = append(backends, api.BackendStat{Address: up.addr, Name: up.name, Pool: "", State: state(k),
			Weight: []int{50, 30, 20}[k], Order: 1, QPS: float64(q/5) * []float64{.5, .3, .2}[k],
			LatencyMs: 4 + float64(k*6) + rand.Float64()*3, Queries: c.Queries * int64(5-k) / 10, Drops: int64(k * tick)})
	}
	var dyn []api.DynBlock
	if i != 1 {
		dyn = []api.DynBlock{
			{Client: fmt.Sprintf("198.51.100.%d/32", 20+i), Reason: "Exceeded query rate", Stage: "blocked", SecondsLeft: 300 - tick%300, Blocks: int64(tick * 17)},
			{Client: "2001:db8::/64", Reason: "Exceeded ServFail rate", Stage: "warning", SecondsLeft: 60, Blocks: 3},
		}
	}
	last := time.Now().Add(-time.Duration(tick%60) * 5 * time.Second).UTC()
	hb := api.Heartbeat{Time: time.Now().UTC(), AgentVersion: "0.1.0-fake", DnsdistVersion: "2.0.1", OS: "Debian 12",
		UptimeS: int64(86400*(i+2) + tick*5), DnsdistRunning: true, AppliedConfigVersion: n.acked, BlocklistSHA256: n.sha,
		System:   api.SystemStats{Load1: .2 + rand.Float64()*float64(i+1)/2, MemTotalMB: 7940, MemAvailMB: int64(5000 + rand.IntN(800)), DiskFreeMB: 41000},
		Counters: *c, LatencyAvgMs: 6 + rand.Float64()*4 + float64(i), Backends: backends, DynBlocks: dyn,
		CGK:           api.CGKStatus{Aliases: 8, RewriteRanges: 4, LastRefresh: &last},
		AckedCommands: n.cmds}
	var ack api.HeartbeatAck
	if call(hc, "POST", "/agent/v1/heartbeat", n.token, hb, &ack) != 200 {
		return
	}
	n.cmds = nil
	for _, cmd := range ack.Commands {
		log.Printf("%s: command %s", n.name, cmd.Type)
		n.cmds = append(n.cmds, cmd.ID)
	}
	// Apply what the panel wants on the next beat; dns2 lags one beat behind to show "syncing".
	if i != 1 || tick%2 == 1 {
		n.acked, n.sha = ack.ConfigVersion, ack.BlocklistSHA256
	}
}
