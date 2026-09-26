package dnsconf

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cdbw "github.com/colinmarc/cdb"
	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/shared/api"
	"github.com/billyriantono/dnsjos/internal/shared/cdb"
)

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestLiveBlocking runs the rendered blocking module in a real dnsdist (skipped when
// dnsdist is not on PATH) and checks the response-IP rewrite, its counting on
// repeated queries (cache) and the per-rule hit counters / metric names.
func TestLiveBlocking(t *testing.T) {
	bin, err := exec.LookPath("dnsdist")
	if err != nil {
		t.Skip("dnsdist not on PATH")
	}
	dir := t.TempDir()

	// Backend: mixed.example has one listed and one unlisted address.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeA {
			ips := map[string][]string{"mixed.example.": {"192.0.2.1", "198.51.100.1"}, "clean.example.": {"198.51.100.2"}}[q.Name]
			for _, ip := range ips {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN A %s", q.Name, ip))
				m.Answer = append(m.Answer, rr)
			}
		}
		w.WriteMsg(m)
	})}
	go backend.ActivateAndServe()
	defer backend.Shutdown()

	cdbPath := filepath.Join(dir, "bl.cdb")
	f, _ := os.Create(cdbPath)
	cw, err := cdbw.NewWriter(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	cw.Put(cdb.IPv4Key(netip.MustParseAddr("192.0.2.1")), nil)
	cw.Put(cdb.DomainKey("blocked.example"), nil)
	if _, err := cw.Freeze(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	spec := api.DefaultConfigSpec()
	listen := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	web := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	spec.Listen.Do53.Addresses = []string{listen}
	spec.Webserver.Listen = web
	spec.Upstreams.Servers = []api.Upstream{{Address: pc.LocalAddr().String(), Weight: 1, Order: 1, Sockets: 1}}
	spec.Abuse.Enabled, spec.CGK.Enabled, spec.Blocking.LogBlocked = false, false, false
	spec.Blocking.BlockResponseIPs = true                                // opt-in since it became off by default
	spec.Analytics.StreamAddr = fmt.Sprintf("127.0.0.1:%d", freePort(t)) // nobody listens; fine
	rt := testRT
	rt.BaseDir, rt.CDBPath = dir, cdbPath
	files, err := Render(spec, rt)
	if err != nil {
		t.Fatal(err)
	}
	for rel, b := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755)
		os.WriteFile(filepath.Join(dir, rel), b, 0o644)
	}
	cmd := exec.Command(bin, "--supervised", "--disable-syslog", "-C", filepath.Join(dir, FileConf))
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	go io.Copy(&log, bufio.NewReader(out))
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	c := &dns.Client{Timeout: time.Second}
	query := func(name string, qt uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qt)
		for range 50 {
			if r, _, err := c.Exchange(m, listen); err == nil && r.Rcode != dns.RcodeServerFailure {
				return r
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("no answer for %s from dnsdist:\n%s", name, log.String())
		return nil
	}

	for i := range 3 {
		r := query("mixed.example.", dns.TypeA)
		if len(r.Answer) != 2 {
			t.Fatalf("mixed #%d: %v", i, r.Answer)
		}
		for _, rr := range r.Answer {
			a := rr.(*dns.A)
			if a.A.String() != "192.0.2.10" || a.Hdr.Ttl > 60 {
				t.Errorf("mixed #%d: want every A = blockpage with ttl<=60, got %v", i, rr)
			}
		}
	}
	if r := query("clean.example.", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "198.51.100.2" {
		t.Errorf("clean rewritten: %v", r.Answer)
	}
	query("blocked.example.", dns.TypeA)
	query("blocked.example.", dns.TypeMX)

	req, _ := http.NewRequest("GET", "http://"+web+"/metrics", nil)
	req.Header.Set("X-API-Key", testRT.WebAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	series := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		k, v, ok := strings.Cut(line, " ")
		if !ok || strings.HasPrefix(line, "#") {
			continue
		}
		if _, dup := series[k]; dup {
			t.Errorf("duplicate series %s", k)
		}
		series[k] = v
	}
	for k, want := range map[string]string{
		"dnsdist_dnsjos_response_ip_blocked":                "3", // every answer counted, none from cache
		`dnsdist_rule_hits{id="dnsjos-blocked-count"}`:      "2",
		`dnsdist_rule_hits{id="dnsjos-block-a"}`:            "1",
		`dnsdist_rule_hits{id="dnsjos-block-nodata"}`:       "1",
		`dnsdist_rule_hits{id="dnsjos-analytics-response"}`: "4",
		`dnsdist_rule_hits{id="dnsjos-analytics-self"}`:     "2",
	} {
		if series[k] != want {
			t.Errorf("%s = %q, want %s", k, series[k], want)
		}
	}
}
