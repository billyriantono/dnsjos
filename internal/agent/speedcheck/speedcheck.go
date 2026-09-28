// Package speedcheck is smartdns' speed test run by the agent (SPEC §6.9): it measures
// the addresses of the names clients ask for, for dual-stack selection (package
// dualstack) and for fastest-IP answers (fastest.go).
package speedcheck

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

const (
	// PerFamily bounds the addresses probed per name and family (smartdns probes every one).
	PerFamily = 16
	// smartdns' DNS_PING_TIMEOUT (950 ms, counted from the first probe, never below 200 ms
	// per probe) and DNS_PING_CHECK_INTERVAL (the next method starts 100 ms later; its
	// docs say 200 ms, the code uses 100).
	probeTimeout    = 950 * time.Millisecond
	minProbeTimeout = 200 * time.Millisecond
	checkInterval   = 100 * time.Millisecond
)

// Answer is a name's addresses per family with the lowest TTL of each RRset.
type Answer struct {
	V4, V6     []string
	TTL4, TTL6 uint32
}

// Prober does the network work; tests use a fake.
type Prober interface {
	Resolve(ctx context.Context, name string) Answer
	// Probe returns the round trip of one speed check to ip, -1 when it fails.
	Probe(ctx context.Context, m api.SpeedCheckMethod, ip string) time.Duration
}

// Measure is smartdns' speed check of one A or AAAA answer (_dns_server_second_ping_check):
// every address with the first method; each later method starts checkInterval after the
// previous one unless an address already answered. It returns every address's time, -1
// when it never answered. Like smartdns, an address answering twice keeps its later answer
// (addr_map->ping_time), except the fastest address, which keeps the fastest answer seen
// (request->ping_time): so Fastest(result) is the request's ping_time.
func Measure(ctx context.Context, p Prober, methods []api.SpeedCheckMethod, ips []string) map[string]time.Duration {
	ips = ips[:min(len(ips), PerFamily)]
	out := make(map[string]time.Duration, len(ips))
	for _, ip := range ips {
		out[ip] = -1
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var once sync.Once
	answered := make(chan struct{})
	start := time.Now()
	bestIP, best := "", time.Duration(-1)
methods:
	for k, m := range methods {
		if k > 0 {
			select {
			case <-answered:
				break methods
			case <-ctx.Done():
				break methods
			case <-time.After(checkInterval):
			}
		}
		pctx, cancel := context.WithTimeout(ctx, max(probeTimeout-time.Since(start), minProbeTimeout))
		defer cancel()
		for _, ip := range ips {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if t := p.Probe(pctx, m, ip); t >= 0 {
					mu.Lock()
					out[ip] = t
					if best < 0 || t < best {
						bestIP, best = ip, t
					}
					mu.Unlock()
					once.Do(func() { close(answered) })
				}
			}()
		}
	}
	wg.Wait()
	if best >= 0 {
		out[bestIP] = best
	}
	return out
}

// Fastest is the request's ping_time: the fastest answer, -1 when none answered.
func Fastest(times map[string]time.Duration) time.Duration {
	best := time.Duration(-1)
	for _, t := range times {
		if t >= 0 && (best < 0 || t < best) {
			best = t
		}
	}
	return best
}

// ParseSeen parses the modules' *Seen() output ("name count" per line).
func ParseSeen(out string) map[string]int64 {
	m := map[string]int64{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		if n, err := strconv.ParseInt(f[1], 10, 64); err == nil && f[0] != "" {
			m[strings.ToLower(strings.TrimSuffix(f[0], "."))] += n
		}
	}
	return m
}

// Excluded reports whether name is one of list (lower case, no trailing dot) or under one.
func Excluded(name string, list []string) bool {
	for _, x := range list {
		if name == x || strings.HasSuffix(name, "."+x) {
			return true
		}
	}
	return false
}

// Names lower-cases a spec's exclude list and drops trailing dots.
func Names(list []string) []string {
	out := make([]string, len(list))
	for i, e := range list {
		out[i] = strings.ToLower(strings.TrimSuffix(e, "."))
	}
	return out
}

// IPv6Ready reports whether this node has an IPv6 route at all (smartdns disables every
// IPv6 feature without one): otherwise every IPv6 check fails.
func IPv6Ready() bool {
	c, err := net.Dial("udp6", "[2001:4860:4860::8888]:53") // no packet is sent
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// NetProber resolves through Resolver (ip:port, the node's upstream) and probes over the
// network.
type NetProber struct{ Resolver string }

func (p NetProber) Resolve(ctx context.Context, name string) Answer {
	var a Answer
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), t)
		c := &dns.Client{Timeout: 3 * time.Second}
		r, _, err := c.ExchangeContext(ctx, m, p.Resolver)
		if err != nil {
			continue
		}
		for _, rr := range r.Answer {
			ttl := rr.Header().Ttl
			switch v := rr.(type) {
			case *dns.A:
				if len(a.V4) == 0 || ttl < a.TTL4 {
					a.TTL4 = ttl
				}
				a.V4 = append(a.V4, v.A.String())
			case *dns.AAAA:
				if len(a.V6) == 0 || ttl < a.TTL6 {
					a.TTL6 = ttl
				}
				a.V6 = append(a.V6, v.AAAA.String())
			}
		}
	}
	return a
}

func (NetProber) Probe(ctx context.Context, m api.SpeedCheckMethod, ip string) time.Duration {
	if m.Port == 0 {
		return ping(ctx, ip)
	}
	d := &net.Dialer{Timeout: probeTimeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(m.Port)))
	if err != nil {
		return -1
	}
	t := time.Since(start)
	conn.Close()
	return t
}
