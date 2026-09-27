package cgk

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

const userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128 Safari/537.36"

// NetProber probes over the network like `curl -s -m 6 --resolve host:443:ip` and
// resolves with `dig @1.1.1.1` (the reference script's tools).
type NetProber struct {
	Resolver string // default 1.1.1.1:53
}

// Resolve returns the A records of name, then its AAAA records.
func (p NetProber) Resolve(ctx context.Context, name string) []string {
	srv := p.Resolver
	if srv == "" {
		srv = "1.1.1.1:53"
	}
	var out []string
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), t)
		c := &dns.Client{Timeout: 3 * time.Second}
		r, _, err := c.ExchangeContext(ctx, m, srv)
		if err != nil {
			continue
		}
		for _, rr := range r.Answer {
			switch a := rr.(type) {
			case *dns.A:
				out = append(out, a.A.String())
			case *dns.AAAA:
				out = append(out, a.AAAA.String())
			}
		}
	}
	return out
}

func (NetProber) Fetch(ctx context.Context, host, ip, path string) (string, time.Duration, string) {
	var connect time.Duration
	d := &net.Dialer{Timeout: 6 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			start := time.Now()
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
			connect = time.Since(start)
			return c, err
		},
		TLSClientConfig:   &tls.Config{ServerName: host},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{
		Transport:     tr,
		Timeout:       6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, // curl does not follow
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return "000", 0, ""
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return "000", connect, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return strconv.Itoa(resp.StatusCode), connect, string(body)
}
