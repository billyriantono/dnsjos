package cgk

import (
	"context"
	"sync"
	"testing"
	"time"
)

// siteProber answers per (host, ip) from a table; flaky entries fail only the first time.
type siteProber struct {
	mu    sync.Mutex
	codes map[string]string // host+" "+ip → status
	flaky map[string]bool
	calls map[string]int
}

func (p *siteProber) Resolve(context.Context, string) []string { return nil }

func (p *siteProber) Fetch(_ context.Context, host, ip, _ string) (string, time.Duration, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := host + " " + ip
	p.calls[k]++
	if p.flaky[k] && p.calls[k] == 1 {
		return "000", 0, ""
	}
	if c, ok := p.codes[k]; ok {
		return c, 0, ""
	}
	return "000", 0, ""
}

func TestLearn(t *testing.T) {
	retryDelay = 0
	p := &siteProber{calls: map[string]int{}, codes: map[string]string{
		"ok.test 104.20.0.1": "200", "ok.test 104.16.0.9": "200", // same answer: keep rewriting
		"waf.test 104.20.0.2": "200", "waf.test 104.16.0.9": "403", // alias blocked: exclude
		// spectrum.test: no HTTPS on either address → exclude
		"flaky.test 104.20.0.4": "301", "flaky.test 104.16.0.9": "301",
		"redir.test 104.20.0.5": "301", "redir.test 104.16.0.9": "200", // skipped redirect: still works
	}, flaky: map[string]bool{"flaky.test 104.16.0.9": true}}
	out := "ok.test. 104.20.0.1 104.16.0.9 50\nwaf.test. 104.20.0.2 104.16.0.9 40\n" +
		"spectrum.test. 104.20.0.3 104.16.0.9 30\nflaky.test. 104.20.0.4 104.16.0.9 20\nredir.test. 104.20.0.5 104.16.0.9 10\ngarbage line\n"
	seen := ParseSeen(out)
	if len(seen) != 5 || seen[0].Name != "ok.test" || seen[0].Hits != 50 {
		t.Fatalf("ParseSeen: %+v", seen)
	}
	st := LearnState{}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !Learn(context.Background(), p, st, seen, now) {
		t.Fatal("new exclusions must report a change")
	}
	var got []string
	for _, e := range st.Excluded() {
		got = append(got, e.Name+":"+e.RealCode+"/"+e.AliasCode)
	}
	if want := "waf.test:200/403 spectrum.test:000/000"; join(got) != want {
		t.Fatalf("excluded %q, want %q", join(got), want)
	}
	if st["flaky.test"].Excluded || st["redir.test"].Excluded || st.Checked() != 5 {
		t.Fatal("one flaky answer must not exclude a site")
	}

	// Nothing is due an hour later; the excluded name is still counted ("-" IPs) and keeps its IPs.
	if Learn(context.Background(), p, st, ParseSeen("waf.test - - 7"), now.Add(time.Hour)) {
		t.Fatal("no change expected")
	}
	if e := st["waf.test"]; e.RealIP != "104.20.0.2" || e.Hits != 47 {
		t.Fatalf("waf.test: %+v", e)
	}

	// A week later the WAF rule is gone: the recheck lifts the exclusion.
	p.codes["waf.test 104.16.0.9"] = "200"
	if !Learn(context.Background(), p, st, ParseSeen("waf.test - - 1\nspectrum.test - - 1"), now.Add(8*24*time.Hour)) || st["waf.test"].Excluded {
		t.Fatal("a site that works through the alias again must be un-excluded")
	}
	// ok.test and flaky.test were not seen for more than a week: forgotten.
	if st["ok.test"] != nil || st["flaky.test"] != nil || st["redir.test"] != nil || st["spectrum.test"] == nil {
		t.Fatalf("forgetting: %v", keys(st))
	}
}

func join(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}

func keys(st LearnState) []string {
	var k []string
	for n := range st {
		k = append(k, n)
	}
	return k
}
