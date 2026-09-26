package blocklist

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":                     "example.com",
		"https://example.com/a/b?c=1":     "example.com",
		"example.com:8080":                "example.com",
		"example.com.":                    "example.com",
		"*.wild.example":                  "wild.example",
		"under_score.example":             "under_score.example",
		"bücher.de":                       "xn--bcher-kva.de",
		"a..b":                            "",
		"bad domain.com":                  "",
		"-":                               "-",
		strings.Repeat("a", 64) + ".com":  "",
		strings.Repeat("a.", 127) + "com": "",
	} {
		got, ok := normalizeDomain(in)
		if !ok {
			got = ""
		}
		if got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
	if got := stripLine("  example.com # note\r"); got != "example.com" {
		t.Errorf("stripLine = %q", got)
	}
	if stripLine("; comment") != "" || stripLine("# x") != "" {
		t.Error("comments not stripped")
	}
}

func TestWhitelisted(t *testing.T) {
	wl := map[string]struct{}{"example.com": {}}
	for name, want := range map[string]bool{"example.com": true, "a.b.example.com": true, "notexample.com": false, "com": false} {
		if whitelisted(wl, name) != want {
			t.Errorf("whitelisted(%q) != %v", name, want)
		}
	}
}

func TestEachIPv4(t *testing.T) {
	count := func(s string) (n int, ok bool) {
		ok = eachIPv4(s, func(netip.Addr) { n++ })
		return
	}
	for in, want := range map[string]int{"1.2.3.4": 1, "10.0.0.0/24": 256, "10.0.0.7/30": 4, "10.0.0.1/32": 1,
		"255.255.255.0/24": 256, "::ffff:1.2.3.0/120": 256, "10.0.0.0/23": -1, "2001:db8::1": -1, "nope": -1} {
		n, ok := count(in)
		if !ok {
			n = -1
		}
		if n != want {
			t.Errorf("eachIPv4(%s) = %d, want %d", in, n, want)
		}
	}
}

func strInput(id, kind, content string) input {
	return input{id, kind, func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(content)), nil }}
}

func writeTmp(t testing.TB, inputs []input, wl map[string]struct{}) (string, stats) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x.cdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := writeCDB(context.Background(), f, inputs, wl)
	if err != nil {
		t.Fatal(err)
	}
	return path, st
}

func TestWriteAndLookup(t *testing.T) {
	path, st := writeTmp(t, []input{
		strInput("d", "manual_domains", "# header\nexample.com\nsub.blocked.org\nbad name\nok.example.com\nwhite.net\nx.white.net\n"),
		strInput("i", "manual_ips", "1.2.3.4\n10.9.8.0/30\n10.0.0.0/8\n2001:db8::1\n5.5.5.5\n"),
	}, map[string]struct{}{"white.net": {}, "5.5.5.5": {}})
	if st.domains != 3 || st.ips != 5 || st.whitelisted != 3 || st.skipped != 3 {
		t.Fatalf("stats = %+v", st)
	}
	for q, want := range map[string]string{
		"example.com": "example.com", "www.EXAMPLE.com.": "example.com", "deep.sub.blocked.org": "sub.blocked.org",
		"blocked.org": "", "white.net": "", "x.white.net": "", "1.2.3.4": "1.2.3.4", "10.9.8.3": "10.9.8.3",
		"10.9.8.4": "", "5.5.5.5": "",
	} {
		res, err := lookupCDB(path, q)
		if err != nil {
			t.Fatal(q, err)
		}
		if res.Match != want || res.Blocked != (want != "") {
			t.Errorf("lookup(%s) = %+v, want match %q", q, res, want)
		}
	}
	if _, err := lookupCDB(path, "bad name"); err != errBadName {
		t.Errorf("bad name: %v", err)
	}
}

// TestLargeBuildMemory streams 1 M domains and checks the heap stays far below the
// input size (the production list is ~9.7 M names / 220 MB).
func TestLargeBuildMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	const n = 1_000_000
	src := filepath.Join(t.TempDir(), "src.txt")
	f, _ := os.Create(src)
	for i := range n {
		fmt.Fprintf(f, "host-%d.some-rather-long-domain-name-%d.example.co.id\n", i, i%9973)
	}
	f.Close()
	fi, _ := os.Stat(src)

	runtime.GC()
	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapInuse > peak.Load() {
				peak.Store(m.HeapInuse)
			}
			select {
			case <-done:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	start := time.Now()
	path, st := writeTmp(t, []input{{"big", "url_domains", func() (io.ReadCloser, error) { return os.Open(src) }}}, nil)
	close(done)
	elapsed := time.Since(start)
	out, _ := os.Stat(path)
	t.Logf("%d domains: input %d MB, cdb %d MB, %s, peak heap in use %d MB",
		st.domains, fi.Size()>>20, out.Size()>>20, elapsed.Round(time.Millisecond), peak.Load()>>20)
	if st.domains != n {
		t.Fatalf("domains = %d", st.domains)
	}
	if peak.Load() > 48<<20 {
		t.Fatalf("peak heap %d MB, want < 48 MB (input is %d MB)", peak.Load()>>20, fi.Size()>>20)
	}
	if res, _ := lookupCDB(path, fmt.Sprintf("www.host-%d.some-rather-long-domain-name-%d.example.co.id", 123456, 123456%9973)); !res.Blocked {
		t.Fatalf("lookup miss: %+v", res)
	}
}
