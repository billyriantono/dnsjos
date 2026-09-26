package blocklist

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/panel/app"
)

// rangeServer serves body (with ETag) through http.ServeContent and records every Range.
type rangeServer struct {
	mu     sync.Mutex
	etag   string
	body   []byte
	ranges []string
	// hook may replace the response for a request (return true when handled).
	hook func(w http.ResponseWriter, r *http.Request, n int) bool
}

func (s *rangeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.ranges = append(s.ranges, r.Header.Get("Range"))
	n, etag, body, hook := len(s.ranges), s.etag, s.body, s.hook
	s.mu.Unlock()
	if hook != nil && hook(w, r, n) {
		return
	}
	w.Header().Set("ETag", etag)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
}

func (s *rangeServer) rangeRequests() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.ranges {
		if r != "" {
			n++
		}
	}
	return n
}

func randBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// fetchVia runs the first GET and download() like fetch does; returns the file content.
func fetchVia(t *testing.T, url string, segs int) (data []byte, streams int, etag string) {
	t.Helper()
	s := &Service{d: &app.Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, client: &http.Client{Timeout: time.Minute}}
	ctx := context.Background()
	resp, err := s.get(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	tmp := filepath.Join(t.TempDir(), "src.tmp")
	n, streams, etag, _, err := s.download(ctx, resp, url, tmp, segs)
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(tmp)
	if err != nil || int64(len(data)) != n {
		t.Fatalf("file %d bytes, reported %d (%v)", len(data), n, err)
	}
	return data, streams, etag
}

func sameContent(t *testing.T, got, want []byte) {
	t.Helper()
	if sha256.Sum256(got) != sha256.Sum256(want) {
		t.Fatalf("content differs from the source (%d vs %d bytes)", len(got), len(want))
	}
}

func TestParallelDownload(t *testing.T) {
	src := &rangeServer{etag: `"v1"`, body: randBytes(t, 9<<20+12345)}
	srv := httptest.NewServer(src)
	defer srv.Close()
	got, streams, etag := fetchVia(t, srv.URL, 8)
	sameContent(t, got, src.body)
	if streams != 8 || src.rangeRequests() != 8 || etag != `"v1"` {
		t.Fatalf("streams %d, range requests %d, etag %s", streams, src.rangeRequests(), etag)
	}
}

func TestParallelDownloadSmallOrSingle(t *testing.T) {
	for _, tc := range []struct {
		size, segs int
	}{{1 << 20, 8}, {9 << 20, 1}} {
		src := &rangeServer{etag: `"v1"`, body: randBytes(t, tc.size)}
		srv := httptest.NewServer(src)
		got, streams, _ := fetchVia(t, srv.URL, tc.segs)
		srv.Close()
		sameContent(t, got, src.body)
		if streams != 1 || len(src.ranges) != 1 || src.rangeRequests() != 0 {
			t.Fatalf("%+v: streams %d, requests %v", tc, streams, src.ranges)
		}
	}
}

func TestParallelDownloadRangeIgnored(t *testing.T) {
	// Advertises ranges but always answers 200 with the full body.
	src := &rangeServer{etag: `"v1"`, body: randBytes(t, 9<<20)}
	src.hook = func(w http.ResponseWriter, _ *http.Request, _ int) bool {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", strconv.Itoa(len(src.body)))
		w.Write(src.body)
		return true
	}
	srv := httptest.NewServer(src)
	defer srv.Close()
	got, streams, _ := fetchVia(t, srv.URL, 8)
	sameContent(t, got, src.body)
	if streams != 1 {
		t.Fatalf("streams %d, want the single-stream fallback", streams)
	}
}

func TestParallelDownloadETagChanges(t *testing.T) {
	v1, v2 := randBytes(t, 9<<20), randBytes(t, 9<<20+7)
	src := &rangeServer{etag: `"v1"`, body: v1}
	src.hook = func(_ http.ResponseWriter, _ *http.Request, n int) bool {
		if n == 4 { // a new version is published mid-download
			src.mu.Lock()
			src.etag, src.body = `"v2"`, v2
			src.mu.Unlock()
		}
		return false
	}
	srv := httptest.NewServer(src)
	defer srv.Close()
	got, streams, etag := fetchVia(t, srv.URL, 8)
	sameContent(t, got, v2)
	if streams != 1 || etag != `"v2"` {
		t.Fatalf("streams %d etag %s, want a clean single-stream v2", streams, etag)
	}
}

// abortAfter lets limit bytes through, flushes them and drops the connection.
type abortAfter struct {
	http.ResponseWriter
	limit int
}

func (w *abortAfter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		w.ResponseWriter.Write(p[:w.limit])
		w.ResponseWriter.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	w.limit -= len(p)
	return w.ResponseWriter.Write(p)
}

func TestParallelDownloadSegmentRetry(t *testing.T) {
	src := &rangeServer{etag: `"v1"`, body: randBytes(t, 9<<20)}
	part := (int64(len(src.body)) + 7) / 8
	segStart, segEnd := 3*part, 4*part-1
	var mu sync.Mutex
	var starts []int64 // requests hitting segment 3
	src.hook = func(w http.ResponseWriter, r *http.Request, _ int) bool {
		from, _, ok := strings.Cut(strings.TrimPrefix(r.Header.Get("Range"), "bytes="), "-")
		f, err := strconv.ParseInt(from, 10, 64)
		if !ok || err != nil || f < segStart || f > segEnd {
			return false
		}
		mu.Lock()
		starts = append(starts, f)
		fail := len(starts) <= 2
		mu.Unlock()
		if fail { // fails twice mid-body, then succeeds
			w.Header().Set("ETag", `"v1"`)
			http.ServeContent(&abortAfter{w, 100 << 10}, r, "", time.Time{}, bytes.NewReader(src.body))
		}
		return false
	}
	srv := httptest.NewServer(src)
	defer srv.Close()
	got, streams, _ := fetchVia(t, srv.URL, 8)
	sameContent(t, got, src.body)
	if streams != 8 || len(starts) != 3 || starts[0] != segStart || starts[2] <= starts[1] || starts[1] <= starts[0] {
		t.Fatalf("streams %d, segment 3 requests start at %v (want 3, each resuming)", streams, starts)
	}
}

func TestFetchStatus(t *testing.T) {
	for _, tc := range []struct {
		streams int
		want    string
	}{{1, "ok: 217.3 MB in 2.9 s (74.9 MB/s, 1 stream)"}, {8, "ok: 217.3 MB in 2.9 s (74.9 MB/s, 8 streams)"}} {
		if got := fetchStatus(217_300_000, 2900*time.Millisecond, tc.streams); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
}
