package blocklist

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	minParallel = 8 << 20 // smallest body split into parallel byte ranges
	segRetries  = 3       // per segment, each resuming from the segment's progress
)

// errNoRanges: the server stopped honouring our ranges (200 instead of 206, another
// ETag, a different range): the parallel download is abandoned.
var errNoRanges = errors.New("server does not honour byte ranges for this ETag")

// newHTTPClient has no overall timeout: a 220 MB list on a slow day takes minutes; the
// build context bounds the total and a stalled server is caught by the header timeout.
func newHTTPClient(http2 bool) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = 60 * time.Second
	t.MaxIdleConnsPerHost = 16
	if !http2 {
		t.ForceAttemptHTTP2 = false
		t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{} // disables h2
		t.TLSClientConfig = &tls.Config{NextProtos: []string{"http/1.1"}}
	}
	return &http.Client{Transport: t}
}

func (s *Service) get(ctx context.Context, url string, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/plain,*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if hdr["Range"] != "" && s.rangeClient != nil {
		return s.rangeClient.Do(req)
	}
	return s.client.Do(req)
}

func fetchStatus(n int64, took time.Duration, streams int) string {
	unit := "streams"
	if streams == 1 {
		unit = "stream"
	}
	return fmt.Sprintf("ok: %.1f MB in %.1f s (%.1f MB/s, %d %s)",
		float64(n)/1e6, took.Seconds(), float64(n)/1e6/took.Seconds(), streams, unit)
}

// download writes the body of resp (a 200 for url) to tmp and fsyncs it. When the server
// offers byte ranges for a large body with a strong ETag, the body is fetched in segs
// parallel ranges pinned to that ETag (If-Range); any failure falls back to one fresh
// single-stream GET. etag/lastMod are the validators of the content actually written.
func (s *Service) download(ctx context.Context, resp *http.Response, url, tmp string, segs int) (n int64, streams int, etag, lastMod string, err error) {
	etag, lastMod = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	if segs > 1 && resp.ContentLength >= minParallel && resp.Header.Get("Accept-Ranges") == "bytes" &&
		strings.HasPrefix(etag, `"`) {
		resp.Body.Close()
		if n, err = s.fetchRanges(ctx, url, tmp, resp.ContentLength, etag, segs); err == nil || ctx.Err() != nil {
			return n, segs, etag, lastMod, err
		}
		s.d.Log.Warn("blocklist parallel download failed, retrying as one stream", "url", url, "err", err)
		if resp, err = s.get(ctx, url, nil); err != nil {
			return 0, 1, "", "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return 0, 1, "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		etag, lastMod = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	}
	n, err = saveFile(tmp, resp.Body)
	return n, 1, etag, lastMod, err
}

func saveFile(path string, r io.Reader) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// fetchRanges downloads size bytes in segs parallel ranges into a preallocated tmp.
func (s *Service) fetchRanges(ctx context.Context, url, tmp string, size int64, etag string, segs int) (int64, error) {
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	var total atomic.Int64
	part := (size + int64(segs) - 1) / int64(segs)
	for from := int64(0); from < size; from += part {
		wg.Go(func() {
			n, err := s.fetchSegment(ctx, url, etag, f, from, min(from+part, size)-1)
			total.Add(n)
			if err != nil {
				cancel(err) // stop the other segments
			}
		})
	}
	wg.Wait()
	if err := context.Cause(ctx); err != nil {
		return total.Load(), err
	}
	if total.Load() != size {
		return total.Load(), fmt.Errorf("downloaded %d of %d bytes", total.Load(), size)
	}
	return size, f.Sync()
}

// fetchSegment writes bytes from..to (inclusive) at their offset, retrying segRetries
// times from where the previous attempt stopped. It returns the bytes written.
func (s *Service) fetchSegment(ctx context.Context, url, etag string, f *os.File, from, to int64) (int64, error) {
	var done int64
	var err error
	for attempt := 0; attempt <= segRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return done, ctx.Err()
			case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
			}
		}
		var n int64
		n, err = s.fetchRange(ctx, url, etag, f, from+done, to)
		if done += n; err == nil || errors.Is(err, errNoRanges) || ctx.Err() != nil {
			return done, err
		}
	}
	return done, fmt.Errorf("bytes %d-%d: %w", from, to, err)
}

func (s *Service) fetchRange(ctx context.Context, url, etag string, f *os.File, from, to int64) (int64, error) {
	resp, err := s.get(ctx, url, map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", from, to), "If-Range": etag})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusPartialContent:
	case resp.StatusCode < 300 || resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		return 0, errNoRanges
	default:
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode) // e.g. 503: retried
	}
	if resp.Header.Get("ETag") != etag || !strings.HasPrefix(resp.Header.Get("Content-Range"), fmt.Sprintf("bytes %d-%d/", from, to)) {
		return 0, errNoRanges
	}
	want := to - from + 1
	n, err := io.Copy(io.NewOffsetWriter(f, from), io.LimitReader(resp.Body, want))
	if err == nil && n < want {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
