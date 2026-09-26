package blocklist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/billyriantono/dnsjos/internal/agent/client"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type panel struct {
	mu      sync.Mutex
	body    []byte
	sha     string // advertised sha (may lie)
	reqs    []*http.Request
	cutAt   int // >0: close the connection after this many body bytes
	etagHit int
}

func (p *panel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.reqs = append(p.reqs, r)
	body, sha, cut := p.body, p.sha, p.cutAt
	p.cutAt = 0
	p.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get(api.AgentHeader) != "test" {
		w.WriteHeader(401)
		return
	}
	etag := `"` + sha + `"`
	if r.Header.Get("If-None-Match") == etag {
		p.etagHit++
		w.WriteHeader(304)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set(api.Sha256Header, sha)
	if cut > 0 { // simulate a dropped connection mid-download
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(200)
		w.Write(body[:cut])
		return
	}
	http.ServeContent(w, r, "current.cdb", time.Unix(0, 0), bytes.NewReader(body))
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func setup(t *testing.T, body []byte) (*panel, *Syncer) {
	p := &panel{body: body, sha: sum(body)}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	cl := client.New(srv.URL, "tok", "test")
	return p, &Syncer{Client: cl, Path: filepath.Join(t.TempDir(), "blocklist", "current.cdb")}
}

func TestSyncInstallAnd304(t *testing.T) {
	body := []byte(strings.Repeat("cdb-data-", 1000))
	p, s := setup(t, body)
	ctx := context.Background()
	changed, err := s.Sync(ctx, p.sha)
	if err != nil || !changed {
		t.Fatalf("first sync: %v %v", changed, err)
	}
	if got, _ := os.ReadFile(s.Path); !bytes.Equal(got, body) || s.Local() != p.sha {
		t.Fatal("installed file differs")
	}
	if _, err := os.Stat(s.Path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp left behind")
	}
	// already installed: no request at all
	n := len(p.reqs)
	if changed, err := s.Sync(ctx, p.sha); err != nil || changed || len(p.reqs) != n {
		t.Fatalf("resync: %v %v reqs=%d", changed, err, len(p.reqs)-n)
	}
	// the ack names a newer build but the panel still serves ours → 304 via If-None-Match
	if changed, err := s.Sync(ctx, strings.Repeat("0", 64)); err != nil || changed || p.etagHit != 1 {
		t.Fatalf("304: %v %v hits=%d", changed, err, p.etagHit)
	}
}

func TestSyncRejectsBadSHA(t *testing.T) {
	body := []byte("good-cdb")
	p, s := setup(t, body)
	os.MkdirAll(filepath.Dir(s.Path), 0o755)
	os.WriteFile(s.Path, []byte("old"), 0o644)
	p.sha = strings.Repeat("a", 64) // panel advertises a checksum the body does not have
	if _, err := s.Sync(context.Background(), p.sha); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("want mismatch error, got %v", err)
	}
	if got, _ := os.ReadFile(s.Path); string(got) != "old" {
		t.Fatal("current.cdb replaced by a bad download")
	}
	if _, err := os.Stat(s.Path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("bad tmp kept")
	}
}

func TestSyncResumes(t *testing.T) {
	body := bytes.Repeat([]byte("0123456789"), 5000)
	p, s := setup(t, body)
	p.cutAt = 20000
	if _, err := s.Sync(context.Background(), p.sha); err == nil {
		t.Fatal("interrupted download must fail")
	}
	if fi, err := os.Stat(s.Path + ".tmp"); err != nil || fi.Size() != 20000 {
		t.Fatalf("partial tmp: %v %v", fi, err)
	}
	changed, err := s.Sync(context.Background(), p.sha)
	if err != nil || !changed {
		t.Fatalf("resume: %v %v", changed, err)
	}
	last := p.reqs[len(p.reqs)-1]
	if last.Header.Get("Range") != "bytes=20000-" || last.Header.Get("If-Range") != `"`+p.sha+`"` {
		t.Fatalf("resume headers: %v", last.Header)
	}
	if got, _ := os.ReadFile(s.Path); !bytes.Equal(got, body) {
		t.Fatal("resumed file differs")
	}

	// a stale partial of another build is replaced by a full download (If-Range miss)
	next := bytes.Repeat([]byte("abcdefghij"), 3000)
	p.mu.Lock()
	p.body, p.sha = next, sum(next)
	p.mu.Unlock()
	os.WriteFile(s.Path+".tmp", []byte("stale partial of some other build"), 0o644)
	if changed, err := s.Sync(context.Background(), p.sha); err != nil || !changed {
		t.Fatalf("stale partial: %v %v", changed, err)
	}
	if got, _ := os.ReadFile(s.Path); !bytes.Equal(got, next) {
		t.Fatal("new build differs")
	}
}
