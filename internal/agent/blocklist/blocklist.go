// Package blocklist downloads the panel's CDB and installs it atomically (SPEC §9.2).
package blocklist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/billyriantono/dnsjos/internal/agent/client"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// URL is the panel path of the current CDB.
const URL = "/agent/v1/blocklist"

type Syncer struct {
	Client *client.Client
	Path   string // .../blocklist/current.cdb; the download goes to Path+".tmp"

	mu   sync.Mutex
	sha  string     // sha256 of Path, computed lazily
	busy sync.Mutex // one Sync or Seed at a time (they share Path+".tmp")
}

// Local returns the sha256 of the installed CDB ("" when none).
func (s *Syncer) Local() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sha == "" {
		s.sha, _ = fileSHA(s.Path)
	}
	return s.sha
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Sync installs the CDB with sha256 want unless it is already installed. It resumes
// an interrupted download of the same file (Range + If-Range) and rejects any file
// whose checksum does not match. It returns true when a new file was installed.
func (s *Syncer) Sync(ctx context.Context, want string) (bool, error) {
	s.busy.Lock()
	defer s.busy.Unlock()
	if want == "" || want == s.Local() {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return false, err
	}
	tmp := s.Path + ".tmp"
	got, err := s.download(ctx, tmp, want, true)
	if errors.Is(err, errRestart) {
		got, err = s.download(ctx, tmp, want, false)
	}
	if err != nil || got == "" {
		return false, err
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		return false, err
	}
	s.mu.Lock()
	s.sha = got
	s.mu.Unlock()
	return true, nil
}

// Seed installs a copy of src (the CDB of a server being adopted) when no CDB is
// installed yet, so blocking never lapses before the first panel build arrives.
func (s *Syncer) Seed(src string) (bool, error) {
	s.busy.Lock()
	defer s.busy.Unlock()
	if s.Local() != "" {
		return false, nil
	}
	in, err := os.Open(src)
	if err != nil {
		return false, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return false, err
	}
	tmp := s.Path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return false, err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, s.Path)
	}
	if err != nil {
		os.Remove(tmp)
		return false, err
	}
	s.mu.Lock()
	s.sha = hex.EncodeToString(h.Sum(nil))
	s.mu.Unlock()
	return true, nil
}

var errRestart = errors.New("restart download")

// download returns the sha256 of the completed tmp file, or "" when nothing changed.
func (s *Syncer) download(ctx context.Context, tmp, want string, resume bool) (string, error) {
	h := sha256.New()
	var off int64
	if resume {
		off = hashPrefix(tmp, h)
	} else {
		os.Remove(tmp)
	}
	req, err := s.Client.NewRequest(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return "", err
	}
	etag := `"` + want + `"`
	if off > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(off, 10)+"-")
		req.Header.Set("If-Range", etag) // a different build → full 200 instead of a broken splice
	} else if local := s.Local(); local != "" {
		req.Header.Set("If-None-Match", `"`+local+`"`)
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	switch resp.StatusCode {
	case http.StatusNotModified: // panel's current build is what we already have
		return "", nil
	case http.StatusRequestedRangeNotSatisfiable:
		return "", errRestart
	case http.StatusPartialContent:
		if off == 0 {
			return "", errRestart
		}
		flag = os.O_WRONLY | os.O_APPEND
	case http.StatusOK:
		h.Reset()
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", &client.StatusError{Code: resp.StatusCode, Body: string(b)}
	}
	// The panel may have moved to a newer build since `want` was learnt; trust its header.
	if hs := resp.Header.Get(api.Sha256Header); hs != "" {
		want = hs
	}

	f, err := os.OpenFile(tmp, flag, 0o644)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("blocklist download (resumable): %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		os.Remove(tmp)
		if off > 0 && flag&os.O_APPEND != 0 { // the partial may have been of another build
			return "", errRestart
		}
		return "", fmt.Errorf("blocklist sha256 mismatch: got %s, want %s", got, want)
	}
	return want, nil
}

// hashPrefix feeds an existing partial download into h and returns its length.
func hashPrefix(p string, h hash.Hash) int64 {
	f, err := os.Open(p)
	if err != nil {
		return 0
	}
	defer f.Close()
	n, err := io.Copy(h, f)
	if err != nil {
		h.Reset()
		return 0
	}
	return n
}
