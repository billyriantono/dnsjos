package dnstap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/billyriantono/dnsjos/internal/agent/client"
	"github.com/billyriantono/dnsjos/internal/shared/api"
)

// chunk keeps each POST well under the panel's 10 MiB body limit.
const chunk = 50000

// BlockedBatches splits a window's items into POST-sized batches.
func BlockedBatches(items []api.BlockedItem) []api.BlockedBatch {
	var out []api.BlockedBatch
	for i := 0; i < len(items); i += chunk {
		out = append(out, api.BlockedBatch{Items: items[i:min(i+chunk, len(items))]})
	}
	return out
}

// Spool posts batches and keeps the ones the panel did not take on disk, so a panel
// outage loses nothing (up to MaxFiles / MaxBytes, oldest dropped first).
type Spool[T any] struct {
	Name     string // for logs: "blocked", "analytics"
	Dir      string
	MaxFiles int   // default 10000 (~7 days of 1-minute windows)
	MaxBytes int64 // 0 = no size limit
	Post     func(context.Context, T) error
	Log      *slog.Logger
}

// Flush sends older spooled batches first, then batches; whatever fails is spooled.
func (s *Spool[T]) Flush(ctx context.Context, batches []T) {
	down := !s.drain(ctx)
	for _, b := range batches {
		if !down {
			err := s.Post(ctx, b)
			if err == nil {
				continue
			}
			if client.Permanent(err) {
				s.Log.Error("panel rejected batch, dropping it", "spool", s.Name, "err", err)
				continue
			}
			s.Log.Warn("posting batch failed, spooling", "spool", s.Name, "err", err)
			down = true
		}
		if err := s.write(b); err != nil {
			s.Log.Error("spooling batch failed", "spool", s.Name, "err", err)
		}
	}
	s.trim()
}

func (s *Spool[T]) files() []string {
	m, _ := filepath.Glob(filepath.Join(s.Dir, "*.json"))
	sort.Strings(m) // names start with a zero-padded timestamp
	return m
}

// drain posts spooled files oldest first; false when the panel is unreachable.
func (s *Spool[T]) drain(ctx context.Context) bool {
	for _, f := range s.files() {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var b T
		if json.Unmarshal(raw, &b) == nil {
			err = s.Post(ctx, b)
		}
		if err != nil && !client.Permanent(err) {
			return false
		}
		if err != nil {
			s.Log.Error("panel rejected spooled batch, dropping it", "spool", s.Name, "file", f, "err", err)
		}
		os.Remove(f)
	}
	return true
}

func (s *Spool[T]) write(b T) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	name := filepath.Join(s.Dir, fmt.Sprintf("%020d", time.Now().UnixNano()))
	if err := os.WriteFile(name+".tmp", raw, 0o600); err != nil {
		return err
	}
	return os.Rename(name+".tmp", name+".json")
}

func (s *Spool[T]) trim() {
	limit := s.MaxFiles
	if limit <= 0 {
		limit = 10000
	}
	f := s.files()
	drop := max(len(f)-limit, 0)
	if s.MaxBytes > 0 {
		var size int64
		for i := len(f) - 1; i >= drop; i-- { // newest first: keep what fits
			if fi, err := os.Stat(f[i]); err == nil {
				if size += fi.Size(); size > s.MaxBytes {
					drop = i + 1
					break
				}
			}
		}
	}
	if drop > 0 {
		s.Log.Error("spool full, dropping oldest batches", "spool", s.Name, "dropped", drop)
		for _, x := range f[:drop] {
			os.Remove(x)
		}
	}
}
