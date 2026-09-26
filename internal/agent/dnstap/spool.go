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

// Spool posts blocked batches and keeps the ones the panel did not take on disk,
// so a panel outage loses nothing (up to MaxFiles windows).
type Spool struct {
	Dir      string
	MaxFiles int // default 10000 (~7 days of 1-minute windows)
	Post     func(context.Context, api.BlockedBatch) error
	Log      *slog.Logger
}

// Flush sends older spooled batches first, then items; whatever fails is spooled.
func (s *Spool) Flush(ctx context.Context, items []api.BlockedItem) {
	down := !s.drain(ctx)
	for i := 0; i < len(items); i += chunk {
		b := api.BlockedBatch{Items: items[i:min(i+chunk, len(items))]}
		if !down {
			err := s.Post(ctx, b)
			if err == nil {
				continue
			}
			if client.Permanent(err) {
				s.Log.Error("panel rejected blocked batch, dropping it", "items", len(b.Items), "err", err)
				continue
			}
			s.Log.Warn("posting blocked batch failed, spooling", "err", err)
			down = true
		}
		if err := s.write(b); err != nil {
			s.Log.Error("spooling blocked batch failed", "items", len(b.Items), "err", err)
		}
	}
	s.trim()
}

func (s *Spool) files() []string {
	m, _ := filepath.Glob(filepath.Join(s.Dir, "*.json"))
	sort.Strings(m) // names start with a zero-padded timestamp
	return m
}

// drain posts spooled files oldest first; false when the panel is unreachable.
func (s *Spool) drain(ctx context.Context) bool {
	for _, f := range s.files() {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var b api.BlockedBatch
		if json.Unmarshal(raw, &b) == nil {
			err = s.Post(ctx, b)
		}
		if err != nil && !client.Permanent(err) {
			return false
		}
		if err != nil {
			s.Log.Error("panel rejected spooled blocked batch, dropping it", "file", f, "err", err)
		}
		os.Remove(f)
	}
	return true
}

func (s *Spool) write(b api.BlockedBatch) error {
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

func (s *Spool) trim() {
	max := s.MaxFiles
	if max <= 0 {
		max = 10000
	}
	if f := s.files(); len(f) > max {
		s.Log.Error("blocked spool full, dropping oldest batches", "dropped", len(f)-max)
		for _, x := range f[:len(f)-max] {
			os.Remove(x)
		}
	}
}
