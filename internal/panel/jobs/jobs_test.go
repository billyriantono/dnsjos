package jobs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestEvery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var n atomic.Int32
	s.Every("t", 5*time.Millisecond, func(context.Context) error {
		if n.Add(1) == 1 {
			panic("boom") // must not kill the job
		}
		return errors.New("keeps going")
	})
	time.Sleep(60 * time.Millisecond)
	cancel()
	s.Wait()
	if n.Load() < 3 {
		t.Fatalf("ran %d times", n.Load())
	}
}
