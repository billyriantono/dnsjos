// Package jobs is a tiny in-process scheduler: one ticker goroutine per job.
package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type Scheduler struct {
	ctx context.Context
	log *slog.Logger
	wg  sync.WaitGroup
}

// New returns a scheduler whose jobs stop when ctx is cancelled.
func New(ctx context.Context, log *slog.Logger) *Scheduler {
	return &Scheduler{ctx: ctx, log: log}
}

// Every runs fn every interval (first run after one interval). Runs never overlap;
// errors and panics are logged and the job keeps going.
func (s *Scheduler) Every(name string, interval time.Duration, fn func(ctx context.Context) error) {
	s.wg.Go(func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-t.C:
				if err := s.run(fn); err != nil && s.ctx.Err() == nil {
					s.log.Error("job failed", "job", name, "err", err)
				}
			}
		}
	})
}

func (s *Scheduler) run(fn func(context.Context) error) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("panic: %v", v)
		}
	}()
	return fn(s.ctx)
}

// Wait blocks until every job goroutine has returned (after ctx cancel).
func (s *Scheduler) Wait() { s.wg.Wait() }
