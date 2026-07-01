package exercise

import (
	"context"
	"time"
)

// Scheduler drives the executor's tick. Abstracting it lets us swap the
// polling implementation for pg_notify, Redis, Kafka, etc. without touching
// the executor.
type Scheduler interface {
	Start(tick func(ctx context.Context))
	Stop()
}

// PollScheduler is the default scheduler: a simple time.Ticker.
type PollScheduler struct {
	interval time.Duration
	stop     chan struct{}
}

func NewPollScheduler(interval time.Duration) *PollScheduler {
	return &PollScheduler{
		interval: interval,
		stop:     make(chan struct{}),
	}
}

func (s *PollScheduler) Start(tick func(ctx context.Context)) {
	go func() {
		t := time.NewTicker(s.interval)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-t.C:
				tick(context.Background())
			}
		}
	}()
}

func (s *PollScheduler) Stop() {
	select {
	case <-s.stop: // already closed
	default:
		close(s.stop)
	}
}
