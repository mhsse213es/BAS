package exercise

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/observability"
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
	interval  time.Duration
	stop      chan struct{}
	metrics   *observability.MetricsRegistry
}

func NewPollScheduler(interval time.Duration) *PollScheduler {
	return &PollScheduler{
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// WithMetrics attaches a metrics registry for observability instrumentation.
func (s *PollScheduler) WithMetrics(reg *observability.MetricsRegistry) *PollScheduler {
	s.metrics = reg
	return s
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
				start := time.Now()
				tick(context.Background())
				if s.metrics != nil {
					s.metrics.SchedulerTickDuration.Observe(time.Since(start).Seconds())
				}
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
