package sched

import (
	"context"
	"sync"
)

// ConcurrencyLimiter caps how many jobs may hold locks and execute at once,
// independent of the worker pool size (`workers` in Run). The pool stays
// fixed -- this is the admission layer sitting in front of it: it answers
// "should this much work run right now", never "can these two jobs safely
// overlap" (the lock system alone answers that, and always will).
//
// A limiter constructed with Limit == workers is a true no-op: there can
// never be more than `workers` jobs concurrently past the worker channel in
// the first place, so Acquire always succeeds immediately. Only a caller
// explicitly lowering the limit (via SetLimit, once something is actually
// watching endpoint pressure) changes behavior -- introducing the mechanism
// here is deliberately inert on its own.
type ConcurrencyLimiter struct {
	mu     sync.Mutex
	cond   *sync.Cond
	limit  int
	active int
}

// NewConcurrencyLimiter returns a limiter admitting up to limit concurrent
// jobs. limit < 1 is treated as 1 (a limiter that never admits anything is
// never useful and would silently wedge a run).
func NewConcurrencyLimiter(limit int) *ConcurrencyLimiter {
	if limit < 1 {
		limit = 1
	}
	l := &ConcurrencyLimiter{limit: limit}
	l.cond = sync.NewCond(&l.mu)
	return l
}

// Acquire blocks until a slot is free or ctx is done, whichever comes first.
// Returns false only on ctx cancellation -- the caller's existing "cancelled
// scenario, skip the job" path (identical in shape to AcquireCtx's lock
// acquisition and Job.Schedule's timeout: never trusted as a verdict, always
// treated as an abort or wait, never a rejection with side effects).
func (l *ConcurrencyLimiter) Acquire(ctx context.Context) bool {
	// sync.Cond has no cancellable Wait. This bridge goroutine rebroadcasts
	// when ctx finishes so a blocked Wait below wakes up and re-checks
	// ctx.Err(), mirroring the tryLock bridge already used in locks.go for the
	// same reason (a non-cancellable stdlib primitive gated by a context).
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			l.mu.Lock()
			l.cond.Broadcast()
			l.mu.Unlock()
		case <-stop:
		}
	}()

	l.mu.Lock()
	defer l.mu.Unlock()
	for l.active >= l.limit {
		if ctx.Err() != nil {
			return false
		}
		l.cond.Wait()
	}
	l.active++
	return true
}

// Release frees one admitted slot, waking any Acquire callers blocked on it.
// Must be called exactly once per successful Acquire.
func (l *ConcurrencyLimiter) Release() {
	l.mu.Lock()
	l.active--
	l.mu.Unlock()
	l.cond.Broadcast()
}

// SetLimit adjusts the ceiling at runtime. It never preempts already-running
// jobs: lowering the limit below the current active count just admits no new
// ones until active naturally drops to or below it. n < 1 is treated as 1,
// for the same reason as NewConcurrencyLimiter.
func (l *ConcurrencyLimiter) SetLimit(n int) {
	if n < 1 {
		n = 1
	}
	l.mu.Lock()
	l.limit = n
	l.mu.Unlock()
	l.cond.Broadcast()
}

// Limit returns the current ceiling.
func (l *ConcurrencyLimiter) Limit() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}

// Active returns the current number of admitted (not yet Released) jobs.
func (l *ConcurrencyLimiter) Active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.active
}
