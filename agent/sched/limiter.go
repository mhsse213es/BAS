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
//
// Admission is FIFO: a blocked Acquire is granted strictly in arrival order
// via an explicit ticket queue, never by racing other blocked callers for
// the internal lock after a wakeup. See grantLocked.
type ConcurrencyLimiter struct {
	mu     sync.Mutex
	limit  int
	active int
	queue  []chan struct{} // FIFO tickets, arrival order; grantLocked closes from the front
}

// NewConcurrencyLimiter returns a limiter admitting up to limit concurrent
// jobs. limit < 1 is treated as 1 (a limiter that never admits anything is
// never useful and would silently wedge a run).
func NewConcurrencyLimiter(limit int) *ConcurrencyLimiter {
	if limit < 1 {
		limit = 1
	}
	return &ConcurrencyLimiter{limit: limit}
}

// Acquire blocks until a slot is free or ctx is done, whichever comes first.
// Returns false only on ctx cancellation -- the caller's existing "cancelled
// scenario, skip the job" path (identical in shape to AcquireCtx's lock
// acquisition and Job.Schedule's timeout: never trusted as a verdict, always
// treated as an abort or wait, never a rejection with side effects).
//
// A slot free at the instant of the call is not enough to admit ahead of
// existing waiters: the fast path below only fires when the queue is also
// empty, which is what makes admission order arrival order rather than
// "whoever happened to call Acquire while a slot was momentarily free."
func (l *ConcurrencyLimiter) Acquire(ctx context.Context) bool {
	l.mu.Lock()
	if l.active < l.limit && len(l.queue) == 0 {
		l.active++
		l.mu.Unlock()
		return true
	}
	ticket := make(chan struct{})
	l.queue = append(l.queue, ticket)
	l.mu.Unlock()

	select {
	case <-ticket:
		return true
	case <-ctx.Done():
		return l.cancelWaiting(ticket)
	}
}

// cancelWaiting resolves the race between a caller's ctx being cancelled and
// grantLocked concurrently closing that same caller's ticket. Both events
// can become ready to a select at close to the same instant; Go's select
// makes no promise about which arm is chosen when more than one is ready.
//
// If the ticket is still in the queue, cancellation genuinely won the race:
// remove it so a phantom, never-collected ticket doesn't block whoever's
// behind it in line. If it's no longer in the queue, grantLocked already
// popped and closed it -- Acquire's caller was in fact admitted, active was
// already incremented for them, but they are about to report `false` to
// their own caller (who will never call Release, per Acquire's contract for
// a false return). Release the slot on their behalf so it isn't leaked.
func (l *ConcurrencyLimiter) cancelWaiting(ticket chan struct{}) bool {
	l.mu.Lock()
	for i, t := range l.queue {
		if t == ticket {
			l.queue = append(l.queue[:i], l.queue[i+1:]...)
			l.mu.Unlock()
			return false
		}
	}
	l.mu.Unlock()
	l.Release()
	return false
}

// grantLocked admits queued waiters, in arrival order, while capacity
// allows. Must be called with l.mu already held. Closing a ticket wakes
// only the one goroutine that owns it -- never a Broadcast to every blocked
// waiter -- so which caller is admitted next is decided by queue position,
// not by which goroutine wins a post-wakeup race to re-acquire l.mu.
func (l *ConcurrencyLimiter) grantLocked() {
	for len(l.queue) > 0 && l.active < l.limit {
		t := l.queue[0]
		l.queue = l.queue[1:]
		l.active++
		close(t)
	}
}

// Release frees one admitted slot, admitting the next queued waiter (if
// any and if capacity allows) in arrival order. Must be called exactly once
// per successful Acquire.
func (l *ConcurrencyLimiter) Release() {
	l.mu.Lock()
	l.active--
	l.grantLocked()
	l.mu.Unlock()
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
	l.grantLocked()
	l.mu.Unlock()
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
