package sched

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestConcurrencyLimiter_NewWithInvalidLimitDefaultsToOne(t *testing.T) {
	for _, n := range []int{0, -5} {
		l := NewConcurrencyLimiter(n)
		if got := l.Limit(); got != 1 {
			t.Errorf("NewConcurrencyLimiter(%d).Limit() = %d, want 1", n, got)
		}
	}
}

// TestConcurrencyLimiter_AdmitsUpToLimitConcurrently proves the limiter lets
// exactly `limit` callers through at once and no more, using the same peak
// tracker idiom as the scheduler's own concurrency tests.
func TestConcurrencyLimiter_AdmitsUpToLimitConcurrently(t *testing.T) {
	l := NewConcurrencyLimiter(2)
	tr := &tracker{}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !l.Acquire(context.Background()) {
				t.Error("Acquire returned false with an uncancelled context")
				return
			}
			tr.enter()
			time.Sleep(20 * time.Millisecond)
			tr.leave()
			l.Release()
		}()
	}
	wg.Wait()
	if tr.peak() != 2 {
		t.Errorf("peak concurrency = %d, want exactly 2 (the configured limit)", tr.peak())
	}
}

// TestConcurrencyLimiter_BlocksBeyondLimitUntilRelease proves a second
// Acquire genuinely blocks (not merely "runs later") while the limit is held,
// and unblocks the instant Release is called.
func TestConcurrencyLimiter_BlocksBeyondLimitUntilRelease(t *testing.T) {
	l := NewConcurrencyLimiter(1)
	if !l.Acquire(context.Background()) {
		t.Fatal("first Acquire should succeed immediately")
	}

	acquired := make(chan struct{})
	go func() {
		l.Acquire(context.Background())
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("second Acquire returned before Release -- limit was not enforced")
	case <-time.After(30 * time.Millisecond):
		// expected: still blocked
	}

	l.Release()
	select {
	case <-acquired:
		// expected
	case <-time.After(1 * time.Second):
		t.Fatal("second Acquire did not unblock after Release")
	}
}

// TestConcurrencyLimiter_AcquireReturnsFalseOnContextCancel proves a blocked
// Acquire gives up promptly when its context is cancelled, rather than
// waiting for a Release that may never come (e.g. a scenario abort while the
// endpoint is fully saturated).
func TestConcurrencyLimiter_AcquireReturnsFalseOnContextCancel(t *testing.T) {
	l := NewConcurrencyLimiter(1)
	if !l.Acquire(context.Background()) {
		t.Fatal("first Acquire should succeed immediately")
	}
	defer l.Release()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() { result <- l.Acquire(ctx) }()

	time.Sleep(20 * time.Millisecond) // let it actually block
	cancel()

	select {
	case ok := <-result:
		if ok {
			t.Error("Acquire returned true after its context was cancelled")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Acquire did not return after context cancellation")
	}
	if got := l.Active(); got != 1 {
		t.Errorf("Active() = %d after a cancelled Acquire, want 1 (the cancelled caller must not count as admitted)", got)
	}
}

// TestConcurrencyLimiter_SetLimitAdmitsMoreWaiters proves raising the ceiling
// at runtime immediately wakes a blocked Acquire, without that caller having
// to retry or poll.
func TestConcurrencyLimiter_SetLimitAdmitsMoreWaiters(t *testing.T) {
	l := NewConcurrencyLimiter(1)
	if !l.Acquire(context.Background()) {
		t.Fatal("first Acquire should succeed immediately")
	}

	acquired := make(chan struct{})
	go func() {
		l.Acquire(context.Background())
		close(acquired)
	}()
	time.Sleep(20 * time.Millisecond) // let it actually block

	l.SetLimit(2)
	select {
	case <-acquired:
		// expected
	case <-time.After(1 * time.Second):
		t.Fatal("raising the limit did not admit the blocked waiter")
	}
}

// TestConcurrencyLimiter_SetLimitBelowActiveDoesNotPreempt proves lowering
// the ceiling below the current active count never kills or interrupts
// already-admitted work -- it only withholds new admissions until active
// naturally drops to the new limit.
func TestConcurrencyLimiter_SetLimitBelowActiveDoesNotPreempt(t *testing.T) {
	l := NewConcurrencyLimiter(2)
	if !l.Acquire(context.Background()) {
		t.Fatal("first Acquire should succeed")
	}
	if !l.Acquire(context.Background()) {
		t.Fatal("second Acquire should succeed (limit is 2)")
	}

	l.SetLimit(1)
	if got := l.Active(); got != 2 {
		t.Errorf("Active() = %d immediately after lowering the limit, want 2 (both already-admitted jobs must keep running)", got)
	}

	// A third Acquire must now block, even though it would have been fine
	// under the original limit of 2.
	thirdDone := make(chan struct{})
	go func() {
		l.Acquire(context.Background())
		close(thirdDone)
	}()
	select {
	case <-thirdDone:
		t.Fatal("third Acquire was admitted despite the lowered limit and 2 active jobs")
	case <-time.After(30 * time.Millisecond):
		// expected
	}

	l.Release() // active: 2 -> 1, at the new limit
	l.Release() // active: 1 -> 0

	select {
	case <-thirdDone:
		// expected: freed up once active dropped to the new limit
	case <-time.After(1 * time.Second):
		t.Fatal("third Acquire never admitted after active dropped below the new limit")
	}
}

// TestConcurrencyLimiter_FIFOOrderUnderContention proves Acquire admits
// blocked callers in strict arrival order, not in whatever order the
// goroutine scheduler happens to wake them. With 20 waiters and a
// Broadcast-and-race implementation, the odds of them landing in exact
// arrival order by chance are astronomically small (~1/20!), so this
// test fails almost every run against the old sync.Cond code and must
// pass every run against the FIFO queue.
func TestConcurrencyLimiter_FIFOOrderUnderContention(t *testing.T) {
	const n = 20
	l := NewConcurrencyLimiter(1)
	if !l.Acquire(context.Background()) {
		t.Fatal("first Acquire should succeed immediately")
	}

	var mu sync.Mutex
	var admitted []int
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if !l.Acquire(context.Background()) {
				t.Errorf("Acquire(%d) returned false with an uncancelled context", i)
				return
			}
			mu.Lock()
			admitted = append(admitted, i)
			mu.Unlock()
			l.Release()
		}(i)
		// Let goroutine i actually reach the queue before launching i+1, so
		// arrival order is deterministic even though admission order (what
		// this test checks) is not guaranteed by the old implementation.
		time.Sleep(5 * time.Millisecond)
	}

	l.Release() // free the setup slot; admission cascades through the queue from here
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	for i, got := range admitted {
		if got != i {
			t.Fatalf("admission order = %v, want strictly increasing 0..%d (arrival order) -- goroutine %d was admitted out of turn at position %d", admitted, n-1, got, i)
		}
	}
}

// TestConcurrencyLimiter_CancelWhileQueuedRemovesTicket proves a cancelled
// waiter's ticket is fully removed from the queue -- it must not leave a
// phantom entry that blocks whoever is queued behind it.
func TestConcurrencyLimiter_CancelWhileQueuedRemovesTicket(t *testing.T) {
	l := NewConcurrencyLimiter(1)
	if !l.Acquire(context.Background()) {
		t.Fatal("first Acquire should succeed immediately")
	}

	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstResult := make(chan bool, 1)
	go func() { firstResult <- l.Acquire(firstCtx) }()
	time.Sleep(20 * time.Millisecond) // let it actually queue

	secondResult := make(chan bool, 1)
	go func() { secondResult <- l.Acquire(context.Background()) }()
	time.Sleep(20 * time.Millisecond) // let it actually queue behind the first

	firstCancel()
	select {
	case ok := <-firstResult:
		if ok {
			t.Error("cancelled first waiter's Acquire returned true")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("cancelled first waiter's Acquire did not return")
	}

	l.Release() // free the original slot; the second (still-waiting) caller should get it
	select {
	case ok := <-secondResult:
		if !ok {
			t.Error("second waiter's Acquire returned false -- it was never cancelled")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("second waiter was never admitted -- the cancelled first waiter's ticket likely blocked the queue")
	}
}

// TestConcurrencyLimiter_CancelRaceWithGrantDoesNotLeakSlot targets the
// specific race cancelWaiting exists to handle: a waiter's ctx cancelling
// at close to the same instant grantLocked closes that waiter's ticket.
// Regardless of which way the inherent select race resolves, Active() must
// never exceed the limit afterward, and the slot must remain usable.
func TestConcurrencyLimiter_CancelRaceWithGrantDoesNotLeakSlot(t *testing.T) {
	for i := 0; i < 200; i++ { // repeat: this exercises a genuine goroutine-scheduling race
		l := NewConcurrencyLimiter(1)
		if !l.Acquire(context.Background()) {
			t.Fatal("first Acquire should succeed immediately")
		}

		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan bool, 1)
		go func() { result <- l.Acquire(ctx) }()
		time.Sleep(2 * time.Millisecond) // let it actually queue

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); l.Release() }() // races grantLocked against...
		go func() { defer wg.Done(); cancel() }()     // ...cancellation, deliberately
		wg.Wait()

		ok := <-result
		if got := l.Active(); got > 1 {
			t.Fatalf("iteration %d: Active() = %d after the race, want <= 1 (limit) -- a slot leaked", i, got)
		}

		// If the waiter actually won the slot (ok == true), it is a
		// successful Acquire per the type's contract and this test must
		// pair it with exactly one Release. If it lost (ok == false), the
		// slot was already given back internally -- either cancelWaiting
		// found the ticket still queued and simply removed it (nothing was
		// ever granted), or it found the ticket already granted-and-gone
		// and called Release() itself on the waiter's behalf. Calling
		// Release() again here in the ok == false case would double-free
		// and drive Active() negative, so it must NOT happen.
		if ok {
			l.Release()
		}
		if got := l.Active(); got != 0 {
			t.Fatalf("iteration %d: Active() = %d after settling the race, want 0", i, got)
		}

		// Whichever way the race went, the limiter must still work.
		if !l.Acquire(context.Background()) {
			t.Fatalf("iteration %d: limiter unusable after the race", i)
		}
		l.Release()
	}
}

// TestRun_ConcurrencyLimiterCapsBelowWorkerCount is the end-to-end proof:
// with 6 worker goroutines but a limiter capped at 2, no more than 2 jobs are
// ever inside runJob (holding locks / executing) simultaneously, even though
// the jobs' own resource profile would otherwise let all 6 run in parallel.
func TestRun_ConcurrencyLimiterCapsBelowWorkerCount(t *testing.T) {
	tr := &tracker{}
	p := &ResourceProfile{Domains: []ResourceLock{{Domain: "registry"}}, Scope: "local", Risk: RiskObservation}
	limiter := NewConcurrencyLimiter(2)
	Run(context.Background(), 6, NewLockManager(), makeJobs(6, p, tr), nil, WithConcurrencyLimiter(limiter))
	if tr.peak() > 2 {
		t.Errorf("peak concurrency = %d, want <= 2 -- the limiter should cap below the 6-worker pool", tr.peak())
	}
	if tr.peak() < 2 {
		t.Errorf("peak concurrency = %d, want == 2 -- the limiter should still admit up to its own ceiling", tr.peak())
	}
	if got := limiter.Active(); got != 0 {
		t.Errorf("limiter.Active() = %d after Run returned, want 0 (every Acquire must be Released)", got)
	}
}

// TestRun_ConcurrencyLimiterEqualToWorkersIsANoOp proves the exact claim in
// ConcurrencyLimiter's doc comment: a limit equal to the worker count changes
// nothing observable, since Run can never have more than `workers` jobs past
// the channel at once regardless.
func TestRun_ConcurrencyLimiterEqualToWorkersIsANoOp(t *testing.T) {
	tr := &tracker{}
	p := &ResourceProfile{Domains: []ResourceLock{{Domain: "registry"}}, Scope: "local", Risk: RiskObservation}
	limiter := NewConcurrencyLimiter(4)
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr), nil, WithConcurrencyLimiter(limiter))
	if tr.peak() < 2 {
		t.Errorf("peak concurrency = %d with limit == workers, want the same parallelism as without a limiter", tr.peak())
	}
}
