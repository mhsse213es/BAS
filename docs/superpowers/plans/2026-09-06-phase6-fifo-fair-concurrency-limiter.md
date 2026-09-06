# Phase 6: FIFO-Fair ConcurrencyLimiter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `agent/sched/limiter.go`'s `sync.Cond`-based admission with an explicit FIFO ticket queue so `ConcurrencyLimiter.Acquire` admits blocked callers in strict arrival order, eliminating the goroutine-scheduling-luck starvation risk documented in the spec.

**Architecture:** `ConcurrencyLimiter` gains a `queue []chan struct{}` field. A blocked `Acquire` appends its own one-shot ticket channel to the queue and waits on it (or `ctx.Done()`). `Release` and `SetLimit` call a shared `grantLocked()` helper that pops tickets off the front of the queue and closes them — one at a time, in order — while capacity allows. Closing a channel wakes only its one owner, so admission order is decided by queue position, not by which goroutine wins a post-`Broadcast` mutex-reacquisition race. `RiskGate` is untouched except for one doc comment.

**Tech Stack:** Go (agent module), standard library only (`sync`, `context`) — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-06-phase6-fifo-fair-concurrency-limiter-design.md`

## Global Constraints

- Public API of `ConcurrencyLimiter` (`Acquire`, `Release`, `SetLimit`, `Limit`, `Active`) does not change signature or documented contract — zero call-site changes anywhere else in the codebase.
- `RiskGate` (`agent/sched/riskgate.go`) gets a doc-comment addition only — no functional or test changes.
- Every existing test in `agent/sched/limiter_test.go` and `agent/sched/sched_test.go` must keep passing unmodified.
- Run tests with `-race` throughout — this is a concurrency-correctness change; a green run without `-race` proves nothing.
- One commit per task (this project's established discipline — see Phase 5's plan/execution).

---

### Task 1: FIFO ticket-queue rewrite of `ConcurrencyLimiter`

This task bundles the queue rewrite with the cancellation-handling logic
(`cancelWaiting`) in one commit rather than splitting them across tasks.
Reason: `Acquire`'s `select` block calls `cancelWaiting` in its
`ctx.Done()` arm from the moment the queue exists — there is no
intermediate state where `Acquire` builds and satisfies the *existing*
regression suite (in particular
`TestConcurrencyLimiter_AcquireReturnsFalseOnContextCancel`, which is
unmodified and must keep passing) without `cancelWaiting` already being
correct. Splitting them would leave a commit where the package either
doesn't build or fails an existing test — the exact anti-pattern Phase
5's plan self-review caught and fixed by merging tasks. Task 2 then adds
*additional*, more targeted tests of the same `cancelWaiting` logic
this task already implements and proves via the existing suite.

**Files:**
- Modify: `agent/sched/limiter.go` (full rewrite of the struct's fields and all five methods)
- Test: `agent/sched/limiter_test.go` (add one new test function)

**Interfaces:**
- Consumes: nothing new — `context.Context` (stdlib), the existing `ConcurrencyLimiter` type this task rewrites.
- Produces: `ConcurrencyLimiter.queue []chan struct{}` (unexported field), `(*ConcurrencyLimiter).grantLocked()` (unexported method, no params, no return — must be called with `l.mu` already held), `(*ConcurrencyLimiter).cancelWaiting(ticket chan struct{}) bool` (unexported method). Task 2 calls none of these directly — it only calls `Acquire`/`Release`/`Active` — but relies on `cancelWaiting` being correct.

- [ ] **Step 1: Write the new FIFO-order test**

Add to `agent/sched/limiter_test.go` (after `TestConcurrencyLimiter_SetLimitBelowActiveDoesNotPreempt`, before `TestRun_ConcurrencyLimiterCapsBelowWorkerCount`):

```go
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
```

- [ ] **Step 2: Run it against the current (unmodified) code to confirm it fails**

Run: `go test ./agent/sched/... -run TestConcurrencyLimiter_FIFOOrderUnderContention -race -v`

Expected: FAIL, with the error message showing an `admitted` slice that is
not `[0 1 2 ... 19]` (e.g. a goroutine landing out of its arrival
position). Also run the full existing suite once now to record the
pre-change baseline: `go test ./agent/sched/... -race -v` — expected
PASS (everything except the new test you just added, which is exempted
by name in this run or simply noted as the one expected failure).

- [ ] **Step 3: Rewrite `limiter.go` with the FIFO ticket queue**

Replace the full contents of `agent/sched/limiter.go` with:

```go
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
```

- [ ] **Step 4: Run the full suite against the new code**

Run: `go test ./agent/sched/... -race -v`

Expected: PASS for every test in the package, including the new
`TestConcurrencyLimiter_FIFOOrderUnderContention` and every existing test
in `limiter_test.go` and `sched_test.go` (in particular
`TestConcurrencyLimiter_AcquireReturnsFalseOnContextCancel`,
`TestConcurrencyLimiter_SetLimitAdmitsMoreWaiters`, and
`TestRun_ConcurrencyLimiterCapsBelowWorkerCount`, which exercise this
file end-to-end). Run the new test alone a few extra times to confirm
it's now deterministic, not just lucky once: `go test ./agent/sched/...
-run TestConcurrencyLimiter_FIFOOrderUnderContention -race -count=10 -v`
— expected PASS all 10 times.

- [ ] **Step 5: Commit**

```bash
git add agent/sched/limiter.go agent/sched/limiter_test.go
git commit -m "$(cat <<'EOF'
feat(agent): FIFO ticket queue for ConcurrencyLimiter admission

Replaces sync.Cond broadcast-and-race with an explicit FIFO queue of
one-shot ticket channels. grantLocked pops and closes exactly one
ticket at a time from the front of the queue, so which blocked Acquire
is admitted next is decided by arrival order, not by which goroutine
wins the post-wakeup race to reacquire the mutex -- eliminating the
starvation mechanism traced in the Phase 6 brainstorm investigation.

cancelWaiting handles the inherent select race between a caller's ctx
cancelling and grantLocked concurrently granting that same caller's
ticket: if the ticket already left the queue, the slot it was granted
is released back rather than leaked.

Spec: docs/superpowers/specs/2026-09-06-phase6-fifo-fair-concurrency-limiter-design.md

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y
EOF
)"
git push
```

---

### Task 2: Cancellation edge-case tests

Adds two tests that specifically pin the `cancelWaiting` behavior Task 1
already implemented and proved indirectly via the existing regression
suite. No production code changes in this task — if either test fails,
it means Task 1's `cancelWaiting` has a bug, which should be fixed in
`agent/sched/limiter.go` before continuing (do not weaken the test to
match broken behavior).

**Files:**
- Test: `agent/sched/limiter_test.go` (add two new test functions)

**Interfaces:**
- Consumes: `ConcurrencyLimiter.Acquire`, `.Release`, `.Active` (public API from Task 1, unchanged signatures) — this task calls no unexported members.
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write `TestConcurrencyLimiter_CancelWhileQueuedRemovesTicket`**

Add to `agent/sched/limiter_test.go` (after `TestConcurrencyLimiter_FIFOOrderUnderContention`):

```go
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
```

- [ ] **Step 2: Run it**

Run: `go test ./agent/sched/... -run TestConcurrencyLimiter_CancelWhileQueuedRemovesTicket -race -v`

Expected: PASS. (If it fails, `cancelWaiting`'s queue-removal branch in
`agent/sched/limiter.go` has a bug — fix it there before continuing.)

- [ ] **Step 3: Write `TestConcurrencyLimiter_CancelRaceWithGrantDoesNotLeakSlot`**

Add to `agent/sched/limiter_test.go` (after the test from Step 1):

```go
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
```

- [ ] **Step 4: Run it**

Run: `go test ./agent/sched/... -run TestConcurrencyLimiter_CancelRaceWithGrantDoesNotLeakSlot -race -v`

Expected: PASS across all 200 iterations. (This test is specifically
designed to exercise both arms of the race across repeated iterations —
a single run isn't enough to trust; if it ever fails, re-run with `-race
-count=5` to confirm it's reproducible before treating it as a real bug
per this project's systematic-debugging discipline, then fix
`cancelWaiting` or `grantLocked` in `agent/sched/limiter.go`.)

- [ ] **Step 5: Run the full package suite once more**

Run: `go test ./agent/sched/... -race -v`

Expected: PASS, all tests (Task 1's + Task 2's + every pre-existing
test in the package).

- [ ] **Step 6: Commit**

```bash
git add agent/sched/limiter_test.go
git commit -m "$(cat <<'EOF'
test(agent): pin ConcurrencyLimiter cancellation edge cases

Two targeted tests for cancelWaiting (implemented in the prior commit):
a cancelled queued waiter must not leave a phantom ticket blocking
whoever's behind it, and a ctx-cancel racing a concurrent grant must
never leak a slot regardless of which way the inherent select race
resolves.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y
EOF
)"
git push
```

---

### Task 3: `RiskGate` doc-comment addition

No functional or test changes — this task documents why `RiskGate` was
deliberately left out of the FIFO rewrite, per the spec's Scope
correction section, so a future reader doesn't have to re-derive the
reasoning from scratch.

**Files:**
- Modify: `agent/sched/riskgate.go:8-20` (the `RiskGate` type's doc comment)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing later tasks depend on (documentation only).

- [ ] **Step 1: Add the doc comment**

In `agent/sched/riskgate.go`, the current type doc comment (lines 8-20) reads:

```go
// RiskGate blocks a job until an externally-set policy admits its risk
// classification, or ctx is cancelled. Mechanically identical to
// ConcurrencyLimiter (same sync.Cond + ctx-bridge pattern, for the same
// reason: sync.Cond.Wait isn't itself cancellable) but answers a different
// question -- ConcurrencyLimiter asks "how many jobs may run"; RiskGate asks
// "is this kind of job eligible to run at all right now." The two compose
// independently and neither has any awareness of the other.
//
// sched has no notion of "pressure" -- the policy is an opaque predicate the
// caller (package main, which does know about pressure.Level) swaps in via
// SetPolicy whenever conditions change. This mirrors how ConcurrencyLimiter's
// SetLimit takes a plain int, with the Level -> int mapping (ceilingForLevel)
// living entirely in package main.
type RiskGate struct {
```

Replace it with (adding one new paragraph, keeping everything else
identical -- note the second paragraph's "Mechanically identical to
ConcurrencyLimiter" claim is now stale and is corrected too):

```go
// RiskGate blocks a job until an externally-set policy admits its risk
// classification, or ctx is cancelled. Uses the same sync.Cond +
// ctx-bridge pattern ConcurrencyLimiter used before Phase 6 (see below)
// for the same reason: sync.Cond.Wait isn't itself cancellable. RiskGate
// answers a different question than ConcurrencyLimiter -- ConcurrencyLimiter
// asks "how many jobs may run"; RiskGate asks "is this kind of job eligible
// to run at all right now." The two compose independently and neither has
// any awareness of the other.
//
// sched has no notion of "pressure" -- the policy is an opaque predicate the
// caller (package main, which does know about pressure.Level) swaps in via
// SetPolicy whenever conditions change. This mirrors how ConcurrencyLimiter's
// SetLimit takes a plain int, with the Level -> int mapping (ceilingForLevel)
// living entirely in package main.
//
// Unlike ConcurrencyLimiter (which moved to an explicit FIFO ticket queue in
// Phase 6 -- see limiter.go), RiskGate deliberately keeps sync.Cond's
// broadcast-wake-all. The two types only look symmetric on the surface:
// ConcurrencyLimiter.Acquire allocates from a scarce, countable resource
// (active < limit), so which of several blocked callers wins a post-wakeup
// race is a genuine, real starvation risk -- one caller can in principle
// keep losing that race indefinitely. Allow's wait loop instead evaluates a
// pure predicate (policy(risk)) that consumes nothing; every waiter whose
// risk the new policy admits is independently and correctly woken by
// Broadcast, with zero contention between them. A FIFO grant here would
// actually be wrong: it would only wake one waiter at a time when several
// different risk classes might have simultaneously become eligible.
type RiskGate struct {
```

- [ ] **Step 2: Verify the package still builds**

Run: `go build ./agent/... && go vet ./agent/...`

Expected: no errors (this is a comment-only change, but confirms no
stray syntax mistake in the edit).

- [ ] **Step 3: Commit**

```bash
git add agent/sched/riskgate.go
git commit -m "$(cat <<'EOF'
docs(agent): explain why RiskGate keeps sync.Cond after Phase 6

ConcurrencyLimiter moved to a FIFO ticket queue (prior commits) because
Acquire allocates from a scarce, countable resource where a losing a
post-wakeup race is a genuine starvation risk. RiskGate.Allow evaluates
a pure predicate with nothing to allocate, so Broadcast-wake-all is
already correct there -- documented so the asymmetry doesn't need to be
re-derived by a future reader.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y
EOF
)"
git push
```

---

### Task 4: Final regression run and memory updates

**Files:**
- None modified in the codebase (verification only).
- Modify: `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_phase6_brainstorm_paused.md`
- Modify: `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\MEMORY.md`

**Interfaces:**
- Consumes: the fact that Tasks 1-3 are committed and pushed.
- Produces: nothing further in this plan.

- [ ] **Step 1: Run the full agent test suite**

Run: `go test ./agent/... -race -count=1 -v`

Expected: PASS, 0 failures across every package (not just
`agent/sched`) — this confirms the rewrite has zero observable effect
on anything outside `limiter.go`, matching the spec's success criterion
that no call site changes.

- [ ] **Step 2: Update the paused-brainstorm memory note**

In `project_phase6_brainstorm_paused.md`, insert this paragraph
immediately after the frontmatter's closing `---` (before the existing
"Paused 2026-09-06..." paragraph):

```markdown
**RESOLVED 2026-09-06** -- user chose Approach A. Scope was narrowed
during design (see the spec's "Scope correction" section): only
`ConcurrencyLimiter` needed the FIFO fix; `RiskGate.Allow` turned out to
have no scarce-resource contention to be unfair about, so it was left
unchanged apart from a doc comment. Full record: spec at
`docs/superpowers/specs/2026-09-06-phase6-fifo-fair-concurrency-limiter-design.md`,
plan at
`docs/superpowers/plans/2026-09-06-phase6-fifo-fair-concurrency-limiter.md`,
implementation on `main`. Everything below this line is the original
paused-brainstorm record, kept for history -- do not re-open Approach
B/C without a new decision and a new reason (e.g. real
`sched_lock_wait_max_ms` evidence from the still-pending Phase 1-5
rollout showing this fix was insufficient).
```

Also update the file's frontmatter `description:` field from its
current paused-focused text to:

```yaml
description: Phase 6 (agent scheduler admission fairness) RESOLVED via Approach A (FIFO-fair ConcurrencyLimiter) -- see the RESOLVED note at the top for the spec/plan links; rest of file is historical brainstorm record
```

- [ ] **Step 3: Update `MEMORY.md`'s index entry**

In `MEMORY.md`, under `## Active / recent`, replace the current line:

```markdown
- [Phase 6 Brainstorm PAUSED — resume here](project_phase6_brainstorm_paused.md) — mid-brainstorm, no spec/code written yet. User must pick Approach A (FIFO-fair ConcurrencyLimiter/RiskGate, recommended)/B (P0-P4 priority+aging)/C (wait for evidence) to resume. Real findings already verified, don't re-investigate.
```

with:

```markdown
- [Phase 6: FIFO-Fair ConcurrencyLimiter DONE](project_phase6_brainstorm_paused.md) — Approach A shipped 2026-09-06 (scope narrowed to ConcurrencyLimiter only; RiskGate confirmed exempt during design). Spec+plan in docs/superpowers/.
```

(This keeps the same memory filename/link since the resolution note now
lives at the top of that same file — no need to create a new memory
file for a single closed decision.)

- [ ] **Step 4: No commit for this step**

Memory files live outside the git repository
(`C:\Users\Administrator\.claude\projects\...`), so there is nothing to
`git add`/`commit`/`push` for Steps 2-3. This task's only git-relevant
verification is Step 1's test run against the already-pushed commits
from Tasks 1-3.

---

## Final Verification

After Task 4:

1. `go test ./agent/... -race -count=1` passes with 0 failures.
2. `git log --oneline -4` shows the three Task 1-3 commits on top of
   `d59673d` (the spec commit), all pushed (`git log --oneline -1
   main` == `git log --oneline -1 origin/main`).
3. `git status --porcelain -- agent/ docs/` is empty (nothing
   uncommitted in the paths this plan touched).
4. Both memory files reflect the resolved state per Task 4 Steps 2-3.
