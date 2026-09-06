# Phase 7: Priority-Aware Retry Backoff for Failed Steps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add retry-with-backoff for scenario steps that fail, with the retry budget scaled by the step's risk classification, without ever holding a `ConcurrencyLimiter` admission slot or `LockManager` lock idle during a backoff sleep.

**Architecture:** `RetryPolicy` (generic: max attempts + a backoff function) lives in `agent/sched`; the risk-to-policy mapping (`retryPolicyForRisk`) lives in `package main`, mirroring how `ceilingForLevel`/`riskAllowedForLevel` already keep policy decisions out of `sched`. `Job.Run`'s signature changes to report whether its outcome warrants a retry; `sched.Run`'s worker loop becomes a bounded per-attempt loop that runs the full admission-and-execute cycle (RiskGate → ConcurrencyLimiter → locks → execute → release) fresh on every attempt, sleeping between attempts while holding nothing.

**Tech Stack:** Go (agent module), standard library only (`sync`, `sync/atomic`, `context`, `time`) — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-06-phase7-priority-aware-retry-backoff-design.md`

## Global Constraints

- No admission slot or lock is ever held during a backoff sleep — every attempt independently passes `RiskGate`/`ConcurrencyLimiter`/`LockManager` acquisition from scratch.
- Backoff sleeps are interruptible by `ctx` cancellation (checked via `select` against `ctx.Done()`, never a bare `time.Sleep`).
- A schedule timeout (lock acquisition itself timing out) is never retried.
- A `Job` with the zero-value `Retry` field behaves identically to every `Job` before this phase (`MaxAttempts <= 1` → exactly one attempt).
- `-race` is unavailable on this Windows build host (`CGO_ENABLED=0`, no `gcc` in `PATH`, confirmed this session) — run tests without it, consistent with how Phase 6 was verified here.
- One commit per task (this project's established discipline).

---

### Task 1: `Job.Run`/`runJob` signature migration (behavior-preserving refactor)

This task changes ONLY the shape of `Job.Run` and `runJob` — no new
types, no new fields, no retry logic yet. It is deliberately split from
Task 2 for a different reason than Phase 6's task-merge lesson: that
lesson was about never leaving an intermediate commit where a *newly
added test* fails or the build breaks. Here, no new tests are added in
this task at all — every existing test must simply keep passing, since
nothing about `Run`'s actual behavior changes, only the type signature
plumbing needed for Task 2 to build on. This is safe to split precisely
because there's no "written test fails until the next task lands" gap.

**Files:**
- Modify: `agent/sched/scheduler.go` (`Job.Run` field type, `runJob` signature and body)
- Modify: `agent/agent.go:710` (1 closure)
- Modify: `agent/sched/equiv_test.go:74,145` (2 closures)
- Modify: `agent/sched/metrics_test.go:85,126,173,174,192` (5 closures)
- Modify: `agent/sched/sched_test.go:146,228,286,287,310,337,353,376,382,430,463,478,479` (13 closures)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Job.Run func(ctx context.Context) (shouldRetry bool)` and `runJob(...) (shouldRetry bool)` — both consumed by Task 2's loop restructure.

- [ ] **Step 1: Change `Job.Run`'s field type**

In `agent/sched/scheduler.go`, in the `Job` struct, change:

```go
	Run      func(ctx context.Context)
```

to:

```go
	// Run performs the work and reports whether this attempt's outcome
	// warrants a retry (per the caller's own classification of what it ran --
	// sched has no opinion on what "retryable" means). Ignored once a Job's
	// retry budget is exhausted or the outcome already succeeded.
	Run      func(ctx context.Context) (shouldRetry bool)
```

- [ ] **Step 2: Change `runJob`'s signature and body**

In `agent/sched/scheduler.go`, replace the entire `runJob` function with:

```go
func runJob(ctx context.Context, lm *LockManager, j Job, rec Recorder) (shouldRetry bool) {
	reqs := resolve(j.Resource)

	lockWaitStart := time.Now()
	acqCtx, cancel := ctx, context.CancelFunc(func() {})
	if j.Schedule > 0 {
		acqCtx, cancel = context.WithTimeout(ctx, j.Schedule)
	}
	ok := lm.AcquireCtx(acqCtx, reqs)
	cancel()
	if rec != nil {
		rec.LockWait(time.Since(lockWaitStart))
	}
	if !ok {
		// AcquireCtx failed: a cancelled scenario (ctx done) is a normal abort --
		// skip silently. Otherwise the schedule timeout fired: record it so the
		// step is never silently stuck. Either way, never retried -- see the
		// spec's Non-goals (contention for a resource is not the step failing).
		if ctx.Err() == nil && j.OnScheduleTimeout != nil {
			if rec != nil {
				rec.ScheduleTimeout()
			}
			j.OnScheduleTimeout()
		}
		return false
	}

	defer lm.Release(reqs)
	defer func() {
		if p := recover(); p != nil {
			log.Printf("[sched] recovered panic in step: %v", p)
			if rec != nil {
				rec.JobPanic()
			}
			shouldRetry = false
		}
	}()
	if j.Run != nil {
		execStart := time.Now()
		shouldRetry = j.Run(ctx)
		if rec != nil {
			rec.ExecutionTime(time.Since(execStart))
		}
	}
	return shouldRetry
}
```

`Run`'s worker loop itself needs **no changes** in this task: its two
existing call sites (`runJob(ctx, lm, j, cfg.rec)`, once inside the
`cfg.limiter != nil` branch, once in the `else`) are bare statements
that don't capture a return value today — Go permits calling a function
and discarding its return value as a bare statement, so they remain
syntactically valid even though `runJob` now returns a `bool`. Verify
this by eye; do not add capturing variables here, that's Task 2's job.

- [ ] **Step 3: Migrate all 21 existing `Job.Run` closures**

Every closure below currently has the shape `func(ctx context.Context) { ... }` or `func(context.Context) { ... }` (both are the same type). Each needs its body changed so every path ends with `return false` — the correct value for all of them, since none of today's callers want retry behavior:

- `agent/agent.go:710` — this closure already has an early `return` (no value) inside the payload-quarantine branch; change it to `return false`, and add `return false` as the closure's final statement (Task 4 will later change this specific closure further — for this task, just make it compile with the old behavior preserved).
- `agent/sched/equiv_test.go:74`, `:145`
- `agent/sched/metrics_test.go:85`, `:126`, `:173`, `:174`, `:192`
- `agent/sched/sched_test.go:146`, `:228`, `:286`, `:287`, `:310`, `:337`, `:353`, `:376`, `:382`, `:430`, `:463`, `:478`, `:479`

The mechanical rule has two parts, both required at every one of the 21 sites:

1. **The closure's own declared signature** must gain the `bool` return type: `func(ctx context.Context) {` → `func(ctx context.Context) bool {`, and `func(context.Context) {` → `func(context.Context) bool {`. This is required independently of the struct field's type — a Go func literal's signature is whatever it's written as, not inferred from where it's assigned, so `return false` inside a literal still declared as returning nothing is a compile error ("too many return values") no matter what `Job.Run`'s field type says.
2. **The closure's body**: if it's `{}` or `{ <single-statement> }`, change it to `{ <single-statement>; return false }` (or `{ return false }` if empty). If multi-statement, append `return false` as the last statement before the closing `}`. For any closure that already has an explicit early `return` (like `agent.go:710`'s quarantine branch), change that early `return` to `return false` too, in addition to the final `return false`.

Don't hand-verify each one by re-reading it after editing — the Go
compiler is a stronger completeness check than a manual list here: any
closure missing part 1 fails with "too many return values"; any closure
missing part 2 on some path fails with "missing return" (Go requires
every path of a function with a return type to return a value). Use
this to your advantage in the next step.

- [ ] **Step 4: Build iteratively until clean**

Run: `cd agent && go build ./sched/... ./...`

Fix every "missing return" or "cannot use func literal ... as func(context.Context) bool value" compiler error by applying the rule from Step 3 to the reported line, then re-run the build. Repeat until it succeeds with no output. This is the actual completeness proof for Step 3 — the 21-site list above is a starting map, not the final authority; trust the compiler.

- [ ] **Step 5: Run the full existing suite**

Run: `go test ./sched/...` and `go test ./...` (from `agent/`)

Expected: PASS, every existing test unmodified in behavior — this is a pure type-signature refactor, so a failure here means Step 3's mechanical migration introduced an actual behavior change somewhere (e.g. a `return false` landed before code that was supposed to run) and needs fixing, not a genuine new-behavior bug.

- [ ] **Step 6: Commit**

```bash
git add agent/sched/scheduler.go agent/agent.go agent/sched/equiv_test.go agent/sched/metrics_test.go agent/sched/sched_test.go
git commit -m "$(cat <<'EOF'
refactor(agent): Job.Run reports shouldRetry (behavior-preserving)

Job.Run's signature changes from func(ctx context.Context) to
func(ctx context.Context) (shouldRetry bool), and runJob propagates
that value (forced false on panic or schedule timeout). All 21
existing call sites updated to return false, preserving today's
single-attempt behavior exactly -- this is pure plumbing for Phase 7's
retry loop (next commit), not a behavior change on its own.

Spec: docs/superpowers/specs/2026-09-06-phase7-priority-aware-retry-backoff-design.md

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y
EOF
)"
git push
```

---

### Task 2: `RetryPolicy` type, `Recorder.Retry()`, and the bounded per-attempt loop

This is where the `Recorder.Retry()` interface method and its actual
call site land together in the same task and commit — deliberately
avoiding the exact gap Phase 5's plan self-review caught and fixed
(`Recorder.AdmissionWait` was originally going to ship without a task
that wired its call site into the scheduler).

**Files:**
- Create: `agent/sched/retry.go`
- Modify: `agent/sched/scheduler.go` (`Job.Retry` field, `Run`'s worker loop)
- Modify: `agent/sched/metrics.go` (`Recorder` interface)
- Modify: `agent/sched/metrics_test.go` (`fakeRecorder`)
- Test: `agent/sched/scheduler_test.go` or `agent/sched/sched_test.go` (add new tests — use `sched_test.go`, where the existing `Run`-level tests already live)

**Interfaces:**
- Consumes: `Job.Run func(ctx context.Context) (shouldRetry bool)`, `runJob(...) (shouldRetry bool)` (from Task 1).
- Produces: `sched.RetryPolicy{MaxAttempts int, Backoff func(attempt int) time.Duration}`, `Job.Retry RetryPolicy` field, `Recorder.Retry()` — all consumed by Task 3 (production `Retry()` impl) and Task 4 (`agent.go` wiring, which sets `Job.Retry`).

- [ ] **Step 1: Write `agent/sched/retry.go`**

```go
package sched

import "time"

// RetryPolicy bounds how many times a job's attempt cycle repeats and how
// long to wait between attempts. sched has no notion of why a policy is
// generous or conservative -- that judgment belongs to the caller (package
// main, which does know about risk classification), exactly like
// ConcurrencyLimiter's SetLimit takes a plain int with the Level -> int
// mapping living entirely outside sched.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts, including the first --
	// MaxAttempts <= 1 means no retry (the default zero value, so a Job built
	// without setting Retry behaves exactly as before this phase).
	MaxAttempts int
	// Backoff returns the delay before the next attempt, given the 1-indexed
	// number of the attempt that just failed (Backoff(1) is the delay after
	// the first attempt fails, before the second attempt starts). Nil is
	// treated as zero delay.
	Backoff func(attempt int) time.Duration
}

func (p RetryPolicy) maxAttempts() int {
	if p.MaxAttempts < 1 {
		return 1
	}
	return p.MaxAttempts
}

func (p RetryPolicy) backoff(attempt int) time.Duration {
	if p.Backoff == nil {
		return 0
	}
	return p.Backoff(attempt)
}
```

- [ ] **Step 2: Add `Job.Retry` and `Recorder.Retry()`**

In `agent/sched/scheduler.go`, add a field to `Job` (after `Queued time.Time`):

```go
	// Retry bounds how many times this Job's full admission-and-execute
	// cycle repeats on a retryable outcome. The zero value (MaxAttempts 0)
	// means exactly one attempt, identical to every Job before this phase.
	Retry RetryPolicy
```

In `agent/sched/metrics.go`, add to the `Recorder` interface (after `AdmissionWait(d time.Duration)`):

```go
	// Retry reports one retry attempt about to happen -- called once per
	// retry (a Job that retries twice calls this twice), never once per Job.
	Retry()
```

In `agent/sched/metrics_test.go`, add a `retries int` field to `fakeRecorder`'s struct, a method:

```go
func (f *fakeRecorder) Retry() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retries++
}
```

and extend `snapshot()`'s signature and body from:

```go
func (f *fakeRecorder) snapshot() (queue, lock, exec, admission int, timeouts, panics int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queueWaits), len(f.lockWaits), len(f.execTimes), len(f.admissionWaits), f.timeouts, f.panics
}
```

to:

```go
func (f *fakeRecorder) snapshot() (queue, lock, exec, admission int, timeouts, panics, retries int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queueWaits), len(f.lockWaits), len(f.execTimes), len(f.admissionWaits), f.timeouts, f.panics, f.retries
}
```

Update the 5 existing call sites with a trailing `_` for the new value:
`agent/sched/metrics_test.go:68` (`_, _, _, admission, _, _ := f.snapshot()` → `_, _, _, admission, _, _, _ := f.snapshot()`), `:90` (`q, l, e, _, timeouts, panics := rec.snapshot()` → `q, l, e, _, timeouts, panics, _ := rec.snapshot()`), `:151`, `:178` similarly, and `agent/sched/sched_test.go:483` (`_, _, _, admission, _, _ := rec.snapshot()` → `_, _, _, admission, _, _, _ := rec.snapshot()`). Run `go build ./sched/...` after this step and fix any remaining mismatched-arity errors the same way — same completeness-via-compiler approach as Task 1.

- [ ] **Step 3: Write the 8 new sched-level tests**

Add to `agent/sched/sched_test.go`:

```go
func TestRun_RetryDefaultIsSingleAttempt(t *testing.T) {
	var calls int32
	jobs := []Job{{Run: func(ctx context.Context) bool {
		atomic.AddInt32(&calls, 1)
		return true
	}}}
	Run(context.Background(), 1, NewLockManager(), jobs, nil)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls = %d, want 1 (zero-value Retry means exactly one attempt)", got)
	}
}

func TestRun_RetriesUpToMaxAttempts(t *testing.T) {
	var calls int32
	jobs := []Job{{
		Retry: RetryPolicy{MaxAttempts: 3, Backoff: func(int) time.Duration { return time.Millisecond }},
		Run: func(ctx context.Context) bool {
			atomic.AddInt32(&calls, 1)
			return true
		},
	}}
	Run(context.Background(), 1, NewLockManager(), jobs, nil)
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("calls = %d, want exactly 3 (MaxAttempts), never more", got)
	}
}

func TestRun_RetryStopsOnNonRetryableOutcome(t *testing.T) {
	var calls int32
	jobs := []Job{{
		Retry: RetryPolicy{MaxAttempts: 5, Backoff: func(int) time.Duration { return time.Millisecond }},
		Run: func(ctx context.Context) bool {
			atomic.AddInt32(&calls, 1)
			return false
		},
	}}
	Run(context.Background(), 1, NewLockManager(), jobs, nil)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls = %d, want 1 -- a non-retryable outcome must stop the loop immediately", got)
	}
}

// TestRun_RetryReleasesLimiterAndLockBetweenAttempts is the core property of
// this design: an independent acquire attempted during the backoff window
// must succeed promptly, proving the slot and lock are genuinely free, not
// idle-held across the sleep.
func TestRun_RetryReleasesLimiterAndLockBetweenAttempts(t *testing.T) {
	p := &ResourceProfile{Domains: []ResourceLock{{Domain: "registry"}}, Scope: "local", Risk: RiskModification}
	limiter := NewConcurrencyLimiter(1)
	lm := NewLockManager()

	backoffStarted := make(chan struct{})
	releaseBackoff := make(chan struct{})
	var attempts int32
	jobs := []Job{{
		Resource: p,
		Retry: RetryPolicy{MaxAttempts: 2, Backoff: func(int) time.Duration {
			close(backoffStarted)
			<-releaseBackoff
			return 0
		}},
		Run: func(ctx context.Context) bool {
			n := atomic.AddInt32(&attempts, 1)
			return n == 1 // retry once, then succeed
		},
	}}

	done := make(chan struct{})
	go func() {
		Run(context.Background(), 1, lm, jobs, nil, WithConcurrencyLimiter(limiter))
		close(done)
	}()

	<-backoffStarted
	// While the job is deliberately parked inside its backoff callback (attempt
	// 1 already released its slot and lock -- see Run's loop ordering), both
	// must be independently acquirable right now.
	if !limiter.Acquire(context.Background()) {
		t.Fatal("ConcurrencyLimiter slot not free during backoff -- it's being held idle")
	}
	limiter.Release()
	reqs := resolve(p)
	if !lm.AcquireCtx(context.Background(), reqs) {
		t.Fatal("resource lock not free during backoff -- it's being held idle")
	}
	lm.Release(reqs)

	close(releaseBackoff)
	<-done
}

func TestRun_RetryBackoffInterruptedByContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	jobs := []Job{{
		Retry: RetryPolicy{MaxAttempts: 5, Backoff: func(int) time.Duration { return time.Minute }},
		Run: func(ctx context.Context) bool {
			return true
		},
	}}

	done := make(chan struct{})
	go func() {
		Run(ctx, 1, NewLockManager(), jobs, nil)
		close(done)
	}()

	time.Sleep(20 * time.Millisecond) // let attempt 1 finish and enter backoff
	cancel()

	select {
	case <-done:
		// expected: cancellation interrupts the backoff immediately
	case <-time.After(1 * time.Second):
		t.Fatal("Run did not return promptly after ctx cancel during a long backoff")
	}
}

func TestRun_PanicDuringAttemptIsNotRetried(t *testing.T) {
	rec := &fakeRecorder{}
	var calls int32
	jobs := []Job{{
		Retry: RetryPolicy{MaxAttempts: 3, Backoff: func(int) time.Duration { return time.Millisecond }},
		Run: func(ctx context.Context) bool {
			atomic.AddInt32(&calls, 1)
			panic("boom")
		},
	}}
	Run(context.Background(), 1, NewLockManager(), jobs, nil, WithRecorder(rec))
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls = %d, want 1 -- a panic must never be retried", got)
	}
	_, _, _, _, _, panics, _ := rec.snapshot()
	if panics != 1 {
		t.Errorf("panics = %d, want 1", panics)
	}
}

func TestRun_ScheduleTimeoutIsNeverRetried(t *testing.T) {
	p := &ResourceProfile{Domains: []ResourceLock{{Domain: "exclusive"}}, Scope: "global"}
	lm := NewLockManager()
	reqs := resolve(p)
	if !lm.AcquireCtx(context.Background(), reqs) {
		t.Fatal("setup: failed to pre-hold the lock")
	}
	defer lm.Release(reqs)

	var timeoutCalls, runCalls int32
	jobs := []Job{{
		Resource: p,
		Schedule: 20 * time.Millisecond,
		OnScheduleTimeout: func() {
			atomic.AddInt32(&timeoutCalls, 1)
		},
		Retry: RetryPolicy{MaxAttempts: 3, Backoff: func(int) time.Duration { return time.Millisecond }},
		Run: func(ctx context.Context) bool {
			atomic.AddInt32(&runCalls, 1)
			return true
		},
	}}
	Run(context.Background(), 1, lm, jobs, nil)

	if got := atomic.LoadInt32(&timeoutCalls); got != 1 {
		t.Errorf("OnScheduleTimeout calls = %d, want exactly 1", got)
	}
	if got := atomic.LoadInt32(&runCalls); got != 0 {
		t.Errorf("Run calls = %d, want 0 -- schedule timeout must never reach Run", got)
	}
}

func TestRun_RetryRecordsRetryCountViaRecorder(t *testing.T) {
	rec := &fakeRecorder{}
	jobs := []Job{{
		Retry: RetryPolicy{MaxAttempts: 4, Backoff: func(int) time.Duration { return time.Millisecond }},
		Run: func(ctx context.Context) bool {
			return true
		},
	}}
	Run(context.Background(), 1, NewLockManager(), jobs, nil, WithRecorder(rec))
	_, _, _, _, _, _, retries := rec.snapshot()
	if retries != 3 {
		t.Errorf("retries = %d, want 3 (MaxAttempts - 1)", retries)
	}
}
```

(`resolve` is the existing unexported helper `runJob` itself uses — already in scope within package `sched`'s test file. `RiskModification`/`RiskObservation` are the existing exported constants from Phase 5.)

- [ ] **Step 4: Run the new tests to verify they fail**

Run: `go test ./sched/... -run 'TestRun_RetryDefaultIsSingleAttempt|TestRun_RetriesUpToMaxAttempts|TestRun_RetryStopsOnNonRetryableOutcome|TestRun_RetryReleasesLimiterAndLockBetweenAttempts|TestRun_RetryBackoffInterruptedByContextCancel|TestRun_PanicDuringAttemptIsNotRetried|TestRun_ScheduleTimeoutIsNeverRetried|TestRun_RetryRecordsRetryCountViaRecorder' -v`

Expected: compiles cleanly (`Job.Retry` and `Recorder.Retry()` already exist from Step 2) but FAILs on every attempt-count/retry-count assertion, since `Run`'s worker loop doesn't consult `j.Retry` yet -- Step 5 is what actually makes these tests meaningful.

- [ ] **Step 5: Restructure `Run`'s worker loop**

In `agent/sched/scheduler.go`, replace the body of the `for j := range ch { ... }` loop with:

```go
		for j := range ch {
			if cfg.rec != nil && !j.Queued.IsZero() {
				cfg.rec.QueueWait(time.Since(j.Queued))
			}
			if ctx.Err() != nil {
				continue
			}
			gate.Wait(ctx)
			if ctx.Err() != nil {
				continue
			}

			maxAttempts := j.Retry.maxAttempts()
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				if attempt > 1 {
					if cfg.rec != nil {
						cfg.rec.Retry()
					}
					select {
					case <-time.After(j.Retry.backoff(attempt - 1)):
					case <-ctx.Done():
					}
					if ctx.Err() != nil {
						break
					}
					gate.Wait(ctx)
					if ctx.Err() != nil {
						break
					}
				}

				if cfg.riskGate != nil {
					admissionStart := time.Now()
					if !cfg.riskGate.Allow(ctx, effectiveRisk(j.Resource)) {
						break
					}
					if cfg.rec != nil {
						cfg.rec.AdmissionWait(time.Since(admissionStart))
					}
				}

				var retry bool
				if cfg.limiter != nil {
					if !cfg.limiter.Acquire(ctx) {
						break
					}
					retry = runJob(ctx, lm, j, cfg.rec)
					cfg.limiter.Release()
				} else {
					retry = runJob(ctx, lm, j, cfg.rec)
				}
				if !retry || attempt == maxAttempts {
					break
				}
			}
		}
```

- [ ] **Step 6: Run the new tests to verify they pass**

Run the same command as Step 4.

Expected: PASS, all 8 tests named in the `-run` regex above.

- [ ] **Step 7: Run the full `agent/sched` suite**

Run: `go test ./sched/... -v`

Expected: PASS, every test including all of Task 1's migrated closures and Phase 1-6's existing tests — the default `Retry` zero value must make this a no-op for every job that doesn't set it.

- [ ] **Step 8: Commit**

```bash
git add agent/sched/retry.go agent/sched/scheduler.go agent/sched/metrics.go agent/sched/metrics_test.go agent/sched/sched_test.go
git commit -m "$(cat <<'EOF'
feat(agent): bounded per-attempt retry loop in sched.Run

RetryPolicy (MaxAttempts + Backoff func) is generic in sched, with no
opinion on why a policy is generous or conservative -- that judgment
stays in package main (Phase 7's wiring, next commits). Run's worker
loop now repeats the full RiskGate -> ConcurrencyLimiter -> lock ->
execute -> release cycle per attempt, sleeping between attempts while
holding neither the admission slot nor the lock, so backoff never
undermines the fairness work from Phases 3-6. A schedule timeout is
never retried. Recorder.Retry() lands in this same commit as its real
call site, avoiding the interface-without-a-caller gap Phase 5's
self-review caught.

Spec: docs/superpowers/specs/2026-09-06-phase7-priority-aware-retry-backoff-design.md

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y
EOF
)"
git push
```

---

### Task 3: `runMetrics` production `Retry()` implementation and `sched_retry_count` telemetry

**Files:**
- Modify: `agent/sched_metrics.go`
- Test: `agent/sched_metrics_test.go`

**Interfaces:**
- Consumes: `sched.Recorder`'s `Retry()` method (from Task 2) — `runMetrics` already declares `var _ sched.Recorder = (*runMetrics)(nil)`, so this task's `Retry()` method keeps that assertion satisfied.
- Produces: nothing further tasks depend on (this is the production telemetry sink, a leaf).

- [ ] **Step 1: Write the new test (fails first)**

Add to `agent/sched_metrics_test.go`:

```go
func TestRunMetrics_Retry_EmitsRetryCount(t *testing.T) {
	m := &runMetrics{}
	m.Retry()
	m.Retry()
	m.Retry()

	sink := newFakeMetricSink()
	m.report(sink, 5)

	if got := sink.values("sched_retry_count"); len(got) != 1 || got[0] != 3 {
		t.Errorf("sched_retry_count = %v, want [3]", got)
	}
}

func TestRunMetrics_Retry_NoCallsEmitsNothing(t *testing.T) {
	m := &runMetrics{}
	m.ExecutionTime(10 * time.Millisecond) // some unrelated activity, no retries

	sink := newFakeMetricSink()
	m.report(sink, 1)

	if got := sink.values("sched_retry_count"); len(got) != 0 {
		t.Errorf("sched_retry_count = %v, want no emission (no retries recorded)", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./... -run 'TestRunMetrics_Retry_EmitsRetryCount|TestRunMetrics_Retry_NoCallsEmitsNothing' -v` (from `agent/`)

Expected: compile failure — `runMetrics` has no `Retry` method, so it no longer satisfies `sched.Recorder` (the `var _ sched.Recorder = (*runMetrics)(nil)` assertion in `sched_metrics.go` fails to compile once `Retry()` exists on the interface from Task 2 but not yet on `runMetrics`).

- [ ] **Step 3: Implement `runMetrics.Retry()` and extend `report()`**

In `agent/sched_metrics.go`, add a field to the `runMetrics` struct (after `jobPanics int64`):

```go
	retryCount int64
```

Add the method (after `JobPanic()`):

```go
func (m *runMetrics) Retry() {
	atomic.AddInt64(&m.retryCount, 1)
}
```

In `report()`, add after the `if admissionN > 0 { ... }` block:

```go
	if retries := atomic.LoadInt64(&m.retryCount); retries > 0 {
		logger.Metric("sched_retry_count", float64(retries), "count")
	}
```

- [ ] **Step 4: Run to verify it passes**

Run the same command as Step 2. Expected: PASS.

- [ ] **Step 5: Run the full `sched_metrics_test.go` suite**

Run: `go test ./... -run TestRunMetrics -v` (from `agent/`)

Expected: PASS, including the pre-existing `TestRunMetrics_ReportEmitsAveragesAndMaxima` and `TestRunMetrics_ReportSkipsAveragesForUnusedDimensions` — unmodified.

- [ ] **Step 6: Commit**

```bash
git add agent/sched_metrics.go agent/sched_metrics_test.go
git commit -m "$(cat <<'EOF'
feat(agent): sched_retry_count telemetry in runMetrics

Production Recorder.Retry() implementation, aggregated per-run like
every other scheduler metric (never per-attempt) -- emitted only when
nonzero, matching the existing sched_admission_* convention.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y
EOF
)"
git push
```

---

### Task 4: Risk→policy mapping, retryable-outcome classification, and `runScenario` wiring

**Files:**
- Modify: `agent/sched/riskgate.go` (export `effectiveRisk` → `EffectiveRisk`)
- Modify: `agent/sched/scheduler.go`, `agent/sched/riskgate_test.go` (update the 2 internal call sites of the renamed function)
- Modify: `agent/pressure_loop.go` (`retryPolicyForRisk`)
- Modify: `agent/events.go` (`isRetryableResult`)
- Modify: `agent/agent.go` (`runScenario`'s Job-building loop, ~lines 622-772)
- Test: `agent/pressure_loop_test.go`, `agent/events_test.go`

**Interfaces:**
- Consumes: `sched.RetryPolicy` (Task 2), `sched.RiskObservation`/`sched.RiskModification` (existing, Phase 5).
- Produces: `sched.EffectiveRisk(p *sched.ResourceProfile) string` (exported), `retryPolicyForRisk(risk string) sched.RetryPolicy`, `isRetryableResult(r protocol.ExecResult) bool` — all consumed only within `agent.go`'s wiring in this same task.

**Why exporting `EffectiveRisk` is necessary:** `package main` needs to
know a step's risk classification *before* constructing its `sched.Job`
(to set `Job.Retry`), but `sched.effectiveRisk` is currently unexported
— `sched.Run`'s own internal call to it (for `RiskGate.Allow`) doesn't
need this, but `agent.go` now does, since it's the caller deciding the
retry policy, not `sched` itself.

- [ ] **Step 1: Export `effectiveRisk`**

In `agent/sched/riskgate.go`, rename `func effectiveRisk(p *ResourceProfile) string` to `func EffectiveRisk(p *ResourceProfile) string` (update its doc comment's `effectiveRisk` mentions to `EffectiveRisk` too). In `agent/sched/scheduler.go`, update the one internal call site: `effectiveRisk(j.Resource)` → `EffectiveRisk(j.Resource)`. In `agent/sched/riskgate_test.go`, update its two references (`effectiveRisk(c.p)` and the error message's `effectiveRisk()`) to `EffectiveRisk`.

Run: `go build ./sched/... && go test ./sched/...` (from `agent/`) — expected PASS, this is a pure rename.

- [ ] **Step 2: Write `TestRetryPolicyForRisk` (fails first)**

Add to `agent/pressure_loop_test.go`:

```go
func TestRetryPolicyForRisk(t *testing.T) {
	cases := []struct {
		risk        string
		wantMax     int
		wantBackoff []time.Duration // Backoff(1), Backoff(2), Backoff(3)
	}{
		{sched.RiskObservation, 4, []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}},
		{sched.RiskModification, 2, []time.Duration{5 * time.Second}},
		{sched.RiskUnknown, 2, []time.Duration{5 * time.Second}},
		{"some-other-unrecognized-value", 2, []time.Duration{5 * time.Second}},
	}
	for _, c := range cases {
		p := retryPolicyForRisk(c.risk)
		if p.MaxAttempts != c.wantMax {
			t.Errorf("retryPolicyForRisk(%q).MaxAttempts = %d, want %d", c.risk, p.MaxAttempts, c.wantMax)
		}
		for i, want := range c.wantBackoff {
			if got := p.Backoff(i + 1); got != want {
				t.Errorf("retryPolicyForRisk(%q).Backoff(%d) = %v, want %v", c.risk, i+1, got, want)
			}
		}
	}
}
```

Run: `go test ./... -run TestRetryPolicyForRisk -v` (from `agent/`) — expected: compile failure, `retryPolicyForRisk` undefined.

- [ ] **Step 3: Implement `retryPolicyForRisk`**

In `agent/pressure_loop.go`, add (near `ceilingForLevel`/`riskAllowedForLevel`):

```go
// retryPolicyForRisk maps a step's effective risk classification to a retry
// policy. Observation steps are non-modifying, so retrying them carries no
// side-effect-compounding risk -- they get a more generous budget.
// Modification steps can compound real side effects on a repeat, so they get
// a conservative budget. A step with no curated profile (sched.RiskUnknown)
// is treated the same as Modification, for the same conservative-by-default
// reasoning EffectiveRisk itself already applies.
func retryPolicyForRisk(risk string) sched.RetryPolicy {
	if risk == sched.RiskObservation {
		return sched.RetryPolicy{
			MaxAttempts: 4, // 1 initial + 3 retries
			Backoff: func(attempt int) time.Duration {
				return time.Duration(1<<(attempt-1)) * time.Second // 1s, 2s, 4s
			},
		}
	}
	return sched.RetryPolicy{
		MaxAttempts: 2, // 1 initial + 1 retry
		Backoff: func(attempt int) time.Duration {
			return 5 * time.Second
		},
	}
}
```

Run the Step 2 command again — expected PASS.

- [ ] **Step 4: Write `TestIsRetryableResult` (fails first)**

Add to `agent/events_test.go`:

```go
func TestIsRetryableResult(t *testing.T) {
	cases := []struct {
		name string
		r    protocol.ExecResult
		want bool
	}{
		{"blocked always non-retryable", protocol.ExecResult{Blocked: true, ExitCode: 1}, false},
		{"blocked even with exit 0", protocol.ExecResult{Blocked: true, ExitCode: 0}, false},
		{"timed out is retryable", protocol.ExecResult{TimedOut: true}, true},
		{"success is not retryable", protocol.ExecResult{ExitCode: 0}, false},
		{"nonzero exit (fail) is retryable", protocol.ExecResult{ExitCode: 1}, true},
		{"exit -1 (error) is retryable", protocol.ExecResult{ExitCode: -1}, true},
	}
	for _, c := range cases {
		if got := isRetryableResult(c.r); got != c.want {
			t.Errorf("%s: isRetryableResult() = %v, want %v", c.name, got, c.want)
		}
	}
}
```

Run: `go test ./... -run TestIsRetryableResult -v` (from `agent/`) — expected: compile failure, `isRetryableResult` undefined.

- [ ] **Step 5: Implement `isRetryableResult`**

In `agent/events.go`, add (after `eventForResult`):

```go
// isRetryableResult classifies whether a step's outcome warrants a retry.
// Mirrors eventForResult's classification: TimedOut -> retryable, Blocked ->
// never (a security control already caught this; retrying is pointless and
// could look like an attack loop), ExitCode == 0 -> success (never
// retryable), any other nonzero exit (fail or the -1 error sentinel) ->
// retryable.
func isRetryableResult(r protocol.ExecResult) bool {
	if r.Blocked {
		return false
	}
	return r.TimedOut || r.ExitCode != 0
}
```

Run the Step 4 command again — expected PASS.

- [ ] **Step 6: Wire retry into `runScenario`'s Job-building loop**

In `agent/agent.go`, after `ran := make([]bool, total)` (line 623), add:

```go
	attemptCounters := make([]int32, total)
```

In the `for i := range steps` loop (starting line 674), immediately after `step := steps[i]` (line 675), add:

```go
		risk := sched.EffectiveRisk(step.Resource)
		retryPolicy := retryPolicyForRisk(risk)
```

Change the `jobs[i] = sched.Job{...}` literal (line 689) to include the new field:

```go
		jobs[i] = sched.Job{
			Resource: step.Resource,
			Schedule: schedDur,
			Queued:   time.Now(),
			Retry:    retryPolicy,
```

(leaving `OnScheduleTimeout: func() { ... }` — line 693 — completely unchanged, since a schedule timeout is never retried and that closure's signature stays `func()`).

The `Run:` closure at line 710 was already migrated to `func(ctx context.Context) bool { ... return false }` shape by Task 1 (including its quarantine-branch early exit, which already reads `return false` after that task) — nothing further needed there. This task only changes the closure's final block, from:

```go
				typ, verdict := eventForResult(r)
				payload := map[string]any{"durationMs": r.DurationMs, "exitCode": r.ExitCode}
				if verdict != "" {
					payload["verdict"] = verdict
				}
				if typ == "timeout" {
					payload["reason"] = "execute"
				}
				emit(RunEvent{Type: typ, TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name, Payload: payload})
			},
```

to:

```go
				typ, verdict := eventForResult(r)
				payload := map[string]any{"durationMs": r.DurationMs, "exitCode": r.ExitCode}
				if verdict != "" {
					payload["verdict"] = verdict
				}
				if typ == "timeout" {
					payload["reason"] = "execute"
				}
				emit(RunEvent{Type: typ, TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name, Payload: payload})

				retry := isRetryableResult(r)
				attemptNum := atomic.AddInt32(&attemptCounters[i], 1)
				if retry && int(attemptNum) < retryPolicy.MaxAttempts {
					log.Printf("[*]   [%d/%d] %s will retry (attempt %d/%d)", i+1, total, step.TechniqueID, attemptNum, retryPolicy.MaxAttempts)
					emit(RunEvent{Type: "retrying", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
						Payload: map[string]any{"attempt": int(attemptNum), "maxAttempts": retryPolicy.MaxAttempts}})
				}
				return retry
			},
```

The `attemptNum < retryPolicy.MaxAttempts` check exists because `Job.Run` has no attempt-number parameter — `sched` deliberately doesn't expose one, so the closure tracks it independently via `attemptCounters[i]`, comparing against the exact same `retryPolicy.MaxAttempts` value already used to configure `Job.Retry`, so the "retrying" event is only emitted when the scheduler will actually attempt again (not on a step's genuinely final, budget-exhausted failure).

- [ ] **Step 7: Build and run the full agent module test suite**

Run: `cd agent && go build ./... && go test ./...`

Expected: builds clean, all tests pass — this wiring step has no test of its own beyond Steps 2/4's pure-function tests (per the spec's Non-goals: no new end-to-end `runScenario` integration test, since the mechanism is already fully proven at the `sched` level in Task 2).

- [ ] **Step 8: Commit**

```bash
git add agent/sched/riskgate.go agent/sched/scheduler.go agent/sched/riskgate_test.go agent/pressure_loop.go agent/pressure_loop_test.go agent/events.go agent/events_test.go agent/agent.go
git commit -m "$(cat <<'EOF'
feat(agent): wire risk-aware retry policy into runScenario

retryPolicyForRisk maps a step's effective risk to a RetryPolicy
(Observation: 4 attempts, 1s/2s/4s backoff; Modification/Unknown/other:
2 attempts, 5s backoff) -- Observation steps are non-modifying so
retrying them carries no side-effect-compounding risk, Modification
steps can compound real side effects on a repeat so they stay
conservative. isRetryableResult mirrors eventForResult's own
classification (timeout/fail/error retryable, blocked/pass not).
sched.effectiveRisk is exported as EffectiveRisk since package main
now needs it to choose a policy before Job construction, which sched
itself never needed to expose before.

Spec: docs/superpowers/specs/2026-09-06-phase7-priority-aware-retry-backoff-design.md

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y
EOF
)"
git push
```

---

### Task 5: Final regression

**Files:** None modified (verification only).

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: nothing further.

- [ ] **Step 1: Run the full agent module test suite**

Run: `cd agent && go test ./... -count=1 -v`

Expected: PASS, 0 failures across every package (`agent`, `agent/pressure`, `agent/protocol`, `agent/sched`, `agent/statusclient`). `-race` is skipped — unavailable on this Windows host (`CGO_ENABLED=0`, no `gcc` in `PATH`, confirmed earlier this session).

- [ ] **Step 2: Verify git state**

```bash
git log --oneline -6
git log --oneline -1 main
git log --oneline -1 origin/main
git status --porcelain -- agent/ docs/
```

Expected: the 4 Task 1-4 commits on top of `6477f5c` (the spec commit), `main` and `origin/main` at the same commit, and an empty `git status --porcelain` for the touched paths.

## Final Verification

1. `go test ./agent/... -count=1` passes with 0 failures.
2. `git log --oneline -1 main` == `git log --oneline -1 origin/main`.
3. `git status --porcelain -- agent/ docs/` is empty.
4. Every non-goal from the spec remains true: no changes to `ConcurrencyLimiter`/`RiskGate`/`LockManager` internals, no new `Priority` field, no cross-attempt cleanup logic added (none needed), schedule timeouts still never retried.
