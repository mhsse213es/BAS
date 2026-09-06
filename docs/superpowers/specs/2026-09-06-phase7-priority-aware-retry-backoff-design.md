# Phase 7: Priority-Aware Retry Backoff for Failed Steps Design

## Context

Phases 1-6 of the agent scheduler's adaptive control plane are shipped on
`main` (WS reconnect backoff/jitter, scheduler telemetry, `sched.ConcurrencyLimiter`
admission ceiling, host-pressure-driven ceiling, `sched.RiskGate` risk-aware
admission, and FIFO-fair `ConcurrencyLimiter` admission ordering — commits
`c3c8f4d`..`a1d4e59`). Staging (`192.168.10.78:9443`) remains unreachable, so
this phase — like Phase 6 — is designed and justified on real code and
engineering grounds, not live telemetry evidence, per this project's
"measure before adapting" discipline.

Phase 7 adds retry-with-backoff for scenario steps that fail, with the retry
budget scaled by the step's risk classification ("priority-aware").

## Investigation: what exists today

Verified against real code before designing anything:

1. **No retry mechanism exists anywhere in the step-execution path.**
   `execStep` (`agent/executor.go:173`) is called exactly once per step, from
   a single call site in `agent.go`'s `runScenario` (line 754). Whatever
   outcome comes back — `pass`/`fail`/`error`/`timeout`/`blocked`, classified
   by `eventForResult` (`agent/events.go:31`) from `protocol.ExecResult`'s
   `TimedOut`/`Blocked`/`ExitCode` fields — is final.
2. **`agent/backoff.go`'s existing backoff functions are WS-reconnect-only**
   (package `main`, Phase 1) — `wsBackoffDelay`/`wsJitter`/`wsReconnectBackoff`
   have no relationship to step execution.
3. **No "priority" concept exists on a step anywhere.** `Priority` appears
   only for Windows job-object process priority (`job_windows.go`), a
   Windows privilege name string (`privileges.go`), and syslog priority
   parsing for detection (`detect_parse_posix.go`) — none scenario-related.
   This confirms Phase 6's finding still holds.
4. **The only "retry" code in the repo is `orchestrator/internal/scenario/caldera_store.go`'s** background retry of the initial Caldera ability-catalog load at server startup — entirely unrelated to step execution.
5. **`execStep` already runs step cleanup internally, once per call**
   (`runCleanup`/`reconcileCleanupVerdict`, visible at the pooled fast-path,
   `executor.go` ~192-197, mirrored in the main path ~457-459) — so a retry
   attempt naturally starts against a cleaned-up state from the prior
   attempt, with no new code needed for this to compose safely.

Per the user's explicit direction: "priority" maps to the existing risk
classification `RiskGate`/`effectiveRisk` already understand
(`RiskObservation`/`RiskModification`/`RiskUnknown`), not a new fabricated
field — the same reasoning that has governed every prior phase's refusal to
invent per-technique cost/priority data (Phase 4's CPU/memory weights, Phase
5's per-technique cost, Phase 6's declined priority-tier approach).

## Architectural fork: where retry attempts acquire resources

A retrying step must not hold its `ConcurrencyLimiter` admission slot or its
`LockManager` locks while backing off — doing so would idle-hold scarce
resources during a multi-second sleep, directly undermining the fairness and
pressure-responsiveness work Phases 3-6 built. This rules out a retry loop
living inside the existing `Job.Run` closure as a bare sleep-and-retry loop:
by the time that closure starts executing, `sched.Run`'s worker loop has
already acquired the RiskGate/ConcurrencyLimiter/locks for the closure's
entire duration (released only after it returns) — so looping inside it
would still hold everything across every backoff.

Two ways to achieve genuinely independent per-attempt admission were
considered:

- **Chosen: extend `sched.Job`/`sched.Run` natively.** `Job.Run`'s signature
  changes to return a `shouldRetry bool`; `sched.Run`'s worker loop itself
  becomes a bounded per-attempt loop, re-running the full
  `riskGate.Allow → limiter.Acquire → runJob → limiter.Release` cycle per
  attempt, sleeping (holding nothing) between them. Every attempt inherits
  `sched.Run`'s existing pause-gate integration, cancellation semantics, and
  telemetry for free, since it's the same pipeline. Cost: touches
  `scheduler.go`'s core `Run` function and `Job` struct, and changes
  `Job.Run`'s public signature (one call site in production code, 20 in
  tests — see Migration below).
- **Rejected: keep `scheduler.go` untouched, build retry entirely in
  `agent.go`** via new exported `sched` primitives, with retry-enabled steps
  bypassing `sched.Run`'s Job/worker-pool dispatch. Smaller footprint on
  `scheduler.go`, but `agent.go` would need to reimplement pause-gate
  integration, queue-wait telemetry, and cancellation semantics `sched.Run`
  already provides — real duplication, and a genuine risk that a retrying
  step behaves subtly differently under scenario pause/cancel than a
  non-retrying one. Rejected because this project has precedent for careful,
  well-tested core-file surgery (Phase 5's Task 3 gap-fix, Phase 6's full
  `limiter.go` rewrite) and that duplication risk is worse long-term than a
  well-tested change to `Run`'s worker loop.

## Design

### `RetryPolicy` (new, `agent/sched/retry.go`)

```go
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

### Risk → policy mapping (`agent/pressure_loop.go`, alongside `ceilingForLevel`/`riskAllowedForLevel`)

```go
// retryPolicyForRisk maps a step's effective risk classification to a retry
// policy. Observation steps are non-modifying, so retrying them carries no
// side-effect-compounding risk -- they get a more generous budget.
// Modification steps can compound real side effects on a repeat, so they get
// a conservative budget. A step with no curated profile (sched.RiskUnknown)
// is treated the same as Modification, for the same conservative-by-default
// reasoning effectiveRisk itself already applies.
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

### `Job`/`runJob`/`Run` changes (`agent/sched/scheduler.go`)

`Job` gains a field, and `Job.Run`'s signature changes:

```go
type Job struct {
	Resource *ResourceProfile
	// Run performs the work and reports whether this attempt's outcome
	// warrants a retry (per the caller's own classification of what it ran —
	// sched has no opinion on what "retryable" means, only how many times and
	// how far apart to try again). Ignored once Retry.MaxAttempts is
	// exhausted or the outcome already succeeded.
	Run      func(ctx context.Context) (shouldRetry bool)
	Schedule time.Duration
	OnScheduleTimeout func()
	Queued time.Time
	// Retry bounds how many times this Job's full admission-and-execute
	// cycle repeats on a retryable outcome. The zero value (MaxAttempts 0)
	// means exactly one attempt, identical to every Job before this phase.
	Retry RetryPolicy
}
```

`runJob` gains a return value, set by `j.Run`'s result and forced to `false`
on panic:

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
		if ctx.Err() == nil && j.OnScheduleTimeout != nil {
			if rec != nil {
				rec.ScheduleTimeout()
			}
			j.OnScheduleTimeout()
		}
		return false // schedule timeouts are never retried -- see Non-goals
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

`Run`'s worker loop replaces its single admission-and-execute block with a
bounded per-attempt loop:

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

A default `Job` (`Retry` zero value) gets `maxAttempts() == 1`: the loop
runs exactly once, the `attempt > 1` branch (backoff, `Retry()` telemetry)
never taken — byte-for-byte identical behavior to today. This is what lets
every existing `agent/sched` test keep passing after the migration below.

### Migration cost: `Job.Run` call sites

`Job.Run`'s signature change breaks every existing closure that constructs
one. Confirmed via grep: **21 call sites** — `agent.go` (1),
`sched/equiv_test.go` (2), `sched/metrics_test.go` (5), `sched/sched_test.go`
(13). Each currently reads `func(ctx context.Context) { ... }` with no
return and needs a trailing `return false` (correct for all of them — none
of today's test jobs want retry behavior). Purely mechanical, but real
enough to warrant its own implementation task, done first, so the build
stays green before any actual retry logic lands.

### Retryable-outcome classification (`agent.go`)

```go
func isRetryableResult(r protocol.ExecResult) bool {
	if r.Blocked {
		return false // a security control already caught this; retrying is pointless and could look like an attack loop
	}
	return r.TimedOut || r.ExitCode != 0
}
```

Mirrors `eventForResult`'s existing classification exactly
(`agent/events.go:31`): `TimedOut` → retryable, `Blocked` → never,
`ExitCode == 0` → success (never retryable), any other nonzero exit
(`fail` or the `-1` `error` case) → retryable.

The `Job.Run` closure in `runScenario`'s step-building loop keeps writing
`results[i]` and calling `emit(...)` on every attempt, since each attempt is
real, observable work — but also emits a lightweight `"retrying"` event when
an attempt fails and another is coming, so the run log shows why a step took
longer than one attempt's worth of time. This does not add to aggregated
per-run metrics volume (see Telemetry below), keeping the Full-Sweep-volume
discipline Phase 2 established.

### Telemetry

`Recorder` (`agent/sched/metrics.go`) gains one new method:

```go
Retry() // called once per retry attempt (not once per Job -- a Job that
        // retries twice calls this twice), aggregated per run like every
        // other Recorder method.
```

Implemented identically to `ScheduleTimeout()`/`JobPanic()` in both
`fakeRecorder` (test double) and `runMetrics` (production,
`agent/sched_metrics.go`). `runMetrics.report()` gains one new
aggregated-per-run metric, `sched_retry_count`, emitted only when nonzero
(matching Phase 5's `admissionN > 0` convention for optional metrics).

## Non-goals / out of scope

- **Schedule timeouts are never retried.** A schedule timeout (lock
  acquisition itself timing out, the existing `OnScheduleTimeout` path) is
  contention for a resource, not the step failing — `runJob` returns `false`
  unconditionally on that path. Retrying it would just be another wait on
  the same contended lock.
- **A new, fabricated `Priority` field or P0-P4 tiers** — declined for the
  same reason Phase 6's Approach B was declined: no real per-technique
  priority data exists to assign values from honestly. This phase reuses the
  existing, already-evidenced risk classification instead.
- **Cross-attempt cleanup logic** — `execStep` already runs cleanup
  internally per call (see Investigation, point 5); no new code needed.
- **A full `runScenario` end-to-end integration test** — the retry mechanism
  is fully proven at the `sched` level (Testing, items 1-9 below); wiring
  `Retry: retryPolicyForRisk(...)` and the new closure signature into
  `runScenario`'s existing step-building loop follows the exact pattern
  Phase 4/5 already used to wire `ConcurrencyLimiter`/`RiskGate` into that
  same closure, so no new integration test is planned beyond the two pure
  mapping-function tests (items 10-11).
- **Changes to `ConcurrencyLimiter`, `RiskGate`, or `LockManager` themselves**
  — this phase only changes how many times and how far apart `Run` calls
  into them per `Job`, not their own internals (Phase 6 already covered
  `ConcurrencyLimiter`'s fairness).

## Testing

`agent/sched` (new tests, alongside migrating the 21 existing `Job.Run` closures):

1. **`TestRun_RetryDefaultIsSingleAttempt`** — a `Job` with the zero-value
   `Retry` whose `Run` always returns `true` still executes exactly once.
2. **`TestRun_RetriesUpToMaxAttempts`** — `Run` returns `true` every time;
   assert it's called exactly `Retry.MaxAttempts` times, never more.
3. **`TestRun_RetryStopsOnNonRetryableOutcome`** — `Run` returns `false` on
   attempt 1 despite `MaxAttempts > 1`; assert only one attempt happens.
4. **`TestRun_RetryReleasesLimiterAndLockBetweenAttempts`** — the core
   property of this design: a `Job` with `Retry.MaxAttempts=2` and a real
   backoff delay, sharing a `ConcurrencyLimiter` (limit 1) and a resource
   lock with a second, independent acquire attempted from the test goroutine
   during the backoff window. Assert that second acquire succeeds promptly —
   proving the slot and lock are genuinely free during backoff.
5. **`TestRun_RetryBackoffInterruptedByContextCancel`** — cancel `ctx`
   partway through a deliberately long backoff; assert `Run` returns
   promptly (not after the full backoff elapses) and no further attempt
   happens.
6. **`TestRun_PanicDuringAttemptIsNotRetried`** — `Run` panics on attempt 1
   (never reaching a return value); assert exactly one attempt total and
   `JobPanic()` recorded once, regardless of `MaxAttempts`.
7. **`TestRun_ScheduleTimeoutIsNeverRetried`** — a `Job` whose locks are
   already held elsewhere so `Schedule` always expires, with
   `Retry.MaxAttempts > 1` configured; assert `OnScheduleTimeout` fires
   exactly once and `Run` is never called.
8. **`TestRun_RetryRecordsRetryCountViaRecorder`** — `fakeRecorder` gains a
   `retries int` counter via the new `Retry()` method; assert it increments
   exactly once per retry (`MaxAttempts - 1` times for a job that exhausts
   its budget).
9. Full existing `agent/sched` suite re-run after the 21-call-site migration
   — must pass unmodified.

`package main` (agent, new tests for the two pure mapping/classification functions):

10. **`TestRetryPolicyForRisk`** — table test: `RiskObservation` →
    `MaxAttempts=4`, `Backoff(1)=1s`, `Backoff(2)=2s`, `Backoff(3)=4s`;
    `RiskModification` and `RiskUnknown` (and any other non-Observation
    value) → `MaxAttempts=2`, `Backoff(1)=5s`.
11. **`TestIsRetryableResult`** — table test: `Blocked=true` (any exit code)
    → `false`; `TimedOut=true` → `true`; `ExitCode=0, Blocked=false` →
    `false`; `ExitCode=1` or `ExitCode=-1` (`Blocked=false`) → `true`.

## Success criteria

1. `TestRun_RetryReleasesLimiterAndLockBetweenAttempts` passes
   deterministically, proving no admission slot or lock is idle-held during
   backoff.
2. Every existing `agent/sched` test passes unmodified after the
   `Job.Run` signature migration (behavior-preserving refactor for the
   non-retry default path).
3. A schedule timeout never triggers a retry (`TestRun_ScheduleTimeoutIsNeverRetried`).
4. `retryPolicyForRisk` and `isRetryableResult` are pure, fully
   table-tested functions with no dependency on live telemetry or fabricated
   per-technique data.
5. `sched_retry_count` is reported per-run, only when nonzero, following
   the same aggregation discipline as every prior phase's optional metrics.
