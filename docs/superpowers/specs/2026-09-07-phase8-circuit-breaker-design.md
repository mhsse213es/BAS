# Phase 8: Circuit Breaker for Correlated Step Failures Design

## Context

Phases 1-7 of the agent scheduler's adaptive control plane are shipped on
`main` (WS reconnect backoff/jitter, scheduler telemetry, `sched.ConcurrencyLimiter`
admission ceiling, host-pressure-driven ceiling, `sched.RiskGate` risk-aware
admission, FIFO-fair `ConcurrencyLimiter`, and priority-aware per-step retry
backoff — commits `39242a3`..`e802a77`). "Circuit breaker" was identified as
a genuine gap during this session: comparing this project's actual work
against a list of concerns (observability plumbing, admission controller,
pressure model, circuit breakers) found the first three already covered by
Phases 2-6 under different names, but "circuit breaker" matched nothing —
confirmed by grepping the whole repository, which found the term nowhere in
`agent/` or `agent/sched`, only in an unrelated TAXII connector spec.

## What problem this solves, and what it doesn't

Phase 7's retry mechanism is entirely local to one `Job`'s own lifecycle: a
step gets up to 4 attempts (Observation) or 2 (Modification/Unknown), each
independently passing admission and lock acquisition, with backoff between.
Nothing in that mechanism has any visibility into *other* steps — if steps
targeting the same domain or the same technique are failing across a run,
Phase 7's retry has no way to notice or act on that correlation. This phase
adds that missing cross-step signal: track consecutive terminal-outcome
failures per correlation key, and stop attempting new work against a key
once it's clearly broken for the rest of the run.

## Investigation: what exists today

- `sched.Job` has no `TechniqueID` field — only `agent.go`'s `step.TechniqueID`
  (part of `ScenarioStep`, a `package main` type) carries this. A
  domain-keyed breaker could technically live inside `agent/sched` (via
  `ResourceProfile.Domains`, an existing `sched` concept), but a
  technique-keyed one cannot without adding a field `sched` doesn't
  otherwise need.
- `agent/sched/locks.go`'s `LockManager` is purely mechanical (a
  `sync.RWMutex` per key, acquire/release) — no failure-tracking or health
  concept exists there today.
- `orchestrator/internal/scenario/outcome.go:254` already classifies a step
  as `OutcomeSkipped` whenever its combined output's first line starts with
  `skip:` (e.g. `"skip: technique not in store"`) — an existing convention
  for "intentionally not run," currently unused by anything on the agent
  side. `combined` is built from `ExecResult.Stdout + "\n" + ExecResult.Stderr`
  (`orchestrator/internal/scenario/interpreter.go:32`), and the orchestrator's
  own `ExecResult` type decodes the same wire shape the agent's
  `protocol.ExecResult` produces.

## Scope decision: package `main` only, not `agent/sched`

A breaker-open check only needs to skip *before* `execStep` runs — not
before scheduler admission. It can live entirely inside `agent.go`'s
existing `Job.Run` closure, in the same place the payload-quarantine check
already short-circuits today, with **zero changes to `scheduler.go`**. The
cost: a breaker-skipped job still briefly acquires its admission slot and
lock before releasing them — cheap compared to the `execStep` process-spawn
it exists to avoid, and not worth touching `scheduler.go` a third time
without evidence this specific overhead matters in practice. If real
telemetry later shows breaker-related admission churn is a genuine
Full-Sweep-scale problem, moving the check earlier (into `sched.Run` itself)
is a targeted follow-up, not part of this phase.

## Side-finding, not fixed by this phase

Re-reading `agent.go`'s `Run:` closure during this design pass found that
`startedJobs`, `completed` (which drives the local progress bar via
`a.localSt.UpdateProgress`), and `finishedJobs` all increment
unconditionally at the very top of the closure. Phase 7 made this closure
run once per retry attempt (not once per step), so a retrying step now
inflates these counters past `total` on every retry — a latent bug Phase 7
introduced, invisible to Phase 7's own tests (explicitly scoped to
`agent/sched`, never exercising `runScenario`'s own counters). A
breaker-skipped step doesn't worsen this (a skip always returns `false`
immediately, never re-invoking the closure), so it's independent of this
phase's own correctness — flagged here for a small, separate, bounded fix
later, not addressed by this design.

## Design

### `circuitBreaker` (new, `agent/circuitbreaker.go`, package `main`)

```go
// circuitBreaker tracks consecutive terminal-outcome failures per key,
// blocking new work against a key once it trips. Constructed fresh per
// scenario run (see runScenario) -- same per-run lifecycle as
// ConcurrencyLimiter and RiskGate, so a breaker that opened due to a bad
// run self-heals for the next run with no staleness risk.
type circuitBreaker struct {
	mu          sync.Mutex
	threshold   int
	consecutive map[string]int
	open        map[string]bool
}

// circuitBreakerThreshold: consecutive terminal-outcome failures against the
// same key before its breaker opens. One fixed value shared by both the
// technique and domain keyspaces -- risk-based retry (Phase 7) already
// differentiates Observation vs Modification's own retry budget; scaling
// this threshold by risk too would add complexity with no evidence behind
// it (see Non-goals).
const circuitBreakerThreshold = 3

func newCircuitBreaker(threshold int) *circuitBreaker {
	return &circuitBreaker{
		threshold:   threshold,
		consecutive: make(map[string]int),
		open:        make(map[string]bool),
	}
}

// isOpen reports whether key's breaker is currently tripped.
func (b *circuitBreaker) isOpen(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open[key]
}

// recordOutcome updates key's consecutive-failure count from a Job's
// terminal outcome (never called per individual retry attempt -- see
// "Interaction with Phase 7 retry" below). success resets the count to 0;
// a failure increments it and opens the breaker once it reaches threshold.
func (b *circuitBreaker) recordOutcome(key string, success bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if success {
		b.consecutive[key] = 0
		b.open[key] = false
		return
	}
	b.consecutive[key]++
	if b.consecutive[key] >= b.threshold {
		b.open[key] = true
	}
}

// anyOpen reports whether any of keys' breakers is currently tripped --
// blocking a step if even one of the domains/technique it touches is known
// broken this run, the same conservative default already used for locking
// (an unlabeled or unrecognised profile resolves to a fully serial lock).
func (b *circuitBreaker) anyOpen(keys []string) bool {
	for _, k := range keys {
		if b.isOpen(k) {
			return true
		}
	}
	return false
}

// recordAll records the same terminal outcome against every one of keys.
func (b *circuitBreaker) recordAll(keys []string, success bool) {
	for _, k := range keys {
		b.recordOutcome(k, success)
	}
}
```

Key derivation, a pure and independently testable helper:

```go
// breakerKeysForStep returns every circuit-breaker key a step participates
// in: its technique, plus one key per declared resource domain. A step with
// no curated ResourceProfile or no declared Domains still gets its
// technique key -- the domain axis only participates when domains are
// actually declared, mirroring how ResourceProfile itself only narrows
// locking when populated.
func breakerKeysForStep(techniqueID string, p *sched.ResourceProfile) []string {
	keys := []string{"technique:" + techniqueID}
	if p == nil {
		return keys
	}
	for _, d := range p.Domains {
		keys = append(keys, "domain:"+d.Domain)
	}
	return keys
}
```

### Interaction with Phase 7 retry: record only the terminal outcome

A step's `Job.Run` closure is invoked once per retry attempt (Phase 7's
design). If `recordOutcome` were called on every invocation rather than only
the terminal one, a single step's own bounded retry budget (up to 4 attempts
for Observation) could trip a "cross-step correlation" breaker entirely from
its own internal noise — which blurs what the breaker is actually meant to
detect: *different* steps failing against the same key. `agent.go` already
computes `attemptNum` and has `retryPolicy.MaxAttempts` in scope from Phase
7's wiring, so identifying "this is the terminal attempt" requires no new
state — it's the same `willRetry` condition Phase 7 already computes to
decide whether to emit a `"retrying"` event.

A quarantine-blocked step (the existing early-return before `execStep` even
runs) is never recorded at all — a security-control block isn't evidence
the underlying domain or technique is broken, so it should neither open nor
reset any breaker.

### `skip:` integration with the orchestrator's existing `SKIPPED` verdict

When `anyOpen` blocks a step, the closure writes a synthetic result whose
`Stdout` begins with `skip:` — the orchestrator's already-existing
`OutcomeSkipped` classification (`orchestrator/internal/scenario/outcome.go:254`)
picks this up automatically, with no orchestrator-side change:

```go
Run: func(ctx context.Context) bool {
	if cb.anyOpen(breakerKeys) {
		results[i] = protocol.ExecResult{
			TaskID:     step.TaskID,
			ExitCode:   -1,
			Stdout:     fmt.Sprintf("skip: circuit breaker open for %s", strings.Join(breakerKeys, ", ")),
			ExecutedAt: time.Now(),
		}
		ran[i] = true
		emit(RunEvent{Type: "completed", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
			Payload: map[string]any{"verdict": "skipped", "reason": "circuit_open"}})
		return false
	}
	atomic.AddInt64(&startedJobs, 1)
	defer atomic.AddInt64(&finishedJobs, 1)
	// ... unchanged from Phase 7 ...
```

This check is the closure's very first statement — before the
`startedJobs`/`completed`/`finishedJobs` counters increment and before the
`"started"` event — so a breaker-skipped step never inflates progress
counters or logs a confusing "started" immediately followed by "skipped."

### `runScenario` wiring (`agent.go`)

At Job-construction time, alongside the existing `risk`/`retryPolicy`
computation:

```go
breakerKeys := breakerKeysForStep(step.TechniqueID, step.Resource)
```

`cb := newCircuitBreaker(circuitBreakerThreshold)` is constructed once per
run, alongside `limiter`/`riskGate` — the same per-run lifecycle already
established.

At the terminal-attempt point, replacing the existing `retry`/`attemptNum`
block:

```go
retry := isRetryableResult(r)
attemptNum := atomic.AddInt32(&attemptCounters[i], 1)
willRetry := retry && int(attemptNum) < retryPolicy.MaxAttempts
if willRetry {
	log.Printf("[*]   [%d/%d] %s will retry (attempt %d/%d)", i+1, total, step.TechniqueID, attemptNum, retryPolicy.MaxAttempts)
	emit(RunEvent{Type: "retrying", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
		Payload: map[string]any{"attempt": int(attemptNum), "maxAttempts": retryPolicy.MaxAttempts}})
} else {
	cb.recordAll(breakerKeys, !retry) // terminal outcome: success iff not retryable (pass, or a non-retryable block)
}
return retry
```

## Non-goals / out of scope

- **No persistence across runs** — `circuitBreaker` is constructed fresh
  inside `runScenario`, discarded when it returns, exactly like
  `ConcurrencyLimiter`/`RiskGate`. A breaker opened due to a bad run
  self-heals for the next run with no staleness risk and no reset/expiry
  policy to design.
- **No risk-scaled thresholds** — one fixed `circuitBreakerThreshold` shared
  by both the technique and domain keyspaces.
- **No cooldown timer or half-open probe within a run** — the rejected
  Approach B. Per-run scope already provides the reset property a
  within-run cooldown would otherwise need a timer for, and there is no
  evidence (staging still unreachable) that mid-run recovery is a real
  pattern worth the added state-machine complexity.
- **No changes to `agent/sched`** — this lives entirely in `package main`.
  `scheduler.go`, `ConcurrencyLimiter`, `RiskGate`, and `LockManager` are
  all untouched.
- **No changes to `eventForResult` or `isRetryableResult`** — those keep
  classifying step outcomes exactly as Phase 7 left them; the breaker skip
  path bypasses them entirely (same pattern the existing quarantine
  early-return already uses).
- **Does not fix** the Phase 7 progress-counter double-counting bug
  identified during this design pass — flagged for its own separate,
  bounded fix, not addressed here.

## Testing

`agent/circuitbreaker_test.go` (package `main`):

1. **`TestCircuitBreaker_OpensAfterConsecutiveFailures`** —
   `circuitBreakerThreshold-1` failures leave a key's breaker closed; the
   next failure opens it.
2. **`TestCircuitBreaker_SuccessResetsConsecutiveCount`** — some failures,
   then a success, then failures again all need the full threshold from
   scratch — proves a success genuinely resets the counter, not merely
   decrements it.
3. **`TestCircuitBreaker_KeysAreIndependent`** — tripping key A's breaker
   leaves key B closed.
4. **`TestCircuitBreaker_AnyOpenBlocksIfAnyKeyOpen`** — `anyOpen` returns
   true when even one of several keys is open, false when none are.
5. **`TestBreakerKeysForStep`** — table test: nil `ResourceProfile` → just
   the technique key; a profile with 2 declared domains → technique key
   plus 2 domain keys; a profile with an empty `Domains` slice → just the
   technique key.

Wiring into `runScenario` gets no new integration test — same precedent
Phase 7 established for its own wiring (proven at the unit level above;
`go build`/full existing regression is the check), since `runScenario` has
no existing test harness at that granularity to extend.

## Success criteria

1. `TestCircuitBreaker_OpensAfterConsecutiveFailures` and
   `TestCircuitBreaker_SuccessResetsConsecutiveCount` pass, proving the
   core trip/reset semantics.
2. `TestCircuitBreaker_KeysAreIndependent` passes, proving no cross-key
   interference.
3. `TestBreakerKeysForStep` passes for all three declared cases (nil
   profile, populated domains, empty domains).
4. Every existing `agent` and `agent/sched` test continues to pass
   unmodified after wiring — no change to `scheduler.go`, `eventForResult`,
   or `isRetryableResult`.
5. A circuit-breaker-skipped step's synthetic result, once round-tripped
   through the orchestrator's existing `classifyExecution`
   (`orchestrator/internal/scenario/outcome.go`), classifies as
   `OutcomeSkipped` with no orchestrator-side code change.
