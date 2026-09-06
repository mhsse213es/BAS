# Phase 5: Risk-Aware Adaptive Admission — Design

**Goal**

Make the scheduler's admission decision sensitive to *what kind* of work a job is, not just
*how much* work is running. Today's ceiling (Phase 4, `ceilingForLevel`) throttles every job
uniformly under host pressure — a read-only registry query counts the same against the limit as a
step that mutates persistence. Phase 5 adds a second, orthogonal admission gate that defers
state-changing work (`modification`/`persistence` risk) under `High`/`Critical` pressure while still
admitting read-only (`observation`) work immediately — favoring observational work over
state-changing work when the endpoint is under load, without claiming to know each technique's
actual CPU/memory cost.

**Relationship to Phases 1-4** (all shipped, all on `main`): Phase 3 (`3c8d2fc`) built
`sched.ConcurrencyLimiter`, a pure counting semaphore agnostic to which job is asking. Phase 4
(`40e8e10`) built `agent/pressure` (EWMA + 3-state hysteresis: `Normal`/`High`/`Critical`) and wired
its output to `ConcurrencyLimiter.SetLimit` via `agent/pressure_loop.go`'s `pressureTick`. Phase 5
adds a second, independent gate alongside the limiter — same worker-loop insertion point, same
cond-variable mechanism, no changes to either Phase 3 or Phase 4's already-shipped code.

## Context: what exists today, confirmed against real code

**The originally-conceived version of this phase — `CPUWeight`/`MemoryWeight` fields on
`ResourceProfile`, populated per-technique — is not viable today, and this design deliberately does
not pursue it.** `agent/sched/profile.go`'s `ResourceProfile` has no cost fields at all
(`Reads`/`Writes`/`Domains`/`Scope`/`Risk`/`ObservesFootprint` only — all correctness-oriented, none
performance-oriented). The server-side authoring precedent
(`orchestrator/internal/scenario/resource.go`, `discoveryProfiles`/`timeoutOverrides`) shows this
project's real bar for curating a per-technique numeric attribute: `timeoutOverrides`' entries are
each backed by a specific staging `StepTermination` timestamp, not intuition, and the doc comments
explicitly narrate the evidence trail (e.g. "T1018 ... staging run 2026-09-04 recorded a real
termination at 20,011ms"). No telemetry anywhere in this codebase attributes CPU or memory cost to a
specific `TechniqueID` — Phase 2's `sched_*` metrics are run-level aggregates, Phase 4's
`host_cpu_percent` is whole-host. Authoring `CPUWeight`/`MemoryWeight` now would mean guessing,
which this project's own established discipline explicitly rejects. Confirmed with this design's
stakeholder: do not add these fields, do not populate placeholder values. If real per-technique cost
telemetry is ever built (a plausible future increment, informally "Phase 6/7"), granular
weight-based admission becomes a natural follow-on to *this* design, not a replacement for it.

**Where the decision plugs into the existing worker loop**, confirmed by reading
`agent/sched/scheduler.go`'s `Run` directly: the per-job `Job` value (including `j.Resource`) is
already in scope at the exact point the worker calls `cfg.limiter.Acquire(ctx)` (inside the
`if cfg.limiter != nil { ... }` block). A second gate can sit at that same point, checked either
before or after the existing limiter, without touching `ConcurrencyLimiter` itself.

**`ConcurrencyLimiter`'s shape is the template to reuse, not extend.** `agent/sched/limiter.go`'s
`Acquire`/`Release`/`SetLimit` pattern (`sync.Cond`-based, a bridge goroutine rebroadcasting on
`ctx.Done()` because `sync.Cond.Wait` isn't itself cancellable) is proven and already has 8 passing
tests. Rather than changing `Acquire`'s signature to accept a per-job weight (which would be a
breaking change to already-shipped, already-tested Phase 3 code, and would need `ConcurrencyLimiter`
to track per-dimension sub-capacity state it has no business knowing about), Phase 5 introduces a
**new, independent type with the identical mechanism** applied to a different question: not "how
many jobs" but "is this kind of job allowed right now."

**Wire format is a non-issue.** `protocol.ScenarioStep.Resource` is already `json.RawMessage`
(`agent/protocol/messages.go:82`), decoded via a bare `json.Unmarshal(w.Resource, &rp)` in
`agent.go:512`. This design adds no new fields to `ResourceProfile` at all (see above), so there is
no wire-format change in this phase — `Risk` already exists and is already sent today.

**No curated profile currently uses the `Reads`/`Writes` per-atomic form.** Verified by reading
`discoveryProfiles` in full: every entry is built via `observe()`/`observeFootprint()`, which only
ever populate `Domains`/`Scope`/`Risk` (the "per-technique form"). This matters because a
`Reads`/`Writes`-populated profile leaves `Risk` empty per that struct's own doc comment ("When
either is non-empty they take precedence and Domains/Scope/Risk are ignored") — so today, "empty
Risk" in practice means exactly one thing: **no curated profile exists for this step at all**, not
"a Reads/Writes profile chose not to set Risk." The unknown-risk handling below is designed for that
reality, not a hypothetical mixed case.

## Architecture

```
Existing (Phase 3/4, unchanged):
  queue_wait measured -> ctx check -> pause gate.Wait -> ctx check
      -> ConcurrencyLimiter.Acquire -> runJob (locks + execute) -> Release

New (Phase 5), inserted between the pause gate and ConcurrencyLimiter.Acquire:
      -> ctx check -> RiskGate.Allow(ctx, effectiveRisk(j.Resource)) -> ctx check
      -> ConcurrencyLimiter.Acquire -> ...

                (agent lifetime, same ticker as Phase 4's pressure loop)
                              │
                    pressure.Controller.Observe(...)
                              │
                            Level
                    ┌─────────┴─────────┐
                    ▼                   ▼
         ceilingForLevel(level)   riskAllowedForLevel(level, risk)
                    │                   │
      a.activeLimiter.SetLimit(...)   a.activeRiskGate.SetPolicy(...)
                    │                   │
                    ▼                   ▼
           sched.ConcurrencyLimiter   sched.RiskGate
              (Phase 3, unchanged)     (Phase 5, new)
```

The two gates are independent and composable: `ceilingForLevel` controls *how much* concurrent work
runs; `riskAllowedForLevel` controls *which* work is eligible to run at all right now. Both are pure
functions of the same `pressure.Level`, computed in the same tick, applied to two separate
mechanisms that neither know about the other.

## Components

### 1. `sched.RiskGate` (`agent/sched/riskgate.go`)

```go
package sched

import (
	"context"
	"sync"
)

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
	mu     sync.Mutex
	cond   *sync.Cond
	policy func(risk string) bool
}

// NewRiskGate returns a gate that admits everything until SetPolicy narrows it.
func NewRiskGate() *RiskGate {
	g := &RiskGate{policy: func(string) bool { return true }}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// SetPolicy replaces the admission predicate and wakes every blocked Allow
// call so it can re-evaluate against the new policy immediately.
func (g *RiskGate) SetPolicy(policy func(risk string) bool) {
	if policy == nil {
		policy = func(string) bool { return true }
	}
	g.mu.Lock()
	g.policy = policy
	g.mu.Unlock()
	g.cond.Broadcast()
}

// Allow blocks until the current policy admits risk, or ctx is done.
// Returns false only on ctx cancellation -- identical abort semantics to
// ConcurrencyLimiter.Acquire and AcquireCtx: never a rejection with side
// effects, always treated as a scenario abort by the caller.
func (g *RiskGate) Allow(ctx context.Context, risk string) bool {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			g.mu.Lock()
			g.cond.Broadcast()
			g.mu.Unlock()
		case <-stop:
		}
	}()

	g.mu.Lock()
	defer g.mu.Unlock()
	for !g.policy(risk) {
		if ctx.Err() != nil {
			return false
		}
		g.cond.Wait()
	}
	return true
}
```

### 2. `effectiveRisk` (`agent/sched/riskgate.go`, alongside `RiskGate`)

```go
// RiskUnknown is the effective risk of a job with no curated ResourceProfile
// (nil Resource, or an empty Risk field) -- treated conservatively, the same
// way an unlabeled profile already resolves to an exclusive global lock for
// LOCKING purposes (see resolve() in locks.go). A step nobody has evidenced
// as read-only is not assumed safe to prioritize under pressure either.
const RiskUnknown = "unknown"

// effectiveRisk resolves a job's risk classification for admission purposes.
// A Reads/Writes-populated profile also has no Risk field set today by
// convention (see ResourceProfile's own doc comment) -- no curated profile in
// this codebase currently uses that form, so in practice "empty Risk" means
// "no curated profile exists for this step," which is exactly the
// RiskUnknown case this function returns for.
func effectiveRisk(p *ResourceProfile) string {
	if p == nil || p.Risk == "" {
		return RiskUnknown
	}
	return p.Risk
}
```

### 3. `RunOption` and worker-loop wiring (`agent/sched/scheduler.go`)

```go
// WithRiskGate attaches a RiskGate that must admit a job's effective risk
// classification before it proceeds to lock acquisition. Checked between the
// pause gate and the ConcurrencyLimiter, in that order: an operator pause
// always takes precedence, then risk-based deferral, then raw concurrency
// admission, then lock correctness -- each layer strictly narrows what the
// layer below it ever sees.
func WithRiskGate(g *RiskGate) RunOption {
	return func(c *runConfig) { c.riskGate = g }
}
```

Add `riskGate *RiskGate` to `runConfig`. In `Run`'s worker loop, insert between the existing
`gate.Wait(ctx)` (pause) block and the existing `cfg.limiter != nil` block:

```go
			gate.Wait(ctx) // blocks here while paused; no-op if gate is nil or unpaused
			if ctx.Err() != nil {
				continue // cancel can race with a pause -- re-check before running
			}
			if cfg.riskGate != nil {
				start := time.Now()
				if !cfg.riskGate.Allow(ctx, effectiveRisk(j.Resource)) {
					continue // ctx cancelled while deferred
				}
				if cfg.rec != nil {
					cfg.rec.AdmissionWait(time.Since(start))
				}
			}
			if cfg.limiter != nil {
				// ... existing ConcurrencyLimiter.Acquire block, unchanged ...
```

`cfg.rec.AdmissionWait` records the wait unconditionally (including a near-zero wait when the
policy already admits the job) so the aggregator (Component 5 below) can distinguish "never
deferred" from "deferred, then admitted" by whether the recorded duration is non-trivial — this
mirrors exactly how Phase 2's `QueueWait` is recorded for every job, not only the ones that waited
meaningfully.

### 4. `Recorder.AdmissionWait` (`agent/sched/metrics.go`)

Add one new method to the existing `Recorder` interface, alongside `QueueWait`/`LockWait`/etc:

```go
	// AdmissionWait reports how long a job waited at the risk gate before
	// being admitted (near-zero when the policy already allowed it). Recorded
	// for every job with a non-nil RiskGate configured, whether or not it was
	// ever actually deferred.
	AdmissionWait(d time.Duration)
```

This is an interface change, so every existing `Recorder` implementation must gain the method.
Today there is exactly one: `runMetrics` in `agent/sched_metrics.go` (package main). The fake test
double `fakeRecorder` in `agent/sched/metrics_test.go` needs the same addition.

### 5. `riskAllowedForLevel` and `runMetrics` extension (package main)

`agent/pressure_loop.go`, alongside `ceilingForLevel`:

```go
// riskAllowedForLevel decides whether a job of this risk classification may
// be admitted under the given pressure level. Pure and independently
// testable -- mirrors ceilingForLevel's shape exactly. Normal admits
// everything; High and Critical both defer anything that isn't
// RiskObservation (RiskUnknown included, per effectiveRisk's conservative
// default) -- collapsed to one policy for both non-Normal levels rather than
// giving Critical its own stricter rule, since Phase 4's ceiling (workers/2
// vs 1) already differentiates the two levels along a separate axis, and
// there is no evidence yet that High's risk policy is insufficient at
// Critical.
func riskAllowedForLevel(level pressure.Level, risk string) bool {
	if level == pressure.LevelNormal {
		return true
	}
	return risk == sched.RiskObservation
}
```

`agent/sched_metrics.go`'s `runMetrics` gains the `AdmissionWait` method and three new aggregated
fields (mirroring `queueWaitTotal`/`queueWaitMax`/`queueWaitN`'s exact shape):

```go
	admissionWaitTotal time.Duration
	admissionWaitMax   time.Duration
	admissionWaitN     int64
```

`report()` emits, following the existing threshold-based convention (only emitted when `N > 0`):

- `sched_admission_allowed_count` — count of jobs whose `AdmissionWait` was recorded (i.e. every
  job that passed through a configured `RiskGate`, admitted immediately or after waiting)
- `sched_admission_deferred_count` — count of jobs whose `AdmissionWait` exceeded
  `admissionDeferThreshold = 10 * time.Millisecond` (a named constant, not a bare magic number,
  matching this codebase's established style — see `defaultGraceSec`/`waitDelaySlackSec` in
  `agent/executor.go`)
- `sched_admission_defer_wait_avg_ms` / `sched_admission_defer_wait_max_ms` — averaged/maxed only
  over the deferred subset (jobs above the threshold), not diluted by the many jobs that were
  admitted instantly

### 6. Lifecycle wiring (`agent/agent.go`, `agent/pressure_loop.go`)

Exactly mirrors Phase 4's `activeLimiter`/`activeWorkers` addition:

- `Agent` struct: add `activeRiskGate *sched.RiskGate`, guarded by the same `scenarioMu`.
- `runScenario`: alongside `limiter := sched.NewConcurrencyLimiter(workers)`, add
  `riskGate := sched.NewRiskGate()`; set `a.activeRiskGate = riskGate` in the same
  `scenarioMu`-guarded block that sets `a.activeLimiter`; pass `sched.WithRiskGate(riskGate)` to
  `sched.Run(...)` alongside the existing `sched.WithRecorder`/`sched.WithConcurrencyLimiter`
  options; clear `a.activeRiskGate = nil` in the same deferred cleanup block that clears
  `a.activeLimiter`.
- `pressureLoopTick` (`agent/pressure_loop.go`): today reads `a.activeLimiter`/`a.activeWorkers`
  under `a.scenarioMu`, unlocks, then calls `pressureTick(...)` to get `level` (its second return
  value, the ceiling, is already discarded via `_` and stays that way). Add `a.activeRiskGate` to
  the same lock/unlock pair, and call `SetPolicy` after `level` is known — the exact edit is:

```go
	a.scenarioMu.Lock()
	limiter := a.activeLimiter
	workers := a.activeWorkers
	riskGate := a.activeRiskGate
	a.scenarioMu.Unlock()
	if workers == 0 {
		workers = sched.DefaultWorkers()
	}

	level, _ := pressureTick(ctrl, limiter, workers, hostCPU, hostMem)
	if riskGate != nil {
		riskGate.SetPolicy(func(risk string) bool { return riskAllowedForLevel(level, risk) })
	}
```

  (i.e. one new line in the existing lock block, and a 3-line addition right after the existing
  `pressureTick` call -- nothing else in this function changes).

## Explicitly out of scope for this phase

- **`CPUWeight`/`MemoryWeight` fields on `ResourceProfile`** — no fields added, no placeholder
  values populated (see "Context" above). Deferred until real per-technique cost telemetry exists.
- **A stricter, distinct policy for `LevelCritical`** — collapsed to `LevelHigh`'s policy in this
  phase (see Component 5's rationale). Revisit only if field evidence shows High's policy
  insufficient at Critical.
- **Priority-based reordering or aging** — a deferred job simply keeps re-checking the same policy
  via `Allow`'s blocking loop; there is no queue-position change, no starvation-prevention aging
  mechanism, and no cross-job ordering guarantee beyond what already exists (submission-order
  dispatch to the worker channel). This is the separate, not-yet-brainstormed "Phase 6" from the
  original architecture discussion.
- **Per-risk-labeled telemetry breakdown** (e.g. a `sched_admission_deferred_persistence_count`
  distinct from `..._modification_count`) — the existing `agent_telemetry` schema is a flat
  `(metric, value, unit)` triple with no label dimension; a labeled breakdown would need a bigger,
  unwarranted schema change for this phase. The 3 metrics in Component 5 are enough to know whether
  the mechanism is doing anything at all, which is this phase's actual evidentiary goal.
- **Dashboard visualization of the 3 new metrics** — same reasoning and same deferred-follow-up
  shape as Phase 4's telemetry additions.

## Testing strategy

- **`sched.RiskGate`**: mirrors `ConcurrencyLimiter`'s existing test suite shape exactly (Phase 3
  precedent). Required cases: `Allow` returns immediately true under the default (admit-everything)
  policy; `Allow` blocks when the policy rejects the risk, and unblocks the instant `SetPolicy`
  changes to one that admits it; `Allow` returns false promptly on `ctx` cancellation while blocked,
  without ever calling the policy again afterward; `SetPolicy` with a `nil` policy resets to
  admit-everything (documented fallback, not a panic).
- **`effectiveRisk`**: table-driven — nil profile → `RiskUnknown`; empty-`Risk` profile →
  `RiskUnknown`; a profile with `Risk: "observation"` → `"observation"` unchanged; same for
  `"modification"`/`"persistence"`.
- **`riskAllowedForLevel`**: table-driven, mirroring `ceilingForLevel`'s existing test shape —
  `LevelNormal` admits every risk string including `RiskUnknown`; `LevelHigh` and `LevelCritical`
  both admit only `RiskObservation`, rejecting `RiskModification`/`RiskPersistence`/`RiskUnknown`.
- **`sched.Run` integration**: a new test alongside the existing
  `TestRun_ConcurrencyLimiterCapsBelowWorkerCount`-style tests in `sched_test.go` — a job with
  `Risk: RiskModification` under a `RiskGate` whose policy currently rejects modification must not
  start running (proven via the same `tracker`/`enter`/`leave` idiom already used for concurrency
  tests) until `SetPolicy` is changed to admit it, at which point it proceeds normally through the
  existing lock/timeout machinery unchanged.
- **`runMetrics.AdmissionWait`/`report`**: extends the existing `sched_metrics_test.go` table-driven
  style — recording a mix of near-zero and above-threshold `AdmissionWait` calls produces the
  correct `allowed`/`deferred` counts and correctly excludes the non-deferred majority from the
  avg/max calculation.
- **Wiring** (`activeRiskGate`, `pressureLoopTick`): same shape as Phase 4's
  `TestPressureTick_UpdatesLimiterWhenPresent`/`_NilLimiterIsSafe` — a real `sched.RiskGate` fed a
  `LevelHigh` result must reject a modification-risk job's `Allow` call; a nil `activeRiskGate` must
  never panic.
