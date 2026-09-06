# Phase 8: Circuit Breaker for Correlated Step Failures Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop attempting new work against a technique or resource domain once it's shown 3 consecutive terminal-outcome failures this run, without touching `agent/sched` at all.

**Architecture:** A `circuitBreaker` (new, `agent/circuitbreaker.go`, package `main`) tracks consecutive failures per key (`"technique:<id>"`, `"domain:<name>"`). One instance is constructed fresh per `runScenario` call, alongside `limiter`/`riskGate`. The check and the recording both live entirely inside `agent.go`'s existing `Job.Run` closure — no `sched` changes.

**Tech Stack:** Go (agent module), standard library only (`sync`, `strings`, `fmt`) — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-07-phase8-circuit-breaker-design.md`

## Global Constraints

- No changes to `agent/sched` at all — `scheduler.go`, `ConcurrencyLimiter`, `RiskGate`, `LockManager` stay untouched.
- No changes to `eventForResult` or `isRetryableResult`.
- `circuitBreaker` is per-run scoped (constructed fresh in `runScenario`, discarded when it returns) — no persistence, no cooldown timer, no half-open probe.
- One fixed `circuitBreakerThreshold = 3` shared by both the technique and domain keyspaces (no risk-based scaling).
- A breaker-skipped step's result must begin with `skip:` in `Stdout`, matching the orchestrator's existing `OutcomeSkipped` convention (`orchestrator/internal/scenario/outcome.go:254`) — no orchestrator-side change needed or planned.
- `-race` is unavailable on this Windows build host (`CGO_ENABLED=0`, no `gcc` in `PATH`) — verify without it, consistent with every prior phase this session.
- One commit per task.

## Important: the spec's wiring snippet is stale

The spec (`docs/superpowers/specs/2026-09-07-phase8-circuit-breaker-design.md`) was written before a separate bug fix (commit `c5f79b7`, "stop retrying steps inflating progress/gauge counters") landed on `main`. That fix renamed the terminal-decision variable from `retry`/`return retry` to `willRetry`/`return willRetry` and added a `firstAttempt`-gated block (`atomic.LoadInt32(&attemptCounters[i]) == 0`) at the top of the closure. Task 2 below targets the **current** code, not the spec's snippet.

It also refines the spec's stated breaker-check placement ("the closure's very first statement"). Re-examining against the current code: placing the check *before* the `firstAttempt`/`startedJobs`/`defer`/`completed` block would mean a breaker-skipped step never registers as `started`, but its `defer` (which increments `finishedJobs`) would also never be registered — so it would never count as `finished` either. In isolation that's self-consistent, but it diverges from how the *existing* quarantine early-return already behaves: quarantine's check sits *after* that same bookkeeping block, so a quarantined step **does** count as started-then-finished, exactly like a step that actually ran. To keep the breaker-skip consistent with that established precedent (not invent a second, different accounting rule), Task 2 places the breaker check **after** the counter/defer setup and the `"started"` event, in the same structural position as the quarantine check — not before it, as the spec's prose suggested.

---

### Task 1: `circuitBreaker` type and key derivation

Fully self-contained — no `agent.go` changes in this task, no interaction with the `Job.Run` closure at all.

**Files:**
- Create: `agent/circuitbreaker.go`
- Test: `agent/circuitbreaker_test.go`

**Interfaces:**
- Consumes: `sched.ResourceProfile` (existing, from `agent/sched/profile.go`).
- Produces: `circuitBreaker` type with `newCircuitBreaker(threshold int) *circuitBreaker`, `(*circuitBreaker).isOpen(key string) bool`, `(*circuitBreaker).anyOpen(keys []string) bool`, `(*circuitBreaker).recordOutcome(key string, success bool)`, `(*circuitBreaker).recordAll(keys []string, success bool)`; `circuitBreakerThreshold` constant; `breakerKeysForStep(techniqueID string, p *sched.ResourceProfile) []string` — all consumed by Task 2.

- [ ] **Step 1: Write the failing tests**

Create `agent/circuitbreaker_test.go`:

```go
package main

import (
	"testing"

	"audspect/agent/sched"
)

func TestCircuitBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
	b := newCircuitBreaker(3)
	if b.isOpen("technique:T1055") {
		t.Fatal("breaker should start closed")
	}
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	if b.isOpen("technique:T1055") {
		t.Fatal("breaker should still be closed after only 2 of 3 failures")
	}
	b.recordOutcome("technique:T1055", false)
	if !b.isOpen("technique:T1055") {
		t.Fatal("breaker should be open after 3 consecutive failures")
	}
}

func TestCircuitBreaker_SuccessResetsConsecutiveCount(t *testing.T) {
	b := newCircuitBreaker(3)
	b.recordOutcome("domain:registry", false)
	b.recordOutcome("domain:registry", false)
	b.recordOutcome("domain:registry", true) // resets
	b.recordOutcome("domain:registry", false)
	b.recordOutcome("domain:registry", false)
	if b.isOpen("domain:registry") {
		t.Fatal("breaker should still be closed -- only 2 consecutive failures since the reset")
	}
	b.recordOutcome("domain:registry", false)
	if !b.isOpen("domain:registry") {
		t.Fatal("breaker should be open after 3 consecutive failures since the reset")
	}
}

func TestCircuitBreaker_KeysAreIndependent(t *testing.T) {
	b := newCircuitBreaker(3)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	if !b.isOpen("technique:T1055") {
		t.Fatal("technique:T1055 should be open")
	}
	if b.isOpen("domain:registry") {
		t.Fatal("domain:registry should be unaffected by technique:T1055's failures")
	}
}

func TestCircuitBreaker_AnyOpenBlocksIfAnyKeyOpen(t *testing.T) {
	b := newCircuitBreaker(3)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	b.recordOutcome("technique:T1055", false)
	if !b.anyOpen([]string{"domain:registry", "technique:T1055", "domain:filesystem"}) {
		t.Fatal("anyOpen should be true -- technique:T1055 is open even though the others aren't")
	}
	if b.anyOpen([]string{"domain:registry", "domain:filesystem"}) {
		t.Fatal("anyOpen should be false -- neither of these keys is open")
	}
}

func TestBreakerKeysForStep(t *testing.T) {
	cases := []struct {
		name string
		id   string
		p    *sched.ResourceProfile
		want []string
	}{
		{"nil profile", "T1055", nil, []string{"technique:T1055"}},
		{"empty domains", "T1055", &sched.ResourceProfile{}, []string{"technique:T1055"}},
		{"two domains", "T1055", &sched.ResourceProfile{Domains: []sched.ResourceLock{{Domain: "registry"}, {Domain: "filesystem"}}},
			[]string{"technique:T1055", "domain:registry", "domain:filesystem"}},
	}
	for _, c := range cases {
		got := breakerKeysForStep(c.id, c.p)
		if len(got) != len(c.want) {
			t.Fatalf("%s: breakerKeysForStep() = %v, want %v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: breakerKeysForStep() = %v, want %v", c.name, got, c.want)
			}
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd agent && go test ./... -run 'TestCircuitBreaker|TestBreakerKeysForStep' -v`

Expected: compile failure — `newCircuitBreaker`, `breakerKeysForStep`, etc. undefined.

- [ ] **Step 3: Write `agent/circuitbreaker.go`**

```go
package main

import "sync"

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
// it.
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

// anyOpen reports whether any of keys' breakers is currently tripped --
// blocking a step if even one of the domains/technique it touches is known
// broken this run, the same conservative default already used for locking.
func (b *circuitBreaker) anyOpen(keys []string) bool {
	for _, k := range keys {
		if b.isOpen(k) {
			return true
		}
	}
	return false
}

// recordOutcome updates key's consecutive-failure count from a Job's
// terminal outcome (never called per individual retry attempt -- only once
// a step's own Phase 7 retry sequence is genuinely done). success resets
// the count to 0; a failure increments it and opens the breaker once it
// reaches threshold.
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

// recordAll records the same terminal outcome against every one of keys.
func (b *circuitBreaker) recordAll(keys []string, success bool) {
	for _, k := range keys {
		b.recordOutcome(k, success)
	}
}

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

- [ ] **Step 4: Run to verify it passes**

Run the same command as Step 2. Expected: PASS, all 5 tests.

- [ ] **Step 5: Run the full agent package suite**

Run: `go test ./... -v` (from `agent/`)

Expected: PASS, no regressions — this is a new, self-contained file with no existing call sites yet.

- [ ] **Step 6: Commit**

```bash
git add agent/circuitbreaker.go agent/circuitbreaker_test.go
git commit -m "$(cat <<'EOF'
feat(agent): circuitBreaker type and key derivation

Tracks consecutive terminal-outcome failures per key (technique or
resource domain), opening once a key hits circuitBreakerThreshold (3)
consecutive failures, resetting on any success. Self-contained --
no wiring into runScenario yet.

Spec: docs/superpowers/specs/2026-09-07-phase8-circuit-breaker-design.md

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y
EOF
)"
git push
```

---

### Task 2: Wire the breaker into `runScenario`

**Files:**
- Modify: `agent/agent.go`

**Interfaces:**
- Consumes: `newCircuitBreaker`, `breakerKeysForStep`, `circuitBreakerThreshold`, `(*circuitBreaker).anyOpen`, `(*circuitBreaker).recordAll` (Task 1).
- Produces: nothing further tasks depend on (this is the wiring, a leaf).

- [ ] **Step 1: Construct `cb` alongside `limiter`/`riskGate`**

In `agent/agent.go`, find where `limiter := sched.NewConcurrencyLimiter(workers)` and `riskGate := sched.NewRiskGate()` are constructed (inside `runScenario`, shortly before `sched.Run(...)` is called). Add immediately after:

```go
cb := newCircuitBreaker(circuitBreakerThreshold)
```

- [ ] **Step 2: Compute `breakerKeys` at Job-construction time**

In the `for i := range steps` loop, immediately after the existing:

```go
risk := sched.EffectiveRisk(step.Resource)
retryPolicy := retryPolicyForRisk(risk)
```

add:

```go
breakerKeys := breakerKeysForStep(step.TechniqueID, step.Resource)
```

- [ ] **Step 3: Insert the breaker check after the `"started"` event**

In the `Run:` closure, the current code (after the bug-fix commit `c5f79b7`) reads:

```go
				emit(RunEvent{Type: "started", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name})

				// Stage payloads into a per-step subdir so concurrent steps never
				// collide on BAS_PAYLOAD_DIR. Steps without payloads use the run dir.
				stepDir := payloadDir
```

Change it to:

```go
				emit(RunEvent{Type: "started", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name})

				if cb.anyOpen(breakerKeys) {
					log.Printf("[!]   [%d/%d] %s skipped -- circuit breaker open for %s", i+1, total, step.TechniqueID, strings.Join(breakerKeys, ", "))
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

				// Stage payloads into a per-step subdir so concurrent steps never
				// collide on BAS_PAYLOAD_DIR. Steps without payloads use the run dir.
				stepDir := payloadDir
```

This placement is deliberate (see the plan header's "Important" note): it comes *after* the `firstAttempt`/`startedJobs`/`completed`/`defer` bookkeeping block, so a breaker-skipped step counts as started-then-finished exactly like the existing quarantine early-return a few lines below it — no new, second accounting rule. `willRetry` stays at its zero-value `false` here (never assigned before this `return false`), which is exactly what makes the already-registered `defer func() { if !willRetry { atomic.AddInt64(&finishedJobs, 1) } }()` fire correctly for this path too.

- [ ] **Step 4: Record the terminal outcome**

The current terminal-decision block reads:

```go
				retry := isRetryableResult(r)
				attemptNum := atomic.AddInt32(&attemptCounters[i], 1)
				willRetry = retry && int(attemptNum) < retryPolicy.MaxAttempts
				if willRetry {
					log.Printf("[*]   [%d/%d] %s will retry (attempt %d/%d)", i+1, total, step.TechniqueID, attemptNum, retryPolicy.MaxAttempts)
					emit(RunEvent{Type: "retrying", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
						Payload: map[string]any{"attempt": int(attemptNum), "maxAttempts": retryPolicy.MaxAttempts}})
				}
				return willRetry
			},
```

Change the `if willRetry { ... }` to an `if`/`else`:

```go
				retry := isRetryableResult(r)
				attemptNum := atomic.AddInt32(&attemptCounters[i], 1)
				willRetry = retry && int(attemptNum) < retryPolicy.MaxAttempts
				if willRetry {
					log.Printf("[*]   [%d/%d] %s will retry (attempt %d/%d)", i+1, total, step.TechniqueID, attemptNum, retryPolicy.MaxAttempts)
					emit(RunEvent{Type: "retrying", TaskID: step.TaskID, TechniqueID: step.TechniqueID, StepName: step.Name,
						Payload: map[string]any{"attempt": int(attemptNum), "maxAttempts": retryPolicy.MaxAttempts}})
				} else {
					// Terminal outcome for this step (success, or its own retry
					// budget exhausted): record it against every key it touched.
					// success iff not retryable -- a genuine pass, or a
					// non-retryable block encountered mid-execution (as opposed to
					// the pre-execution quarantine early-return above, which is
					// never recorded at all -- a security-control block is not
					// evidence the underlying domain/technique is broken).
					cb.recordAll(breakerKeys, !retry)
				}
				return willRetry
			},
```

- [ ] **Step 5: Build and run the full agent module test suite**

Run: `cd agent && go build ./... && go test ./... -count=1 -v`

Expected: builds clean, all tests pass. No new test is added in this task beyond Task 1's — per the spec's own Non-goals, `runScenario` has no existing test harness at this granularity to extend, matching the precedent Phase 7 already established for its own wiring step.

- [ ] **Step 6: Commit**

```bash
git add agent/agent.go
git commit -m "$(cat <<'EOF'
feat(agent): wire circuit breaker into runScenario

A step is skipped (skip:-prefixed result, picked up by the
orchestrator's existing OutcomeSkipped classification with no
orchestrator change) when any of its technique/domain keys' breakers
are open. The check sits after the started-bookkeeping block, in the
same structural position as the existing payload-quarantine check, so
a skipped step counts as started-then-finished exactly like every
other terminal outcome -- no new accounting rule. Recording happens
only at a step's terminal outcome (success, or Phase 7's own retry
budget exhausted), never per individual retry attempt, so one step's
bounded retries can't trip a breaker meant to correlate across
different steps.

Spec: docs/superpowers/specs/2026-09-07-phase8-circuit-breaker-design.md

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y
EOF
)"
git push
```

## Final Verification

1. `go test ./agent/... -count=1` passes with 0 failures.
2. `git log --oneline -1 main` == `git log --oneline -1 origin/main`.
3. `git status --porcelain -- agent/ docs/` is empty.
4. Every Non-goal from the spec remains true: no changes to `agent/sched`, `eventForResult`, or `isRetryableResult`; `circuitBreaker` has no persistence/cooldown/half-open logic; one fixed threshold for both keyspaces.
