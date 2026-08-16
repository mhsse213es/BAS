# Pause/Resume for Live Scenario Runs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Pause/Resume control to the Live Runs table, alongside the existing Stop button, for live-mode (telemetry/lab) scenario runs.

**Architecture:** A new `sched.Gate` lets the agent's worker-pool scheduler hold new steps between jobs (never mid-job) while a run is paused. Pause/Resume commands travel the same REST→WS path Stop already uses; confirmation that a pause/resume actually took effect flows back through the *existing* run-event pipeline (`SubmitRunEvents`/`relayRunEvents`) as new `paused`/`resumed` event types, landing in a new `scenario_runs.paused` boolean column. `status` never changes — a paused run is still `status='running'`, so the busy-guard and every other existing status check needs zero changes.

**Tech Stack:** Go (agent + orchestrator server, `internal/api`, `agent/sched`), Postgres, vanilla JS frontend (`wwwroot/index.html`), WebSocket for agent↔server command/event transport.

**Spec:** `docs/superpowers/specs/2026-08-16-pause-resume-live-runs-design.md` — read it alongside this plan; the plan argues from it and doesn't repeat its rationale sections (Non-Goals, scope decisions) in full.

## Global Constraints

- Pause semantics: finish the currently-executing step(s), then hold before starting the next. Never suspend/kill a step mid-execution.
- State representation: `scenario_runs.status` is untouched (`running` throughout a pause) — only a new `paused boolean` column changes.
- Pause/Resume applies only to live-mode (`telemetry`/`lab`) runs. Posture-mode runs never show the button (gate on `mode !== 'posture'` in the frontend — see spec's Non-Goals for the precise rationale).
- No new grace-period force-timer server-side (unlike Stop's `forceCancelAfterGracePeriod`) — an unconfirmed pause is harmless, the run just keeps running.
- Reuse the existing `auth.CanCancelScenarioRun` permission — no new permission tier.
- `Pause`/`Resume` must be idempotent at every layer (agent `Gate`, agent methods, REST handlers) — the operator's click is always forwarded as-is, no pre-check of current state required before sending.
- Every Go file touched must be `gofmt`-clean and pass `go vet` before its task's commit.
- Every frontend edit must pass `node --check` on the extracted `<script>` block before its task's commit (script: read `orchestrator/wwwroot/index.html`, regex-extract all `<script>...</script>` bodies, concatenate, write to the scratchpad dir, run `node --check` on it).
- Run the full `internal/api` suite with `go test ./internal/api/... -timeout 25m` (not the default 10-minute timeout — this package's real runtime is ~10-15 minutes and the default timeout produces a false-alarm failure) via `Bash` `run_in_background: true`, and read the actual log file after the completion notification — never trust a piped/truncated capture.
- Commit after each task (or a small logically-complete group), with a message explaining the root cause/purpose, not just "what changed". Push after committing.

---

### Task 1: `sched.Gate` — pause primitive

**Files:**
- Create: `agent/sched/gate.go`
- Test: `agent/sched/gate_test.go`

**Interfaces:**
- Produces: `type Gate struct{...}`, `func NewGate() *Gate`, `func (g *Gate) Pause()`, `func (g *Gate) Resume()`, `func (g *Gate) IsPaused() bool`, `func (g *Gate) Wait(ctx context.Context)` — a nil `*Gate` receiver on `Wait` is a safe, immediate no-op (needed so `sched.Run`'s existing 9 call sites in `sched_test.go` can pass `nil` in Task 2 without behavior change).

- [ ] **Step 1: Write the failing tests**

```go
// agent/sched/gate_test.go
package sched

import (
	"context"
	"testing"
	"time"
)

func TestGate_WaitBlocksWhilePausedThenUnblocksOnResume(t *testing.T) {
	g := NewGate()
	g.Pause()
	done := make(chan struct{})
	go func() { g.Wait(context.Background()); close(done) }()

	select {
	case <-done:
		t.Fatal("Wait returned while paused")
	case <-time.After(50 * time.Millisecond):
	}

	g.Resume()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Wait did not return after Resume")
	}
}

func TestGate_WaitReturnsImmediatelyWhenNeverPaused(t *testing.T) {
	g := NewGate()
	done := make(chan struct{})
	go func() { g.Wait(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Wait blocked despite Gate never paused")
	}
}

func TestGate_WaitUnblocksOnContextCancelWhilePaused(t *testing.T) {
	g := NewGate()
	g.Pause()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Wait(ctx); close(done) }()

	select {
	case <-done:
		t.Fatal("Wait returned before cancel")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Wait did not return after ctx cancel")
	}
}

func TestGate_PauseAndResumeAreIdempotent(t *testing.T) {
	g := NewGate()
	g.Pause()
	g.Pause() // must not panic or misbehave on a second Pause
	g.Resume()
	g.Resume() // must not panic on a second Resume
	if g.IsPaused() {
		t.Fatal("IsPaused = true after Resume")
	}
}

func TestGate_NilGateWaitIsNoOp(t *testing.T) {
	var g *Gate
	done := make(chan struct{})
	go func() { g.Wait(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("nil Gate.Wait blocked")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent && go test ./sched/... -run TestGate -v`
Expected: FAIL — `gate.go` doesn't exist yet, compile error `undefined: NewGate`.

- [ ] **Step 3: Write the implementation**

```go
// agent/sched/gate.go
package sched

import "sync"
import "context"

// Gate lets a caller pause/resume a Run in progress without touching ctx. A
// paused Gate blocks workers from starting their NEXT job; any job already
// inside its Run func is never interrupted -- it always runs to completion.
// Safe for concurrent use. A nil *Gate is a valid, always-unpaused no-op
// (Wait returns immediately), so sched.Run callers that don't need pause
// support can pass nil.
type Gate struct {
	mu     sync.Mutex
	paused bool
	ch     chan struct{} // closed while NOT paused; replaced with a fresh (open) channel on Pause
}

// NewGate returns a Gate that starts in the unpaused state.
func NewGate() *Gate {
	g := &Gate{ch: make(chan struct{})}
	close(g.ch)
	return g
}

// Pause is idempotent -- pausing an already-paused Gate is a no-op.
func (g *Gate) Pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		return
	}
	g.paused = true
	g.ch = make(chan struct{})
}

// Resume is idempotent -- resuming an already-unpaused Gate is a no-op.
func (g *Gate) Resume() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.paused {
		return
	}
	g.paused = false
	close(g.ch)
}

func (g *Gate) IsPaused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}

// Wait blocks until the Gate is resumed or ctx is done, whichever comes
// first. Returns immediately if the Gate is not currently paused. Safe to
// call on a nil *Gate (returns immediately).
func (g *Gate) Wait(ctx context.Context) {
	if g == nil {
		return
	}
	g.mu.Lock()
	ch := g.ch
	g.mu.Unlock()
	select {
	case <-ch:
	case <-ctx.Done():
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd agent && go test ./sched/... -run TestGate -v`
Expected: PASS (all 5 tests)

- [ ] **Step 5: Format, vet, commit**

```bash
cd agent && gofmt -l sched/gate.go sched/gate_test.go && go vet ./sched/...
git add agent/sched/gate.go agent/sched/gate_test.go
git commit -m "feat(agent): add sched.Gate pause primitive for the step scheduler

Channel-based, nil-safe, idempotent Pause/Resume, and Wait unblocks
immediately on ctx cancellation even while paused -- Stop-while-paused
needs no special-casing once sched.Run wires this in (Task 2).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: Wire `Gate` into `sched.Run`

**Files:**
- Modify: `agent/sched/scheduler.go:35` (`func Run`)
- Modify: `agent/sched/sched_test.go` (9 existing call sites at lines 127, 136, 150, 159, 167, 205, 258, 281, 330)
- Test: `agent/sched/sched_test.go` (new test)

**Interfaces:**
- Consumes: `*Gate` from Task 1 (`NewGate()`, `Pause()`, `Resume()`, `Wait(ctx)`).
- Produces: `func Run(ctx context.Context, workers int, lm *LockManager, jobs []Job, gate *Gate)` — every caller in the repo (there is exactly one production caller, `agent/agent.go:639`, updated in Task 3) must now pass a 5th argument.

- [ ] **Step 1: Update the 9 existing test call sites to pass `nil`**

In `agent/sched/sched_test.go`, append `, nil` as the 5th argument on each of these exact lines (verify line numbers haven't shifted before editing — `grep -n "Run(context\|Run(ctx" agent/sched/sched_test.go`):

```
127:	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr))
136:	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr))
150:	Run(context.Background(), 4, lm, jobs)
159:	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr))
167:	Run(context.Background(), 4, NewLockManager(), makeJobs(4, nil, tr))
205:	go func() { Run(context.Background(), 8, NewLockManager(), jobs); close(doneCh) }()
258:	Run(context.Background(), 2, NewLockManager(), jobs)
281:	Run(context.Background(), 1, lm, []Job{job})
330:	Run(ctx, 1, NewLockManager(), jobs)
```

become (e.g. line 127):

```go
	Run(context.Background(), 4, NewLockManager(), makeJobs(4, p, tr), nil)
```

...and so on for all 9 (line 205's edit is `Run(context.Background(), 8, NewLockManager(), jobs, nil); close(doneCh) }()`).

- [ ] **Step 2: Write the new failing test for Gate integration**

Append to `agent/sched/sched_test.go`:

```go
func TestRun_GateHoldsNewJobsButFinishesInFlight(t *testing.T) {
	gate := NewGate()
	var started, finished int32
	firstStarted := make(chan struct{})
	release := make(chan struct{})

	jobs := []Job{
		{Run: func(ctx context.Context) {
			atomic.AddInt32(&started, 1)
			close(firstStarted)
			<-release // held "in flight" until the test says go
			atomic.AddInt32(&finished, 1)
		}},
		{Run: func(ctx context.Context) {
			atomic.AddInt32(&started, 1)
			atomic.AddInt32(&finished, 1)
		}},
	}

	done := make(chan struct{})
	// workers=1 -- deterministic: only one job can ever be "in flight" at a time.
	go func() { Run(context.Background(), 1, NewLockManager(), jobs, gate); close(done) }()

	<-firstStarted // job 1 is now executing
	gate.Pause()   // pause while job 1 is still in flight
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&started); got != 1 {
		t.Fatalf("started = %d, want 1 (job 2 must not start while paused)", got)
	}

	close(release) // let job 1 finish
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&finished); got != 1 {
		t.Fatalf("finished = %d, want 1 (job 1 finishes even though paused)", got)
	}
	if got := atomic.LoadInt32(&started); got != 1 {
		t.Fatalf("started = %d, want still 1 (job 2 must still be held)", got)
	}

	gate.Resume()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Run did not complete after Resume")
	}
	if s, f := atomic.LoadInt32(&started), atomic.LoadInt32(&finished); s != 2 || f != 2 {
		t.Fatalf("started=%d finished=%d, want 2/2 after Resume", s, f)
	}
}
```

Check the top of `agent/sched/sched_test.go` already imports `sync/atomic` and `time` (used by the existing 9 tests) — if not, add them.

- [ ] **Step 3: Run tests to verify the new test fails and the 9 updated ones fail to compile**

Run: `cd agent && go test ./sched/... -v`
Expected: FAIL — compile error, `Run` still only takes 4 args (scheduler.go not yet updated).

- [ ] **Step 4: Update `Run`'s signature and worker loop**

In `agent/sched/scheduler.go`, change:

```go
func Run(ctx context.Context, workers int, lm *LockManager, jobs []Job) {
```

to:

```go
func Run(ctx context.Context, workers int, lm *LockManager, jobs []Job, gate *Gate) {
```

and inside the worker goroutine loop, change:

```go
			for j := range ch {
				if ctx.Err() != nil {
					continue // cancelled: drain the channel without running
				}
				runJob(ctx, lm, j)
			}
```

to:

```go
			for j := range ch {
				if ctx.Err() != nil {
					continue // cancelled: drain the channel without running
				}
				gate.Wait(ctx) // blocks here while paused; no-op if gate is nil or unpaused
				if ctx.Err() != nil {
					continue // cancel can race with a pause -- re-check before running
				}
				runJob(ctx, lm, j)
			}
```

Also update the doc comment above `Run` to mention the new parameter:

```go
// Run executes jobs across `workers` goroutines, holding each job's resource
// locks for the duration of its Run so that conflicting jobs never overlap.
// Non-conflicting jobs run concurrently. Jobs are dispatched in submission order
// but may start and finish in any order. Run blocks until all jobs complete (or,
// once ctx is cancelled, until in-flight jobs drain — remaining jobs are skipped).
//
// gate, if non-nil, is checked between jobs (never mid-job): while gate is
// paused, a worker that has just pulled its next job off the queue blocks in
// gate.Wait before starting it, so no NEW job starts while paused, but any
// job already running always finishes normally. Pass nil for the original
// (no pause support) behavior.
//
// Deadlock-freedom: a job in the queue holds no locks, so no running job can ever
// wait on a lock held by a not-yet-started job; combined with canonical-order
// acquisition (see resolve/LockManager), the scheduler cannot deadlock.
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd agent && go test ./sched/... -v`
Expected: PASS (all tests, including the 9 pre-existing ones and the new `TestRun_GateHoldsNewJobsButFinishesInFlight`)

- [ ] **Step 6: Format, vet, commit**

```bash
cd agent && gofmt -l sched/scheduler.go sched/sched_test.go && go vet ./sched/...
git add agent/sched/scheduler.go agent/sched/sched_test.go
git commit -m "feat(agent): sched.Run holds new jobs while a Gate is paused

gate.Wait is called between jobs only, never mid-job, so an in-flight
step always finishes even when Pause lands while it's running. nil
gate preserves the exact original behavior (all 9 existing callers
updated to pass nil).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: Agent wiring — `pauseCurrentScenario`/`resumeCurrentScenario`, WS commands

**Files:**
- Modify: `agent/agent.go` (Agent struct ~line 24-35, `cancelCurrentScenario` ~line 278, `runScenario` ~line 426-639, WS command switch ~line 1017)
- Create: `agent/pause_test.go`

**Interfaces:**
- Consumes: `sched.Gate` from Task 1/2 (`sched.NewGate()`, `.Pause()`, `.Resume()`).
- Produces: `func (a *Agent) pauseCurrentScenario() bool`, `func (a *Agent) resumeCurrentScenario() bool` — both usable directly by the server-facing WS command switch and by tests, mirroring `cancelCurrentScenario`'s existing shape exactly.

- [ ] **Step 1: Write the failing tests**

```go
// agent/pause_test.go
package main

import (
	"testing"

	"audspect/agent/sched"
)

func TestPauseCurrentScenario(t *testing.T) {
	a := &Agent{}

	if a.pauseCurrentScenario() {
		t.Error("pauseCurrentScenario with no active run = true, want false")
	}

	gate := sched.NewGate()
	a.pauseGate = gate
	if !a.pauseCurrentScenario() {
		t.Error("pauseCurrentScenario with active run = false, want true")
	}
	if !gate.IsPaused() {
		t.Error("the run's gate was not paused")
	}
}

func TestResumeCurrentScenario(t *testing.T) {
	a := &Agent{}

	if a.resumeCurrentScenario() {
		t.Error("resumeCurrentScenario with no active run = true, want false")
	}

	gate := sched.NewGate()
	gate.Pause()
	a.pauseGate = gate
	if !a.resumeCurrentScenario() {
		t.Error("resumeCurrentScenario with active run = false, want true")
	}
	if gate.IsPaused() {
		t.Error("the run's gate was not resumed")
	}
}

func TestPauseCurrentScenario_EmitsConfirmationEvent(t *testing.T) {
	a := &Agent{pauseGate: sched.NewGate()}
	var got RunEvent
	a.pauseEmit = func(ev RunEvent) { got = ev }
	a.pauseCurrentScenario()
	if got.Type != "paused" {
		t.Errorf("emitted event type = %q, want %q", got.Type, "paused")
	}
}

func TestResumeCurrentScenario_EmitsConfirmationEvent(t *testing.T) {
	gate := sched.NewGate()
	gate.Pause()
	a := &Agent{pauseGate: gate}
	var got RunEvent
	a.pauseEmit = func(ev RunEvent) { got = ev }
	a.resumeCurrentScenario()
	if got.Type != "resumed" {
		t.Errorf("emitted event type = %q, want %q", got.Type, "resumed")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent && go test . -run TestPauseCurrentScenario -v` and `-run TestResumeCurrentScenario`
Expected: FAIL — compile error, `Agent` has no field `pauseGate`/`pauseEmit`, no method `pauseCurrentScenario`.

- [ ] **Step 3: Add the Agent struct fields**

In `agent/agent.go`, next to the existing `cancelScenario`/`scenarioMu` fields (~line 31-32):

```go
	cancelScenario context.CancelFunc
	scenarioMu     sync.Mutex
	// pauseGate and pauseEmit belong to whichever run is currently active
	// through runScenario's scheduler (nil when idle or between runs — see
	// runScenario's defer cleanup, which is why this differs from
	// cancelScenario: calling a stale cancel() again is a harmless no-op,
	// but calling a stale emit() would incorrectly mark an already-finished
	// run as paused).
	pauseGate *sched.Gate
	pauseEmit func(RunEvent)
```

- [ ] **Step 4: Add `pauseCurrentScenario`/`resumeCurrentScenario`**

Right after `cancelCurrentScenario` (~line 286):

```go
// pauseCurrentScenario pauses the in-flight scenario's step scheduler, if
// any. Already-executing step(s) always finish -- only the next step(s) a
// worker would otherwise start are held. Returns true if a run was active to
// pause. Idempotent: pausing an already-paused run is a harmless no-op.
func (a *Agent) pauseCurrentScenario() bool {
	a.scenarioMu.Lock()
	defer a.scenarioMu.Unlock()
	if a.pauseGate == nil {
		return false
	}
	a.pauseGate.Pause()
	if a.pauseEmit != nil {
		a.pauseEmit(RunEvent{Type: "paused"})
	}
	return true
}

// resumeCurrentScenario resumes a paused in-flight scenario's step
// scheduler, if any. Returns true if a run was active to resume. Idempotent.
func (a *Agent) resumeCurrentScenario() bool {
	a.scenarioMu.Lock()
	defer a.scenarioMu.Unlock()
	if a.pauseGate == nil {
		return false
	}
	a.pauseGate.Resume()
	if a.pauseEmit != nil {
		a.pauseEmit(RunEvent{Type: "resumed"})
	}
	return true
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd agent && go test . -run "TestPauseCurrentScenario|TestResumeCurrentScenario" -v`
Expected: PASS (all 4 tests)

- [ ] **Step 6: Wire the gate into `runScenario` and the WS command switch**

In `agent/agent.go`'s `runScenario` (~line 426), right after the `emit` closure is defined (~line 537, immediately before `emit(RunEvent{Type: "run_started", ...})`):

```go
	emit := func(ev RunEvent) { ev.RunID = cmd.RunID; ev.Seq = seq(); emitter.emit(ev) }

	gate := sched.NewGate()
	a.scenarioMu.Lock()
	a.pauseGate = gate
	a.pauseEmit = emit
	a.scenarioMu.Unlock()
	defer func() {
		a.scenarioMu.Lock()
		a.pauseGate = nil
		a.pauseEmit = nil
		a.scenarioMu.Unlock()
	}()

	emit(RunEvent{Type: "run_started", Payload: map[string]any{"stepsTotal": total, "mode": cmd.Mode}})
```

Then change the `sched.Run` call (~line 639) from:

```go
	sched.Run(ctx, workers, sched.NewLockManager(), jobs)
```

to:

```go
	sched.Run(ctx, workers, sched.NewLockManager(), jobs, gate)
```

In the WS message switch (~line 1017), immediately after the existing `case "command_cancel":` block:

```go
		case "command_pause":
			if a.pauseCurrentScenario() {
				log.Printf("[*] scenario paused by operator")
				a.logger.Op("info", "lifecycle", "scenario paused by operator request")
			} else {
				log.Printf("[~] command_pause received but no scenario is running")
			}

		case "command_resume":
			if a.resumeCurrentScenario() {
				log.Printf("[*] scenario resumed by operator")
				a.logger.Op("info", "lifecycle", "scenario resumed by operator request")
			} else {
				log.Printf("[~] command_resume received but no scenario is running")
			}
```

- [ ] **Step 7: Build and run the full agent test suite**

Run: `cd agent && go build ./... && go test ./... -v 2>&1 | tail -100`
Expected: PASS — no regressions in `cancel_test.go`, `shutdown_test.go`, or anything else that touches `runScenario`/the WS switch.

- [ ] **Step 8: Format, vet, commit**

```bash
cd agent && gofmt -l agent.go pause_test.go && go vet ./...
git add agent/agent.go agent/pause_test.go
git commit -m "feat(agent): wire pause/resume into runScenario and the WS command loop

Mirrors the existing cancelScenario/command_cancel pattern exactly,
with one deliberate difference: pauseGate/pauseEmit are cleared via
defer when runScenario returns, so a stray command_pause/resume
arriving after a run has already finished can't emit a confirmation
event that would incorrectly mark a completed run as paused (calling
an already-fired cancel() is a true no-op; calling emit() on a
finished run's closure is not).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: Server schema — `paused` column, model field, WS message constants

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (~line 133, right after the `max_privilege` ALTER TABLE)
- Modify: `orchestrator/internal/models/schema.go` (~line 154, `ScenarioRun.MaxPrivilege`; ~line 412, `MsgCommandCancel`)

**Interfaces:**
- Produces: `scenario_runs.paused boolean NOT NULL DEFAULT false` column; `models.ScenarioRun.Paused bool` (`json:"paused"`); `models.MsgCommandPause = "command_pause"`, `models.MsgCommandResume = "command_resume"` — consumed by Task 5 (event ingestion), Task 6 (`scanRunRows`), and Task 7 (REST handlers).

This task is pure additive scaffolding with nothing independently testable in isolation — Task 5's test is what actually exercises the column, and is where "did this task work" gets verified. No standalone test step here; verify with a build only.

- [ ] **Step 1: Add the DB column**

In `orchestrator/internal/db/postgres.go`, immediately after the `max_privilege` line (~133):

```go
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS max_privilege text NOT NULL DEFAULT ''`,
		// paused: true while an operator has paused this run's step scheduler.
		// status stays 'running' throughout a pause (see docs/superpowers/specs/
		// 2026-08-16-pause-resume-live-runs-design.md) -- every existing
		// status='running' check (busy guard, Live Runs button visibility,
		// dashboard counts) needs zero changes; only this flag distinguishes a
		// paused run from an actively-executing one.
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS paused boolean NOT NULL DEFAULT false`,
```

- [ ] **Step 2: Add the model field**

In `orchestrator/internal/models/schema.go`, right after `MaxPrivilege` (~line 154):

```go
	MaxPrivilege string `json:"maxPrivilege,omitempty"`
	// Paused is true while an operator has paused this run's step execution.
	// Only meaningful while Status=="running"; always false on a terminal run.
	Paused bool `json:"paused"`
```

- [ ] **Step 3: Add the WS message constants**

In `orchestrator/internal/models/schema.go`, right after `MsgCommandCancel` (~line 412):

```go
	MsgCommandCancel            = "command_cancel"
	MsgCommandPause             = "command_pause"
	MsgCommandResume            = "command_resume"
```

- [ ] **Step 4: Build**

Run: `cd orchestrator && go build ./...`
Expected: succeeds with no errors.

- [ ] **Step 5: Format, vet, commit**

```bash
cd orchestrator && gofmt -l internal/db/postgres.go internal/models/schema.go && go vet ./...
git add internal/db/postgres.go internal/models/schema.go
git commit -m "feat(runs): add paused column, model field, and pause/resume WS constants

scenario_runs.status stays 'running' throughout a pause -- see the
2026-08-16 pause-resume design spec for why a new status value was
rejected. Scaffolding only; internal/api/event_handlers.go (next)
is what actually sets this column.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 5: `SubmitRunEvents` ingests `paused`/`resumed` events

**Files:**
- Modify: `orchestrator/internal/api/event_handlers.go:36-56` (the `UPDATE scenario_runs` CASE WHEN block)
- Test: `orchestrator/internal/api/event_handlers_test.go` (new test, reusing existing `seedRun`/`postEvents` helpers already in that file)

**Interfaces:**
- Consumes: `paused` column from Task 4.
- Produces: `scenario_runs.paused` flips to `true`/`false` when a `paused`/`resumed` event is ingested — consumed by Task 6 (`scanRunRows`) and Task 7's end-to-end test (Task 8).

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/api/event_handlers_test.go`:

```go
func pausedState(t *testing.T, pool *pgxpool.Pool, runID string) bool {
	t.Helper()
	var p bool
	if err := pool.QueryRow(context.Background(),
		`SELECT paused FROM scenario_runs WHERE id = $1`, runID).Scan(&p); err != nil {
		t.Fatalf("pausedState: %v", err)
	}
	return p
}

func TestSubmitRunEvents_PausedResumedSetsPausedColumn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		runID := "run-pause-1"
		seedRun(t, pool, runID)

		ev := func(seq int, typ string) map[string]any {
			return map[string]any{"runId": runID, "seq": seq, "type": typ, "ts": "2026-06-09T16:40:12Z"}
		}

		postEvents(t, h, []map[string]any{ev(1, "run_started")})
		if pausedState(t, pool, runID) {
			t.Fatal("paused = true before any pause event, want false")
		}

		postEvents(t, h, []map[string]any{ev(2, "paused")})
		if !pausedState(t, pool, runID) {
			t.Fatal("paused = false after a 'paused' event, want true")
		}

		postEvents(t, h, []map[string]any{ev(3, "resumed")})
		if pausedState(t, pool, runID) {
			t.Fatal("paused = true after a 'resumed' event, want false")
		}
	})
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitRunEvents_PausedResumedSetsPausedColumn -v`
Expected: FAIL — `paused` events are ingested into `run_events` (the `INSERT` has no type filter) but `scenario_runs.paused` never changes, since the `UPDATE`'s CASE WHEN block doesn't mention it yet. The `pausedState` assertions fail (stays `false` after a `paused` event).

- [ ] **Step 3: Extend the ingestion SQL**

In `orchestrator/internal/api/event_handlers.go`, add one more field to the existing `UPDATE scenario_runs s SET ...` block (~line 43-53):

```go
			UPDATE scenario_runs s SET
				steps_total   = CASE WHEN ins.type='run_started'
				                     THEN COALESCE((ins.payload->>'stepsTotal')::int, s.steps_total)
				                     ELSE s.steps_total END,
				steps_running = s.steps_running
				                + CASE WHEN ins.type='started' THEN 1 ELSE 0 END
				                - CASE WHEN ins.type IN ('completed','timeout','killed') THEN 1 ELSE 0 END,
				steps_done    = s.steps_done    + CASE WHEN ins.type IN ('completed','timeout','killed') THEN 1 ELSE 0 END,
				steps_passed  = s.steps_passed  + CASE WHEN ins.type='completed' AND ins.payload->>'verdict'='pass' THEN 1 ELSE 0 END,
				steps_failed  = s.steps_failed  + CASE WHEN ins.type='completed' AND ins.payload->>'verdict' IN ('fail','blocked') THEN 1 ELSE 0 END,
				steps_timeout = s.steps_timeout + CASE WHEN ins.type='timeout' THEN 1 ELSE 0 END,
				paused        = CASE WHEN ins.type='paused' THEN true
				                     WHEN ins.type='resumed' THEN false
				                     ELSE s.paused END
			FROM ins
			WHERE s.id = $1`,
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitRunEvents_PausedResumedSetsPausedColumn -v`
Expected: PASS

- [ ] **Step 5: Run the full existing event-handling test to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run TestSubmitRunEventsSummaryAndIdempotency -v`
Expected: PASS (unchanged — this test never sends `paused`/`resumed` events, and the new CASE WHEN's `ELSE s.paused` branch preserves the column when other event types land)

- [ ] **Step 6: Format, vet, commit**

```bash
cd orchestrator && gofmt -l internal/api/event_handlers.go internal/api/event_handlers_test.go && go vet ./internal/api/...
git add internal/api/event_handlers.go internal/api/event_handlers_test.go
git commit -m "feat(runs): ingest paused/resumed run events into scenario_runs.paused

Reuses the exact same batched, idempotent-by-(run_id,seq) event
pipeline every other lifecycle event (run_started, started, completed,
...) already goes through -- no new transport, just one more CASE WHEN
on the existing UPDATE.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 6: Surface `paused` through `scanRunRows`

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`scanRunRows` doc comment + body ~line 2357-2384; `ListScenarioRuns`'s `SELECT` ~line 2391)
- Modify: `orchestrator/internal/api/emsweep_handlers.go` (`SELECT` ~line 137)
- Modify: `orchestrator/internal/api/vexsweep_handlers.go` (`SELECT` ~line 154)
- Test: `orchestrator/internal/api/list_scenario_runs_test.go` (new test)

**Interfaces:**
- Consumes: `paused` column (Task 4), `runRow`/`models.ScenarioRun.Paused` (Task 4).
- Produces: every `ListScenarioRuns`/EM-sweep-drilldown/Full-Variant-Sweep-drilldown response now includes `"paused": true|false` per run — consumed by the frontend (Task 8) and Task 7's end-to-end test.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/api/list_scenario_runs_test.go` (mirror whichever existing test in that file seeds a single run and asserts on a returned field — follow its exact `sharedDB.RunWithPool`/seed/`ListScenarioRuns`-via-`httptest`/decode pattern):

```go
func TestListScenarioRuns_PausedProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		seedActiveAgent(t, pool, "agent-paused-proj", "Windows")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, paused)
			 VALUES ('run-paused-proj','sc','agent-paused-proj','x','running',NOW(),true)`,
		); err != nil {
			t.Fatalf("seed: %v", err)
		}

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-paused-proj", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var runs []runRow
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 1 {
			t.Fatalf("runs = %d, want 1", len(runs))
		}
		if !runs[0].Paused {
			t.Error("runs[0].Paused = false, want true")
		}
	})
}
```

(Check the file's existing imports/helpers first — `seedActiveAgent` and `New(...)` are already used elsewhere in this package per this session's earlier `run_scenario_integration_test.go` work; reuse them rather than redefining.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestListScenarioRuns_PausedProjection -v`
Expected: FAIL — compile error (`scanRunRows`'s `Scan` call has fewer destinations than the `SELECT`'s columns once `paused` is added to the query but not the Go side, or vice versa — implement Step 3 as one atomic change to avoid a half-done intermediate state) or a decode showing `Paused: false` because the column isn't selected yet.

- [ ] **Step 3: Add `paused` to `scanRunRows` and all 3 `SELECT` call sites**

In `orchestrator/internal/api/handlers.go`, update `scanRunRows`'s doc comment and body:

```go
// scanRunRows scans a scenario_runs query's rows, decoding the JSON blob
// columns and deriving DetectedTechs/Progress the same way for every caller.
// Every caller's SELECT must list columns in exactly this order: id,
// scenario_id, agent_id, sweep_id, em_sweep_id, name, status, results, score,
// initiated_by, started_at, completed_at, steps_total, steps_done,
// steps_running, steps_passed, steps_failed, steps_timeout,
// detection_summary, alerts_total, alerts_high_fidelity, noise_score,
// reverted, mode, max_privilege, paused.
func scanRunRows(rows pgx.Rows) ([]runRow, error) {
	var runs []runRow
	for rows.Next() {
		var run runRow
		var resultsJSON, scoreRaw, detRaw, revertedRaw []byte
		var p models.RunProgress
		if err := rows.Scan(&run.ID, &run.ScenarioID, &run.AgentID, &run.SweepID, &run.EMSweepID, &run.Name,
			&run.Status, &resultsJSON, &scoreRaw, &run.InitiatedBy, &run.StartedAt, &run.CompletedAt,
			&p.StepsTotal, &p.StepsDone, &p.StepsRunning, &p.StepsPassed, &p.StepsFailed, &p.StepsTimeout, &detRaw,
			&run.AlertsTotal, &run.AlertsHighFidelity, &run.NoiseScore, &revertedRaw,
			&run.Mode, &run.MaxPrivilege, &run.Paused); err != nil {
			log.Printf("[api] scan run row: %v", err)
			continue
		}
```

(the rest of the function body is unchanged).

Update all 3 `SELECT` statements — append `, paused` right after `max_privilege`:

`internal/api/handlers.go` (`ListScenarioRuns`, ~line 2392):
```go
		`SELECT id, scenario_id, agent_id, sweep_id, em_sweep_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted, mode, max_privilege, paused
		 FROM scenario_runs
```

`internal/api/emsweep_handlers.go` (~line 137):
```go
		`SELECT id, scenario_id, agent_id, sweep_id, em_sweep_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted, mode, max_privilege, paused
		 FROM scenario_runs WHERE em_sweep_id = $1 ORDER BY started_at`,
```

`internal/api/vexsweep_handlers.go` (~line 154):
```go
		`SELECT id, scenario_id, agent_id, sweep_id, em_sweep_id, name, status, results, score, initiated_by, started_at, completed_at,
		        steps_total, steps_done, steps_running, steps_passed, steps_failed, steps_timeout, detection_summary,
		        alerts_total, alerts_high_fidelity, noise_score, reverted, mode, max_privilege, paused
		 FROM scenario_runs WHERE sweep_id = $1 ORDER BY started_at`,
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestListScenarioRuns_PausedProjection -v`
Expected: PASS

- [ ] **Step 5: Run the broader `ListScenarioRuns`/sweep-drilldown test groups to confirm no regression**

Run: `cd orchestrator && go test ./internal/api/... -run "TestListScenarioRuns|TestVexSweep|TestEMSweep" -v 2>&1 | tail -150`
Expected: PASS across the board — a wrong column order here would show up as garbage/mismatched values in unrelated fields (e.g. `Mode` containing a boolean-looking string), not just a missing `paused`.

- [ ] **Step 6: Format, vet, commit**

```bash
cd orchestrator && gofmt -l internal/api/handlers.go internal/api/emsweep_handlers.go internal/api/vexsweep_handlers.go internal/api/list_scenario_runs_test.go && go vet ./internal/api/...
git add internal/api/handlers.go internal/api/emsweep_handlers.go internal/api/vexsweep_handlers.go internal/api/list_scenario_runs_test.go
git commit -m "feat(runs): surface paused through ListScenarioRuns and sweep drilldowns

Same 3-call-site pattern the mode/max_privilege Run Settings work
used earlier this session -- scanRunRows is the single shared scan
function; all 3 SELECTs must list columns in its exact documented
order.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 7: `PauseRun`/`ResumeRun` REST endpoints

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (new handlers + helper, placed right after `cancelScenarioRun`/`forceCancelAfterGracePeriod`, ~line 2500)
- Modify: `orchestrator/internal/api/routes.go` (~line 313, right after the cancel route)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (~line 181, right after the cancel row)
- Test: `orchestrator/internal/api/pause_resume_handlers_test.go` (new file)

**Interfaces:**
- Consumes: `MsgCommandPause`/`MsgCommandResume` (Task 4), `errRunNotFound`/`errRunNotRunning` (already defined at `handlers.go:2452-2453`).
- Produces: `POST /api/scenarios/runs/{runId}/pause`, `POST /api/scenarios/runs/{runId}/resume` — consumed by Task 8 (end-to-end test) and Task 9 (frontend).

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/pause_resume_handlers_test.go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPauseRun_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		rec := httptest.NewRecorder()
		h.PauseRun(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/does-not-exist/pause", nil), "runId", "does-not-exist"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestPauseRun_NotRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		seedActiveAgent(t, pool, "agent-pause-notrun", "Windows")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
			 VALUES ('run-pause-notrun','sc','agent-pause-notrun','x','completed',NOW())`,
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
		rec := httptest.NewRecorder()
		h.PauseRun(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/run-pause-notrun/pause", nil), "runId", "run-pause-notrun"))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})
}

func TestPauseRun_SendsCommandPauseOverWS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "int-pause-cmd")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-pause-cmd"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("dispatch status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}
		fake.WaitForMessage(t, 2*time.Second) // drain the command_scenario dispatch

		pauseRec := httptest.NewRecorder()
		h.PauseRun(pauseRec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/"+runID+"/pause", nil), "runId", runID))
		if pauseRec.Code != http.StatusOK {
			t.Fatalf("pause status = %d, body = %s", pauseRec.Code, pauseRec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandPause {
			t.Fatalf("WS message type = %q, want %q", env.Type, models.MsgCommandPause)
		}
	})
}
```

`json` must be imported in this test file (`encoding/json`) — check the file's existing imports first; add it if the file doesn't already import it under another test's usage.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestPauseRun" -v`
Expected: FAIL — compile error, `h.PauseRun` undefined.

- [ ] **Step 3: Implement the shared helper and both handlers**

In `orchestrator/internal/api/handlers.go`, right after `forceCancelAfterGracePeriod` (~line 2528, after its closing brace):

```go
var errAgentOffline = fmt.Errorf("agent not connected")

// sendRunControlCommand looks up runID's agent and status, requires it be
// 'running' (paused or not -- pause/resume don't gate on the run's current
// paused state, only its status; see the package doc on idempotency), and
// forwards msgType to the agent over WS. Shared by PauseRun and ResumeRun.
// Unlike cancelScenarioRun, there is no grace-period force-timer here: an
// unconfirmed pause/resume is harmless, the run just keeps running as before.
func (h *Handler) sendRunControlCommand(ctx context.Context, runID, msgType string) (agentID string, err error) {
	var status string
	if err := h.db.QueryRow(ctx,
		`SELECT agent_id, status FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &status); err != nil {
		return "", errRunNotFound
	}
	if status != "running" {
		return agentID, errRunNotRunning
	}
	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    msgType,
		AgentID: agentID,
		Data:    map[string]string{"runId": runID},
	})
	if !sent {
		return agentID, errAgentOffline
	}
	return agentID, nil
}

// POST /api/scenarios/runs/{runId}/pause
func (h *Handler) PauseRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	agentID, err := h.sendRunControlCommand(r.Context(), runID, models.MsgCommandPause)
	switch err {
	case nil:
	case errRunNotFound:
		jsonError(w, "run not found", http.StatusNotFound)
		return
	case errRunNotRunning:
		jsonError(w, "run is not running", http.StatusConflict)
		return
	case errAgentOffline:
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	default:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[scenario] pause requested for run %s → agent %s", runID, agentID)
	h.auditLog(r, "scenario.pause", runID, map[string]any{"agentId": agentID}, "ok")
	respond(w, map[string]string{"runId": runID, "status": "pausing"})
}

// POST /api/scenarios/runs/{runId}/resume
func (h *Handler) ResumeRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	agentID, err := h.sendRunControlCommand(r.Context(), runID, models.MsgCommandResume)
	switch err {
	case nil:
	case errRunNotFound:
		jsonError(w, "run not found", http.StatusNotFound)
		return
	case errRunNotRunning:
		jsonError(w, "run is not running", http.StatusConflict)
		return
	case errAgentOffline:
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	default:
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[scenario] resume requested for run %s → agent %s", runID, agentID)
	h.auditLog(r, "scenario.resume", runID, map[string]any{"agentId": agentID}, "ok")
	respond(w, map[string]string{"runId": runID, "status": "resuming"})
}
```

- [ ] **Step 4: Add the routes**

In `orchestrator/internal/api/routes.go`, immediately after the cancel route (~line 313):

```go
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/scenarios/runs/{runId}/cancel", h.CancelRun)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/scenarios/runs/{runId}/pause", h.PauseRun)
		r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/scenarios/runs/{runId}/resume", h.ResumeRun)
```

- [ ] **Step 5: Add the RBAC matrix rows**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the cancel row (~line 181):

```go
	{http.MethodPost, "/api/scenarios/runs/{runId}/cancel", tierPermission, auth.CanCancelScenarioRun},
	{http.MethodPost, "/api/scenarios/runs/{runId}/pause", tierPermission, auth.CanCancelScenarioRun},
	{http.MethodPost, "/api/scenarios/runs/{runId}/resume", tierPermission, auth.CanCancelScenarioRun},
```

(`tierPermission` is the real, existing constant used throughout this table's "analyst + admin, per-permission" rows — confirmed at `rbac_matrix_test.go:172-183` — not a stand-in.)

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestPauseRun|TestRBACMatrix_NoDrift" -v`
Expected: PASS

- [ ] **Step 7: Format, vet, commit**

```bash
cd orchestrator && gofmt -l internal/api/handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go internal/api/pause_resume_handlers_test.go && go vet ./internal/api/...
git add internal/api/handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go internal/api/pause_resume_handlers_test.go
git commit -m "feat(runs): add PauseRun/ResumeRun REST endpoints

Mirrors CancelRun/cancelScenarioRun's lookup+WS-send shape via a new
shared sendRunControlCommand helper, deliberately without the
grace-period force-timer half -- an unconfirmed pause/resume is
harmless, unlike an unconfirmed cancel which must eventually force
the run out of 'running'. Reuses the existing CanCancelScenarioRun
permission (same operator-control-of-an-in-flight-run capability).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 8: End-to-end integration test

**Files:**
- Modify: `orchestrator/internal/api/run_scenario_integration_test.go` (new test, appended)

**Interfaces:**
- Consumes: everything from Tasks 4-7 (`PauseRun`/`ResumeRun`, `paused` column/projection, event ingestion).
- Produces: nothing new — this is the integration proof that all the pieces from Tasks 4-7 actually compose correctly end-to-end, the way a real agent round-trip would.

- [ ] **Step 1: Write the test**

Append to `orchestrator/internal/api/run_scenario_integration_test.go`, following the exact style of `TestRunScenarioIntegration_ModeAndMaxPrivilegePersisted` (added earlier this session in the same file):

```go
// Proves the full pause/resume round-trip: dispatch a live run, pause it
// (asserting the agent receives command_pause), simulate the agent's
// confirmation the way a real one would (POSTing a "paused" run event),
// assert ListScenarioRuns reflects paused=true, then symmetrically resume.
func TestRunScenarioIntegration_PauseResumeRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "int-pause-resume")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-pause-resume"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("dispatch status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}
		fake.WaitForMessage(t, 2*time.Second) // drain command_scenario

		// -- Pause --
		pauseRec := httptest.NewRecorder()
		h.PauseRun(pauseRec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/"+runID+"/pause", nil), "runId", runID))
		if pauseRec.Code != http.StatusOK {
			t.Fatalf("pause status = %d, body = %s", pauseRec.Code, pauseRec.Body.String())
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandPause {
			t.Fatalf("WS message type = %q, want %q", env.Type, models.MsgCommandPause)
		}

		// Simulate the agent's real confirmation (agent.go's pauseCurrentScenario
		// would emit exactly this through the same batched event pipeline).
		postEvents(t, h, []map[string]any{
			{"runId": runID, "seq": 100, "type": "paused", "ts": "2026-06-09T16:40:12Z"},
		})

		listRec := httptest.NewRecorder()
		h.ListScenarioRuns(listRec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId="+agentID, nil))
		var runs []runRow
		_ = json.Unmarshal(listRec.Body.Bytes(), &runs)
		if len(runs) != 1 || !runs[0].Paused {
			t.Fatalf("after pause: runs = %+v, want exactly 1 run with Paused=true", runs)
		}
		if runs[0].Status != "running" {
			t.Errorf("Status = %q, want unchanged %q (pause never touches status)", runs[0].Status, "running")
		}

		// -- Resume --
		resumeRec := httptest.NewRecorder()
		h.ResumeRun(resumeRec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/"+runID+"/resume", nil), "runId", runID))
		if resumeRec.Code != http.StatusOK {
			t.Fatalf("resume status = %d, body = %s", resumeRec.Code, resumeRec.Body.String())
		}
		env2 := fake.WaitForMessage(t, 2*time.Second)
		if env2.Type != models.MsgCommandResume {
			t.Fatalf("WS message type = %q, want %q", env2.Type, models.MsgCommandResume)
		}

		postEvents(t, h, []map[string]any{
			{"runId": runID, "seq": 101, "type": "resumed", "ts": "2026-06-09T16:40:13Z"},
		})

		listRec2 := httptest.NewRecorder()
		h.ListScenarioRuns(listRec2, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId="+agentID, nil))
		var runs2 []runRow
		_ = json.Unmarshal(listRec2.Body.Bytes(), &runs2)
		if len(runs2) != 1 || runs2[0].Paused {
			t.Fatalf("after resume: runs = %+v, want exactly 1 run with Paused=false", runs2)
		}
	})
}
```

- [ ] **Step 2: Run the test**

Run: `cd orchestrator && go test ./internal/api/... -run TestRunScenarioIntegration_PauseResumeRoundTrip -v`
Expected: PASS. If it fails, the failure will point at exactly which layer broke (WS message type wrong → Task 7's routing; `Paused` stuck at `false` after the event → Task 5's SQL or Task 6's column list; `Status` changed → a Task 4-7 regression touching `status` that must not exist).

- [ ] **Step 3: Format, vet, commit**

```bash
cd orchestrator && gofmt -l internal/api/run_scenario_integration_test.go && go vet ./internal/api/...
git add internal/api/run_scenario_integration_test.go
git commit -m "test(runs): add end-to-end pause/resume round-trip integration test

Proves Tasks 4-7 compose correctly: dispatch -> pause -> WS command
received -> simulated agent confirmation -> paused=true readable via
ListScenarioRuns -> resume -> symmetric. status stays 'running'
throughout, asserted explicitly.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 9: Frontend — Live Runs Pause/Resume button

**Files:**
- Modify: `orchestrator/wwwroot/index.html`:
  - Live Runs action-buttons block (~line 10879-10897, the exact block with the Stop button and today's `openRunPanel` calls)
  - `loadRuns()` area — no change needed, reused as-is
  - `stopRun` (~line 14632) — reference point, not modified
  - `socket.onmessage`'s `run_event` dispatch (~line 14879)

**Interfaces:**
- Consumes: `r.paused`, `r.mode` (Task 6's projection), `POST /api/scenarios/runs/{runId}/pause` / `.../resume` (Task 7).
- Produces: `pauseRun(runId)`, `resumeRun(runId)`, `armPauseConfirmFallback(runId)` JS functions.

No automated frontend test exists in this repo (confirmed pattern from every prior frontend change this session) — verification is `node --check` on the extracted script plus manual browser QA, which is deferred like all other frontend work this session (flag in the pending-QA backlog per project memory).

- [ ] **Step 1: Add the Pause/Resume button to the Live Runs row**

In `orchestrator/wwwroot/index.html`, immediately after the existing Stop button line (~10882-10883):

```js
      if (r.id && r.status === 'running') acts += '<button class="btn btn-outline btn-sm" onclick="openRunPanel(\'' + x(r.id) + '\',\'' + x(r.name).replace(/'/g,'&#39;') + '\',' + ((r.progress && r.progress.stepsTotal) || 0) + ',\'' + x(r.mode||'') + '\',\'' + x(r.maxPrivilege||'') + '\')" title="Live run timeline + progress">&#9673; Live</button> ';
      if (r.id && r.status === 'running') acts += '<button class="btn btn-outline-red btn-sm" onclick="stopRun(\'' + x(r.id) + '\')" title="Stop this run — keeps completed steps, marks the run partial">&#9632; Stop</button> ';
      // Pause/Resume is only meaningful for live-mode runs -- posture-mode
      // scenarios mostly run via runLocalScan (no scheduler to pause between
      // steps), and are excluded outright rather than distinguishing the rare
      // posture+non-LocalCheck case (see the design spec's Non-Goals).
      if (r.id && r.status === 'running' && r.mode !== 'posture') {
        acts += r.paused
          ? '<button class="btn btn-outline btn-sm" id="pause-btn-' + x(r.id) + '" onclick="resumeRun(\'' + x(r.id) + '\')">&#9654; Resume</button> '
          : '<button class="btn btn-outline btn-sm" id="pause-btn-' + x(r.id) + '" onclick="pauseRun(\'' + x(r.id) + '\')">&#10073;&#10073; Pause</button> ';
      }
```

- [ ] **Step 2: Add `pauseRun`/`resumeRun`/`armPauseConfirmFallback`**

Immediately after `stopRun` (~line 14640, right after its closing `}`):

```js
// _pausePending tracks runIds with an outstanding pause/resume click still
// awaiting confirmation, so armPauseConfirmFallback's timeout can tell
// whether loadRuns() already resolved it (see that function below).
var _pausePending = {};

function pauseRun(runId) {
  apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/pause', { method: 'POST' })
    .then(function() {
      showToast('Pausing…', 'ok');
      armPauseConfirmFallback(runId, 'Pause');
    })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function resumeRun(runId) {
  apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/resume', { method: 'POST' })
    .then(function() {
      showToast('Resuming…', 'ok');
      armPauseConfirmFallback(runId, 'Resume');
    })
    .catch(function(e) { showToast(e.message, 'err'); });
}

// Disables the clicked button immediately with a transient label, then
// reverts it after 20s IF no confirmation (a 'paused'/'resumed' run_event,
// see the run_event WS handler below) triggered a loadRuns() re-render in
// the meantime -- loadRuns() fully replaces this row's DOM from fresh
// server data when it does fire, so the only case this guards is a lost WS
// frame or an agent that never actually applied the pause/resume.
function armPauseConfirmFallback(runId, priorLabel) {
  _pausePending[runId] = true;
  var btn = document.getElementById('pause-btn-' + runId);
  if (btn) {
    btn.disabled = true;
    btn.textContent = priorLabel === 'Pause' ? 'Pausing…' : 'Resuming…';
  }
  setTimeout(function() {
    if (!_pausePending[runId]) return; // already resolved by a real confirmation
    delete _pausePending[runId];
    var stillThere = document.getElementById('pause-btn-' + runId);
    if (stillThere) {
      stillThere.disabled = false;
      stillThere.textContent = priorLabel === 'Pause' ? '❙❙ Pause' : '▶ Resume';
    }
  }, 20000);
}
```

- [ ] **Step 3: Extend the `run_event` WS dispatch to refresh Live Runs on confirmation**

In `orchestrator/wwwroot/index.html`'s `socket.onmessage` (~line 14879), change:

```js
      if (msg.type === 'run_event')          { window.onRunEvent(msg); return; }
```

to:

```js
      if (msg.type === 'run_event') {
        window.onRunEvent(msg);
        // A paused/resumed confirmation must refresh the Live Runs table --
        // window.onRunEvent above only updates the Live drawer (scoped to
        // whichever single run's drawer, if any, is currently open). Filtered
        // to this rare event type so it doesn't fire loadRuns() on every
        // routine step-level event.
        if ((msg.data.events || []).some(function(e) { return e.type === 'paused' || e.type === 'resumed'; })) {
          _pausePending = {}; // any pending fallback for this batch's run(s) is now resolved
          loadRuns();
        }
        return;
      }
```

- [ ] **Step 4: Verify JS syntax**

```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
fs.writeFileSync('SCRATCHPAD/extracted.js', scripts.join('\n;\n'));
"
node --check SCRATCHPAD/extracted.js
```

(replace `SCRATCHPAD` with this session's actual scratchpad path)

Expected: `SYNTAX OK` (no output = success from `node --check`)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): add Pause/Resume button to Live Runs

Shows next to Stop for live-mode running rows only. Doesn't flip to
'Resume' optimistically on click -- waits for the server's real
paused=true (via the run_event WS confirmation triggering a targeted
loadRuns()) before the button changes, with a 20s fallback so a lost
WS frame can't leave it stuck mid-transition.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 10: Full verification and final push

**Files:** none (verification only)

- [ ] **Step 1: Build everything**

```bash
cd agent && go build ./... && go vet ./...
cd ../orchestrator && go build ./... && go vet ./...
```

Expected: no errors.

- [ ] **Step 2: Run the full agent test suite**

Run: `cd agent && go test ./... -v 2>&1 | tail -100`
Expected: PASS, no regressions.

- [ ] **Step 3: Run the full `internal/api` suite with the correct timeout, in the background**

```bash
cd orchestrator && go test ./internal/api/... -timeout 25m > /path/to/scratchpad/final_api_test.log 2>&1
```

Use `Bash` with `run_in_background: true`. Wait for the completion notification, then read the actual log file (`tail -30`, and `grep -n "FAIL\|panic:"` if anything looks off) — do not trust a piped/truncated capture.

Expected: `ok  	github.com/audspect/bas/internal/api	<duration>s`, zero `FAIL` lines.

- [ ] **Step 4: Confirm everything from Tasks 1-9 is committed and pushed**

```bash
git status --short
git log --oneline -12
```

Expected: clean working tree (nothing to commit), and the last ~10 commits are this feature's Task 1-9 commits, all present on `origin/main` (`git push` already ran after each task, but this step is the final gate — if `git status` shows anything uncommitted, commit and push it now before declaring the feature done).
