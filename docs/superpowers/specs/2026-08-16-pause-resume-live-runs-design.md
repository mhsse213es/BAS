# Pause/Resume for Live Scenario Runs — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-08-16.
**Depends on:** `agent/sched` (the resource-lock scheduler runScenario dispatches steps through), `agent.go`'s existing `cancelScenario`/`cancelCurrentScenario` pattern (the wiring Pause/Resume mirrors), `internal/api/handlers.go`'s `cancelScenarioRun`/`CancelRun` (the REST+WS pattern Pause/Resume mirrors), `internal/api/event_handlers.go`'s `SubmitRunEvents`/`ListRunEvents` (the existing run-event pipeline Pause/Resume's confirmation reuses), this session's earlier `mode`/`max_privilege` Run Settings work (the `scanRunRows`/3-SELECT-call-site pattern a new `paused` column follows).

## Problem

Live Runs has a Stop button but no way to pause an in-flight run and pick it back up later. An operator who needs to temporarily halt a run — investigate an alert mid-sweep, avoid a maintenance window, etc. — has to either let it keep going or Stop it (which discards remaining steps and marks the run `partial` permanently). There's no middle ground.

## Requirements (user-specified)

1. A combined Pause/Resume control next to the existing Stop button in the Live Runs table.
2. Shows "Pause" while running; clicking it does **not** immediately flip the button to "Resume" — it must wait for confirmation that the run is actually paused before showing "Resume".
3. Hidden entirely once the run reaches a terminal state (`completed`/`partial`/`failed`).

## Scope decisions (from brainstorming)

- **Pause semantics: finish current step(s), then hold.** No step is suspended or killed mid-execution. Confirmed by the user over the alternative (suspending a live process), which has no existing capability to build on (the agent's process-tree machinery only kills, never suspends) and was assessed as unnecessary complexity for this need.
- **State representation: boolean flag, not a new status value.** `scenario_runs.status` stays `running` throughout a pause — only a new `paused` column changes. Rejected making `paused` a first-class `status` value because a large number of existing checks across the codebase compare `status === 'running'` directly (the busy/concurrency guard, Live Runs' own button visibility, dashboard counts, etc.), and this codebase has hit multiple bugs this session alone from scattered, out-of-sync status-string comparisons. Keeping `status` unchanged means every one of those checks keeps working with zero changes, and a paused run correctly continues to occupy its agent (the existing `idx_scenario_runs_agent_running` unique index, scoped to `status='running'`, needs no changes).
- **Posture-mode runs are out of scope.** Precisely: a scenario dispatched in posture mode AND flagged `LocalCheck` (`dispatchRun`'s `!live && sc.LocalCheck` branch) runs via `runLocalScan` — all checks synchronously in one shot, no scheduler, no step-by-step structure to pause between. That covers the vast majority of real posture dispatches (every Endpoint Mastery layer, the built-in posture scenarios). A posture-mode scenario that is *not* `LocalCheck` would still go through `runScenario`'s scheduler like any live run and could technically be paused — but the frontend doesn't have a `LocalCheck` signal on the run row today, and this combination is rare/low-value enough that the simplification (gate the button on `mode !== 'posture'` outright, not on the narrower `LocalCheck` condition) is worth the reduced complexity. Posture checks are also fast and read-only by design, so pausing them has little value even where it would technically work. The Pause/Resume button only appears for live-mode (`telemetry`/`lab`) runs.
- **No new grace-period force-timer.** Unlike Stop (which must eventually force a run out of `running` even if the agent never confirms, via `forceCancelAfterGracePeriod`), a pause that's never confirmed is harmless — the run just keeps running normally. No server-side timer is needed; only a client-side UI fallback (§5) so a button can't get stuck.

## Non-Goals

- No pause/resume for posture-mode (`local_check`) runs — see above.
- No pause/resume for EM Sweep or Full Variant Sweep layer/technique dispatch loops — those orchestrate *between* `scenario_runs` rows server-side (`internal/emsweep`, `internal/vexsweep`); this feature pauses *within* one already-dispatched run's step execution on the agent. A sweep's individual layer/technique runs could gain this button like any other live run, but the sweep orchestrator itself is untouched.
- No mid-step suspension — see "Pause semantics" above.
- No new permission tier — reuses the existing `auth.CanCancelScenarioRun` permission (same "operator controls an in-flight run" capability class as Stop).
- No changes to the disconnect watchdog (`runDisconnectWatchdog`) — a paused run still finalizes as Partial if the agent loses its server link for >90s, identical to an unpaused run. Pausing doesn't reduce the need for that safety net; nothing about "no step is currently executing" makes an unreachable endpoint any more observable or controllable.

## Architecture

### 1. Agent: `sched.Gate`

New type in `agent/sched` (new file `agent/sched/gate.go`):

```go
package sched

import (
	"context"
	"sync"
)

// Gate lets a caller pause/resume a Run in progress without touching ctx.
// A paused Gate blocks workers from starting their NEXT job; any job already
// inside its Run func is never interrupted — it always runs to completion.
// Safe for concurrent use; Pause/Resume/IsPaused/Wait may be called from any
// goroutine. A nil *Gate is a valid, always-unpaused no-op (Wait returns
// immediately), so existing sched.Run callers that don't need pause support
// can keep passing nil.
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

func (g *Gate) Pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		return
	}
	g.paused = true
	g.ch = make(chan struct{})
}

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

// Wait blocks until the Gate is resumed or ctx is done, whichever comes first.
// Returns immediately if the Gate is not currently paused.
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

`Pause`/`Resume` are idempotent (guarded by the `paused` check), so the server never needs to know the agent's current pause state before sending a command — it can always just forward whatever the operator clicked.

### 2. Agent: wiring into `sched.Run` and `agent.go`

`sched.Run`'s signature gains a `gate *Gate` parameter:

```go
func Run(ctx context.Context, workers int, lm *LockManager, jobs []Job, gate *Gate) {
	...
	go func() {
		defer wg.Done()
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
	}()
	...
}
```

`gate.Wait` is called **between** jobs only, never inside `runJob`/a job's `Run` func — so a step that's already executing when Pause is requested always finishes normally, and only the *next* job a worker would otherwise start is held. With multiple workers, each one independently finishes its own in-flight job before checking the gate, so "finish current step(s), then hold" naturally extends to however many steps happen to be running concurrently at the moment Pause lands.

`agent.go` mirrors the existing `cancelScenario`/`scenarioMu` pattern with a new field:

```go
// alongside the existing cancelScenario field, guarded by the same scenarioMu
pauseGate *sched.Gate
```

Set in `runScenario` right before calling `sched.Run`, cleared (set to nil) when the run ends. Two new methods mirroring `cancelCurrentScenario`:

```go
func (a *Agent) pauseCurrentScenario() bool {
	a.scenarioMu.Lock()
	defer a.scenarioMu.Unlock()
	if a.pauseGate == nil {
		return false
	}
	a.pauseGate.Pause()
	return true
}

func (a *Agent) resumeCurrentScenario() bool {
	a.scenarioMu.Lock()
	defer a.scenarioMu.Unlock()
	if a.pauseGate == nil {
		return false
	}
	a.pauseGate.Resume()
	return true
}
```

Two new WS cases in the same switch as `command_cancel` (`agent.go` ~line 1017):

```go
case "command_pause":
	if a.pauseCurrentScenario() {
		log.Printf("[*] scenario paused by operator")
		a.logger.Op("info", "lifecycle", "scenario paused by operator request")
		a.emitPauseEvent("paused") // see §3
	} else {
		log.Printf("[~] command_pause received but no scenario is running")
	}

case "command_resume":
	if a.resumeCurrentScenario() {
		log.Printf("[*] scenario resumed by operator")
		a.logger.Op("info", "lifecycle", "scenario resumed by operator request")
		a.emitPauseEvent("resumed")
	} else {
		log.Printf("[~] command_resume received but no scenario is running")
	}
```

### 3. Confirmation: reuse the existing run-event pipeline

`runScenario` already threads an `emit(RunEvent{...})` closure through to every step (`agent.go:537`, feeding `newEventEmitter`'s batched best-effort POST to `/api/scenarios/events`). Pause/Resume needs that same closure accessible from the WS command handler, which runs on a different goroutine than `runScenario` — so the emit closure (or a thin wrapper) is stored alongside `pauseGate`/`cancelScenario` under `scenarioMu`, and `emitPauseEvent` above just calls it with `RunEvent{Type: "paused"}` / `{Type: "resumed"}`. No new transport, no new HTTP call shape — it's the same batched emitter, same endpoint, same idempotent-by-`(run_id, seq)` ingestion every other event type already gets.

Server-side, `SubmitRunEvents`' ingestion SQL (`internal/api/event_handlers.go`) gains one more `CASE WHEN` on the existing `UPDATE scenario_runs` — mirroring exactly how `steps_total` is already set from `run_started`:

```sql
paused = CASE
           WHEN ins.type='paused'  THEN true
           WHEN ins.type='resumed' THEN false
           ELSE s.paused
         END
```

`relayRunEvents` already broadcasts every batch to browsers unconditionally — no change needed there. This is the "confirmation": once the agent has actually applied the pause (or resume), that fact flows through the same pipe as every other step lifecycle event, with the same reliability characteristics (batched, best-effort, idempotent).

### 4. Server: schema, REST endpoints, RBAC

```sql
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS paused boolean NOT NULL DEFAULT false;
```

`models.ScenarioRun` gains `Paused bool \`json:"paused"\`` (no `omitempty` — `false` is a meaningful, always-present value, not "field absent on old data", matching how `Status` itself has no `omitempty`).

`scanRunRows` (`internal/api/handlers.go`) and its 3 call sites' `SELECT` column lists (`ListScenarioRuns`, EM sweep drilldown, Full Variant Sweep drilldown — the same 3 sites the `mode`/`max_privilege` work touched earlier this session) each add `paused` to the column list, in the same fixed order the function's doc comment enumerates.

Two new handlers mirroring `CancelRun`/`cancelScenarioRun`'s structure (`internal/api/handlers.go`):

```go
// POST /api/scenarios/runs/{runId}/pause
func (h *Handler) PauseRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	if err := h.sendRunControlCommand(r.Context(), runID, models.MsgCommandPause); err != nil {
		// errRunNotFound -> 404, errRunNotRunning -> 409, offline -> 503, mirrors CancelRun
	}
	respond(w, map[string]string{"runId": runID, "status": "pausing"})
}

// POST /api/scenarios/runs/{runId}/resume
func (h *Handler) ResumeRun(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	if err := h.sendRunControlCommand(r.Context(), runID, models.MsgCommandResume); err != nil {
		// same error mapping as PauseRun
	}
	respond(w, map[string]string{"runId": runID, "status": "resuming"})
}
```

`sendRunControlCommand` is a small shared helper factored out of `cancelScenarioRun`'s first half (look up `agent_id`/`status`, require `status == 'running'`, send the WS message) — Pause and Resume don't need the grace-period-timer half that's specific to Cancel, and don't need to pre-check the run's current `paused` value before sending (per "Pause/Resume are idempotent" in §1 — the operator's click is authoritative, forwarded as-is).

New WS message type constants in `internal/models/schema.go`, alongside `MsgCommandCancel`:

```go
MsgCommandPause  = "command_pause"
MsgCommandResume = "command_resume"
```

Routes (`internal/api/routes.go`), immediately after the existing cancel route, reusing its permission:

```go
r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/scenarios/runs/{runId}/pause", h.PauseRun)
r.With(auth.RequirePermission(auth.CanCancelScenarioRun)).Post("/api/scenarios/runs/{runId}/resume", h.ResumeRun)
```

`rbac_matrix_test.go`'s `routeMatrix` table gains two rows mirroring the existing cancel row, or `TestRBACMatrix_NoDrift` fails.

### 5. Frontend

**Live Runs table** (`wwwroot/index.html`, the same action-buttons block the Stop button and today's `openRunPanel` calls live in, ~line 10879-10897): a new button renders only when `r.status === 'running'`, immediately after Stop:

```js
if (r.id && r.status === 'running' && r.mode !== 'posture') {
  acts += r.paused
    ? '<button class="btn btn-outline btn-sm" onclick="resumeRun(\'' + x(r.id) + '\')">&#9654; Resume</button> '
    : '<button class="btn btn-outline btn-sm" onclick="pauseRun(\'' + x(r.id) + '\')">&#10073;&#10073; Pause</button> ';
}
```

`pauseRun`/`resumeRun` mirror `stopRun`'s shape but skip the `confirm()` dialog — unlike Stop, neither discards anything, so there's nothing to warn about:

```js
function pauseRun(runId) {
  apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/pause', { method: 'POST' })
    .then(function() { showToast('Pausing…', 'ok'); armPauseConfirmFallback(runId); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
function resumeRun(runId) {
  apicall('/api/scenarios/runs/' + encodeURIComponent(runId) + '/resume', { method: 'POST' })
    .then(function() { showToast('Resuming…', 'ok'); armPauseConfirmFallback(runId); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
```

**Confirmation → button flip.** Today, `run_event` WS messages (`socket.onmessage`, `msg.type === 'run_event'`) are only consumed by the Live drawer's `window.onRunEvent`, which is scoped to whichever single run's drawer happens to be open — the Live Runs *table* never reacts to them and only refreshes on `loadRuns()` calls (tab load, manual Refresh, post-action calls, and the `scenario_result` WS message on full completion). This is extended with one targeted check, alongside the existing dispatch:

```js
if (msg.type === 'run_event') {
  window.onRunEvent(msg);
  if ((msg.data.events || []).some(function(e) { return e.type === 'paused' || e.type === 'resumed'; })) {
    loadRuns();
  }
  return;
}
```

This only triggers a table refresh on the rare pause/resume event, not on every step-level event, and reflects the server's real `paused` value (round-tripped through the DB via §3) rather than an optimistic client-side guess — genuinely satisfying "only show Resume when it confirms the test is paused."

**Stuck-button fallback.** `armPauseConfirmFallback(runId)` disables the clicked button immediately (`"Pausing…"`/`"Resuming…"`, matching the toast) and sets a 20-second timeout that re-enables it (reverting to its pre-click label) if `loadRuns()` was never triggered by a matching confirmation in that window — so a lost WS frame or a slow agent can't leave the button permanently stuck mid-transition. Since `loadRuns()` fully re-renders the table from fresh server data whenever it *does* fire (including from this fallback's own perspective — the row is gone/replaced), the timeout only needs to guard the case where no `loadRuns()` happened at all.

## Testing

- `agent/sched`: new `gate_test.go` — `Pause` blocks a waiting `Wait(ctx)` until `Resume`; `Wait` returns immediately when unpaused; a cancelled `ctx` unblocks `Wait` even while paused; `Pause`/`Resume` are idempotent (double-call doesn't panic or deadlock); a nil `*Gate` is a safe no-op.
- `agent/sched`: extend `scheduler_test.go` — a job that starts before `Pause()` runs to completion; no new job starts while paused; jobs resume after `Resume()`; `Run` with a `nil` gate behaves exactly as it does today (regression guard for every existing caller).
- `internal/api`: new integration test mirroring `TestRunScenarioIntegration_MaxPrivilegeFiltersStep`'s container-backed style — dispatch a live run, POST `/pause`, assert the WS command the fake agent received; POST a synthetic `paused` run_event via `/api/scenarios/events` (as the fake agent would), assert `ListScenarioRuns` now reports `paused: true` for that run; POST `/resume` + a synthetic `resumed` event, assert it flips back to `false`.
- `internal/api`: `PauseRun`/`ResumeRun` error-path tests mirroring `CancelRun`'s (`errRunNotFound` → 404, non-`running` status → 409, agent offline → 503).
- `rbac_matrix_test.go`: the two new routes must appear in `routeMatrix` or `TestRBACMatrix_NoDrift` fails — this is enforcement, not optional coverage.
- Frontend: `node --check` on the extracted `<script>` block after every edit, per this session's established convention. No automated frontend test suite exists in this repo (confirmed pattern from every prior frontend change this session) — manual browser verification is deferred like all other frontend work this session, and should be flagged in the pending-QA backlog.

## Open Questions

None — all decisions above were confirmed during brainstorming (pause semantics, state representation, posture-mode exclusion, and no new grace-period timer).
