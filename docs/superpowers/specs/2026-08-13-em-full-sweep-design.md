# Endpoint Mastery Full Sweep — Server-Side Orchestration — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-08-13.
**Depends on:** `internal/vexsweep` (the pattern this mirrors — `Store`/`Dispatcher`/stuck-layer force-cancel), `internal/exercise.PollScheduler` (the generic ticker abstraction), `h.dispatchRun` (the shared per-agent dispatch core `RunScenario`, campaign fan-out, and scheduled assessments already use), `h.cancelScenarioRun` (existing agent-notify + grace-period cancel logic).

## Problem

Endpoint Mastery's "Run Full Sweep" button (`runEmSweep()`, `wwwroot/index.html:17812`) has two confirmed bugs:

1. **No target picker at all.** It hardcodes `agents[0].agentId` — whichever agent happens to be first in the client-side array — with zero UI to choose a different agent, a group, or all agents.
2. **Only the first of 14 layers ever actually runs.** `EM_CATALOG` (`wwwroot/index.html:17683-17697`) has 14 real scenario IDs (`em-01-control-validation` through `em-14-continuous-validation`), and the client-side loop does iterate all 14 via a recursive `next(i)` — but `POST /api/scenarios/{id}/run` returns as soon as the run is *dispatched*, not when it *completes*. The loop calls `next(i+1)` immediately on that response, so layer 2's dispatch request arrives while layer 1 is still genuinely running, and hits the server's one-scenario-per-agent concurrency guard (`dispatchRun`'s "agent busy" skip). Layer 1 succeeds; layers 2-14 fail the same way, every time. A "N failed" toast reports this but doesn't explain why or list which ones — easy to miss, and looks like the sweep "only ran Endpoint Mastery 1."

Both are symptoms of the same root issue Full Variant Sweep already solved once: sweep orchestration state living entirely in client-side JS variables, with no server-side memory of "what's next" or "wait for completion before advancing."

## Non-Goals

- **No Telemetry/Lab mode.** EM layers stay posture-only, matching current behavior exactly. No mode selector is added to the EM sweep flow.
- **No new "variant" concept.** Unlike Full Variant Sweep, an EM layer is not fanned into encoding/privilege/execution-context combinations — each layer is one scenario, dispatched once. `em_sweeps` has no `total_variants`/`technique_variant_counts` equivalent; progress is simply `completed_layers` / `total_layers` (`total_layers` is always 14, barring server-side scenario removal — see Architecture §1).
- **No queueing of conflicting sweeps.** Same rule as vexsweep: a second `POST /api/em/sweeps` for an agent that already has one running is rejected (`409`), not queued.
- **No WebSocket push.** The frontend polls, same as Full Variant Sweep's drawer does.
- **No changes to `internal/vexsweep`, `vex_sweeps`, or any Full Variant Sweep code.** This is a parallel, independent package and table — not a generalization of vexsweep to cover both use cases. They share a *pattern*, not a runtime.

## Architecture

### 1. New table `em_sweeps`

```sql
CREATE TABLE IF NOT EXISTS em_sweeps (
    id                      text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    agent_id                text        NOT NULL,
    layers                  text[]      NOT NULL,
    current_index           int         NOT NULL DEFAULT 0,
    current_scenario_run_id text        NOT NULL DEFAULT '',
    current_layer_started_at timestamptz,
    completed_layers        int         NOT NULL DEFAULT 0,
    total_layers            int         NOT NULL DEFAULT 0,
    status                  text        NOT NULL DEFAULT 'running',
    error                   text        NOT NULL DEFAULT '',
    created_by              text        NOT NULL DEFAULT '',
    started_at              timestamptz NOT NULL DEFAULT NOW(),
    completed_at            timestamptz
);
CREATE INDEX IF NOT EXISTS idx_em_sweeps_agent ON em_sweeps (agent_id);
-- Race-safe "one running EM sweep per agent" -- a partial unique index,
-- not an app-level check-then-insert, mirroring vex_sweeps' identical guard.
CREATE UNIQUE INDEX IF NOT EXISTS idx_em_sweeps_one_running_per_agent
    ON em_sweeps (agent_id) WHERE status = 'running';
```

`layers` is resolved **once**, at creation time, from `EM_CATALOG`'s 14 IDs filtered against `h.engine`'s live scenario list (server-side — the client never submits this list, exactly matching how vexsweep independently resolves its technique list rather than trusting the client). `total_layers = len(layers)`. If fewer than 14 EM scenarios are loaded on the server (e.g. a fresh deploy missing scenario YAMLs), the sweep still runs, just for however many actually exist — the same graceful-degradation the client-side loop already does today (`toRun.length` after filtering against server-known IDs), just moved server-side.

`status` is one of `running` / `completed` / `stopped` / `failed`. `current_scenario_run_id`/`current_layer_started_at` are empty/null while no layer is currently dispatched.

Also add, mirroring `scenario_runs.sweep_id`:

```sql
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS em_sweep_id text REFERENCES em_sweeps(id);
CREATE INDEX IF NOT EXISTS idx_scenario_runs_em_sweep_id ON scenario_runs (em_sweep_id);
```

so Live Runs can collapse an EM sweep's 14 layer-runs into one row, exactly like Full Variant Sweep already does for its technique runs.

### 2. New package `internal/emsweep`

```go
package emsweep

type Sweep struct {
    ID                     string
    AgentID                string
    Layers                 []string
    CurrentIndex           int
    CurrentScenarioRunID   string
    CurrentLayerStartedAt  *time.Time // dispatcher's stuck-layer force-cancel trigger, mirrors vexsweep's CurrentTechniqueStartedAt
    CompletedLayers        int
    TotalLayers            int
    Status                 string
    Error                  string
    CreatedBy              string
    StartedAt              time.Time
    CompletedAt            *time.Time
}

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store
func (s *Store) Create(ctx context.Context, sw Sweep) (Sweep, error) // ErrAgentAlreadySweeping on the partial-unique-index conflict, same shape as vexsweep.ErrAgentAlreadySweeping
func (s *Store) Get(ctx context.Context, id string) (Sweep, error)
func (s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error)
func (s *Store) ListRunning(ctx context.Context) ([]Sweep, error)
func (s *Store) AdvanceToNext(ctx context.Context, id string, nextIndex int, nextScenarioRunID string) error
// AdvanceToNext increments completed_layers by 1 (never a variable count --
// unlike vexsweep's per-technique variant credit, every EM layer is worth
// exactly 1), sets current_index = nextIndex, and sets the new
// current_scenario_run_id/current_layer_started_at (empty string + status
// change to 'completed' when nextScenarioRunID == "").
func (s *Store) MarkStopped(ctx context.Context, id string) error
func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error

// DispatchFn dispatches one EM layer (a plain scenario) to an agent.
// Injected via SetDispatch after construction, breaking the
// internal/emsweep -> internal/api import cycle -- identical pattern to
// vexsweep.DispatchFn / exercise.Executor.AgentDispatchFn.
type DispatchFn func(ctx context.Context, sweepID, agentID, scenarioID string) (scenarioRunID string, err error)

// StatusFn reports a scenario_run's current status, read directly from
// scenario_runs -- no callback into internal/api needed, same as
// vexsweep.VariantRunStatusFn.
type StatusFn func(ctx context.Context, scenarioRunID string) (status string, err error)

// CancelFn cancels an in-flight scenario_run. Production wiring points this
// at the exact same Handler.cancelScenarioRun vexsweep's CancelFn uses --
// no new cancellation logic, just reused.
type CancelFn func(ctx context.Context, scenarioRunID string) (agentID, status string, err error)

type Dispatcher struct { /* store, status, dispatch, cancel, stuckThreshold, cancelTriggeredForRun -- identical shape to vexsweep.Dispatcher */ }

func NewDispatcher(store *Store, status StatusFn) *Dispatcher
func (d *Dispatcher) SetDispatch(fn DispatchFn)
func (d *Dispatcher) SetCancel(fn CancelFn)
func (d *Dispatcher) Tick(ctx context.Context) error
```

**Tick logic** — a direct port of `vexsweep.Dispatcher`'s `advance`/`maybeForceCancelStuck`/`dispatchNext`, with the variant-crediting removed (every layer credits exactly 1, not a per-technique count read from an array):

```
for each sweep in store.ListRunning(ctx):
    if sweep.CurrentScenarioRunID == "":
        dispatchNextLayer(sweep)   // sweep just created, nothing dispatched yet
        continue

    status, err := statusFn(ctx, sweep.CurrentScenarioRunID)
    if err != nil:
        maybeForceCancelStuck(sweep)  // a persistent status-check failure must not permanently block stuck-recovery
        continue
    if status == "running":
        maybeForceCancelStuck(sweep)  // 3-minute stuck-layer threshold, identical mechanism to vexsweep's
        continue

    // layer finished (completed/failed/partial) -- advance
    delete(cancelTriggeredForRun, sweep.CurrentScenarioRunID)
    dispatchNextLayer(sweep)

dispatchNextLayer(sweep):
    nextIdx := sweep.CurrentIndex
    if sweep.CurrentScenarioRunID != "": nextIdx++
    if nextIdx >= len(sweep.Layers):
        store.AdvanceToNext(sweep.ID, nextIdx, "")  // marks completed
        return
    scenarioRunID, err := dispatch(ctx, sweep.ID, sweep.AgentID, sweep.Layers[nextIdx])
    if err != nil:
        // Same choice vexsweep already made and this session already relied
        // on: a silently-skipped layer in a security-validation sweep is
        // worse than a sweep that stops and says why.
        store.MarkFailed(sweep.ID, err.Error())
        return
    store.AdvanceToNext(sweep.ID, nextIdx, scenarioRunID)
```

`maybeForceCancelStuck` is a byte-for-byte port of vexsweep's version (same 3-minute `defaultStuckThreshold`, same "set the dedup flag only after a successful cancel, so a failed attempt retries next tick" fix this session already applied to vexsweep — `internal/vexsweep/dispatcher.go`'s current state is the reference implementation to copy, not the original pre-fix version).

### 3. `dispatchEMLayer` — the `DispatchFn` implementation (new, in `internal/api`)

```go
func (h *Handler) dispatchEMLayer(ctx context.Context, sweepID, agentID, scenarioID string) (scenarioRunID string, err error) {
    sc, ok := h.engine.Get(scenarioID)
    if !ok {
        return "", fmt.Errorf("EM layer scenario %q not found", scenarioID)
    }
    runID, skip, err := h.dispatchRun(ctx, sc, agentID, dispatchOpts{Mode: "posture"})
    if err != nil {
        return "", err
    }
    if skip != "" {
        return "", fmt.Errorf("layer skipped: %s", skip)
    }
    if _, err := h.db.Exec(ctx, `UPDATE scenario_runs SET em_sweep_id = $1 WHERE id = $2`, sweepID, runID); err != nil {
        log.Printf("[emsweep] tag run %s with sweep %s: %v", runID, sweepID, err)
    }
    return runID, nil
}
```

Much simpler than `dispatchVariantForSweep` — no template resolution, since an EM layer is a plain posture scenario, not an ART technique needing variant fan-out. This is the exact same `h.dispatchRun` primitive Scheduled Assessments (`dispatchScheduledAssessmentTarget`) and Campaigns (`CreateCampaign`) already call.

### 4. API surface (new file `internal/api/emsweep_handlers.go`)

| Method | Path | Permission | Behavior |
|---|---|---|---|
| POST | `/api/em/sweeps` | `CanRunScenario` (same tier plain `POST /api/scenarios/{id}/run` already requires — this dispatches ordinary posture runs under the hood) | Body: `{agentId}`. Resolves `layers` server-side from `EM_CATALOG`'s 14 IDs filtered against `h.engine`. `409` on an existing running sweep for that agent (partial unique index backstops races). Returns the created `Sweep`; layer 1 dispatches on the dispatcher's next tick, not synchronously. |
| GET | `/api/em/sweeps/active?agentId=X` | `CanViewVariantRun` (reused tier — no EM-specific permission needed; viewing sweep progress is a read, same class as viewing variant-run progress) | Running sweep for that agent, or 404. |
| GET | `/api/em/sweeps/{id}` | `CanViewVariantRun` | Full detail. |
| GET | `/api/em/sweeps/{id}/runs` | `CanViewVariantRun` | The sweep's own row plus its 14 (or fewer) `scenario_runs` rows (`WHERE em_sweep_id = $1`), for the drawer's per-layer list. |
| GET | `/api/em/sweeps?status=running` | `CanViewVariantRun` | Every currently-running EM sweep across all agents. |
| POST | `/api/em/sweeps/{id}/cancel` | `CanCancelScenarioRun` (matches the permission the underlying scenario-run cancel already requires) | `409` if not `running`. Cancels `current_scenario_run_id` via `h.cancelScenarioRun` (the same call vexsweep's `CancelFn` makes), sets `status='stopped'`, `completed_at=NOW()`. No partial credit for the in-flight layer, matching `stopRun`'s existing semantics. |

### 5. `main.go` wiring

```go
emSweepStore := emsweep.NewStore(pool)
emSweepScheduler := exercise.NewPollScheduler(5 * time.Second)
emSweepDispatcher := emsweep.NewDispatcher(emSweepStore, func(ctx context.Context, scenarioRunID string) (string, error) {
    var status string
    err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = $1`, scenarioRunID).Scan(&status)
    return status, err
})
// ...added to the existing .With* chain...
handler := api.New(...).WithEMSweep(emSweepStore, emSweepDispatcher)...

emSweepScheduler.Start(func(ctx context.Context) {
    if err := emSweepDispatcher.Tick(ctx); err != nil {
        log.Printf("[emsweep] tick: %v", err)
    }
})
defer emSweepScheduler.Stop()
```

`WithEMSweep` mirrors `WithVexSweep` exactly: `dispatcher.SetDispatch(h.dispatchEMLayer)`, `dispatcher.SetCancel(h.cancelScenarioRun)`.

## Frontend

### Targeting

The EM tab's "Run Full Sweep" button gets its own new, EM-specific modal offering the same three target modes (Individual Agent / Agent Group(s) / All Agents) `vexRunFullSweep()` already has. This is a new modal with its own DOM/JS, closely modeled on the vex-sweep target-mode markup and logic but **not** sharing elements or functions with it — duplicating and adapting a working, tested pattern is lower-risk than generalizing shared code across two independent sweep types, and keeps this project from touching Full Variant Sweep's code at all (see Non-Goals). Group(s)/All-Agents resolve client-side into a list of agent IDs, then fan out one independent `POST /api/em/sweeps` per agent (`Promise.all`, each dispatch isolated — one agent's failure/offline/already-sweeping state never blocks the others), the same fan-out structure `vexRunFullSweep`'s group-mode block already uses.

`runEmSweep()` is replaced entirely — the old hardcoded-`agents[0]`, client-side-loop implementation is deleted, not kept as a fallback.

### Live progress

A new small drawer (not a reuse of the ART-technique sweep-drilldown, which renders technique/variant-specific columns that don't apply here) listing the sweep's layers with per-layer status pills (pending/running/completed/failed), reusing the existing drawer CSS scaffolding (`.drawer-overlay`/`.drawer`/`.drawer-body` classes already used throughout this file) and polling `GET /api/em/sweeps/{id}` the same way the vex-sweep panel polls its own sweep.

## Testing

- `internal/emsweep`: `Store` CRUD tests (Postgres-backed, mirroring `internal/vexsweep`'s exact test shape) — `Create` rejects a second running sweep for the same agent but allows one for a different agent; `GetActiveForAgent` correctness with multiple agents; `AdvanceToNext` transitions to `completed` on the last layer. `Dispatcher.Tick` tests with a stub `DispatchFn`/`StatusFn`/`CancelFn` — advances a 3-layer sweep one at a time; force-cancels a stuck layer past the threshold; retries a failed cancel attempt on the next tick (not abandoned forever — the exact regression this session's vexsweep fix covers, ported here from day one instead of found later); force-cancels even when `StatusFn` errors persistently; marks the sweep `failed` (not skip-and-continue) when `DispatchFn` errors.
- `internal/api`: `TestCreateEMSweep_RejectsSecondSweepSameAgent`, `TestCreateEMSweep_AllowsConcurrentSweepsDifferentAgents`, `TestCancelEMSweep_StopsSweepAndCancelsCurrentRun`, `TestGetActiveEMSweep_404WhenNoneRunning`, `TestDispatchEMLayer_TagsScenarioRunWithSweepID`, plus RBAC-matrix entries for the 6 new routes (`internal/api/rbac_matrix_test.go`).
- Frontend: JS syntax check via the established `node --check` extraction convention. No local browser click-through is feasible without a full DB+license dev-server bring-up (same constraint noted for the Profile page work this session) — flagged for manual QA once deployed.

## Manual QA (deferred, flagged for the user post-deploy)

- Start an EM sweep against a single agent; confirm all (up to) 14 layers actually dispatch in sequence, not just the first.
- Start an EM sweep via Group(s) and via All Agents; confirm one independent sweep per resolved agent.
- Close the browser tab mid-sweep, reopen, confirm the sweep is still progressing server-side and the drawer can reattach to it.
- Force a layer to hang (or wait for a real one) past 3 minutes; confirm force-cancel-and-advance fires.
- Confirm Live Runs collapses a sweep's layer-runs into one row via `em_sweep_id`, matching Full Variant Sweep's existing behavior.
