# Full Variant Sweep — Server-Side Orchestration (Sub-project A: Backend) — Design

**Status:** Draft for review
**Author:** Claude + user, brainstormed 2026-07-30.
**Depends on:** existing `internal/variant` package and its `/api/variants/run`, `/api/variants/run/{id}` endpoints (`internal/api/variant_handlers.go`); `internal/exercise.PollScheduler` (the generic ticker abstraction already reused by Global Search's reindex, the OpenAEV sync, `verifySyncScheduler`, and `internal/exercise.Executor` itself).

## Problem

The "Full Sweep" feature (dispatch every ART technique sequentially, tracking overall progress) is currently a pure client-side loop (`vexRunFullSweep()`/`_vexSweepQueue()`/`_vexSweepPollAndNext()` in `cmd/server/wwwroot/index.html`). All of its state — which technique it's on, the currently in-flight run's ID, whether it's running at all — lives in plain browser JS variables (`_vexSweepRunning`, `_vexActiveScenarioRunId`, etc.), never persisted anywhere.

This was diagnosed live during a production incident: a user's sweep was mid-run, the progress bar read a misleadingly low percentage, and a page reload wiped every piece of orchestration state — the loop simply stopped (no further techniques get dispatched), the one in-flight technique kept running server/agent-side with nothing left to track or cancel it, and the Stop button (which only becomes visible while the client-side loop is active) vanished along with it.

## Non-Goals (this sub-project)

- **No frontend changes.** `cmd/server/wwwroot/index.html`'s sweep panel is untouched by this spec — it ships in Sub-project B, which rewires the panel to call the new endpoints this spec adds, adds resume-on-reload, and renders smooth variant-based + nested progress. This sub-project is backend-only and is fully covered by automated tests for that reason.
- **No queueing of conflicting runs.** When a same-agent conflict is detected (see Architecture §3), the platform **blocks** the new request with `409 Conflict` — it does not queue it for later automatic start. Today's codebase has no queueing mechanism anywhere (dispatch is always immediate-or-reject), and introducing one is a materially larger feature than this sub-project's scope. Revisit as a future enhancement if needed.
- **No new conflict rules beyond what was explicitly discussed.** Two *ad-hoc* variant runs (`/api/variants/run`, outside a sweep) on the same agent are not newly restricted by this spec — that's pre-existing behavior, unchanged. The only new conflict rules are: sweep vs. sweep on the same agent, and sweep vs. ad-hoc-variant-run on the same agent (both directions).
- **No WebSocket push for sweep progress.** The browser polls `GET /api/vex/sweeps/{id}` (per the earlier decision to keep progress delivery correctness independent of a live WS connection) — this is a Sub-project B frontend concern regardless, but worth stating here since it shapes the API (no new WS message types are added by this sub-project).
- **No changes to `variant_runs`/`scenario_runs` schemas.** Everything the dispatcher needs to know about an in-flight technique's completion is already queryable from those existing tables.

## Architecture

### 1. New table `vex_sweeps`

```sql
CREATE TABLE IF NOT EXISTS vex_sweeps (
    id                       text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    agent_id                 text        NOT NULL,
    mode                     text        NOT NULL DEFAULT 'sequential',
    include_advanced         boolean     NOT NULL DEFAULT false,
    techniques               text[]      NOT NULL,
    technique_variant_counts int[]       NOT NULL,
    current_index            int         NOT NULL DEFAULT 0,
    current_variant_run_id   text        NOT NULL DEFAULT '',
    current_scenario_run_id  text        NOT NULL DEFAULT '',
    completed_variants       int         NOT NULL DEFAULT 0,
    total_variants           int         NOT NULL DEFAULT 0,
    status                   text        NOT NULL DEFAULT 'running',
    error                    text        NOT NULL DEFAULT '',
    created_by               text        NOT NULL DEFAULT '',
    started_at               timestamptz NOT NULL DEFAULT NOW(),
    completed_at             timestamptz
);
CREATE INDEX IF NOT EXISTS idx_vex_sweeps_agent ON vex_sweeps (agent_id);
-- Enforces "one running sweep per agent" race-safely -- a partial unique
-- index, not an app-level check-then-insert, so two simultaneous
-- POST /api/vex/sweeps for the same agent can never both succeed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_vex_sweeps_one_running_per_agent
    ON vex_sweeps (agent_id) WHERE status = 'running';
```

`techniques` and `technique_variant_counts` are parallel arrays, resolved and computed **once**, at creation time — `techniques[i]`'s variant count is `technique_variant_counts[i]`. Computing this once (rather than re-deriving via `resolveTemplates` at dispatch time for each technique) keeps `total_variants` stable for the whole sweep's lifetime even if payload families change mid-sweep, matching the existing "quote the same real, server-computed total" principle already documented in `vexRunFullSweep()`'s comment.

`status` is one of `running` / `completed` / `stopped` / `failed`. `current_variant_run_id`/`current_scenario_run_id` are empty strings (not null) while no technique is currently dispatched (between sweep creation and the dispatcher's first tick, or after the last technique finishes but before the sweep is marked `completed` — a narrow window).

### 2. New package `internal/vexsweep`

```go
package vexsweep

type Sweep struct {
    ID                     string
    AgentID                string
    Mode                   string
    IncludeAdvanced        bool
    Techniques             []string
    TechniqueVariantCounts []int
    CurrentIndex           int
    CurrentVariantRunID    string
    CurrentScenarioRunID   string
    CompletedVariants      int
    TotalVariants          int
    Status                 string
    Error                  string
    CreatedBy              string
    StartedAt              time.Time
    CompletedAt            *time.Time
}

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store
func (s *Store) Create(ctx context.Context, sw Sweep) (Sweep, error)
// Create returns a *ConflictError (unwrap-checkable) when the partial
// unique index rejects a second running sweep for the same agent, so the
// HTTP handler can map it to 409 without string-matching the pg error.
func (s *Store) Get(ctx context.Context, id string) (Sweep, error)
func (s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error)
func (s *Store) ListRunning(ctx context.Context) ([]Sweep, error)
func (s *Store) ListByStatus(ctx context.Context, status string) ([]Sweep, error)
func (s *Store) AdvanceToNext(ctx context.Context, id string, justCompletedVariants int, nextVariantRunID, nextScenarioRunID string) error
// AdvanceToNext increments completed_variants by justCompletedVariants,
// increments current_index, and sets the new current_*_run_id fields (or
// marks status='completed' + completed_at when current_index reaches
// len(techniques)).
func (s *Store) MarkStopped(ctx context.Context, id string) error
func (s *Store) MarkFailed(ctx context.Context, id, errMsg string) error

// DispatchFn dispatches one technique's variants to an agent, returning the
// created scenario_run/variant_run IDs and the variant count actually
// generated (which may differ from a stale technique_variant_counts entry
// if payload families changed -- the dispatcher trusts THIS return value
// for AdvanceToNext, not the precomputed count). Injected via SetDispatch
// after the API handler is constructed, breaking the internal/vexsweep ->
// internal/api import cycle -- the exact pattern internal/exercise.Executor
// already uses for AgentDispatchFn.
type DispatchFn func(ctx context.Context, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error)

type Dispatcher struct {
    store     *Store
    scheduler exercise.Scheduler
    dispatch  DispatchFn
}

func NewDispatcher(store *Store, scheduler exercise.Scheduler) *Dispatcher
func (d *Dispatcher) SetDispatch(fn DispatchFn)
func (d *Dispatcher) Start()
func (d *Dispatcher) Stop()
```

**Tick logic** (`Dispatcher.tick(ctx)`, called by the injected `exercise.Scheduler` — production wiring uses `exercise.NewPollScheduler(5 * time.Second)`, matching the Exercise engine's own cadence):

```
for each sweep in store.ListRunning(ctx):
    if sweep.CurrentVariantRunID == "":
        dispatchNextTechnique(sweep)   // sweep just created, nothing dispatched yet
        continue

    status := queryVariantRunStatus(sweep.CurrentVariantRunID)  // direct SQL against variant_runs/scenario_runs, no callback needed for this half
    if status is still "running":
        continue  // nothing to do this tick

    // technique finished (completed/failed/partial) -- credit its variants and advance
    justFinishedCount := sweep.TechniqueVariantCounts[sweep.CurrentIndex]
    if sweep.CurrentIndex + 1 >= len(sweep.Techniques):
        store.AdvanceToNext(sweep.ID, justFinishedCount, "", "")  // marks completed
        continue
    dispatchNextTechnique(sweep)  // dispatches techniques[CurrentIndex+1], AdvanceToNext credits + advances + records new current_*_run_id

dispatchNextTechnique(sweep):
    scenarioRunID, variantRunID, totalVariants, err := dispatch(ctx, sweep.AgentID, sweep.Techniques[nextIdx], sweep.Mode, sweep.IncludeAdvanced)
    if err != nil:
        // Dispatch failed (e.g. agent went offline mid-sweep) -- log and
        // mark the sweep failed rather than silently looping forever.
        // (The old client-side loop retried by moving to the NEXT
        // technique on dispatch failure; this sub-project chooses to stop
        // and surface the error instead, since a silently-degraded sweep
        // that skips techniques is worse for a security-validation tool
        // than one that stops and says why.)
        store.MarkFailed(sweep.ID, err.Error())
        return
    store.AdvanceToNext(...)
```

This is a deliberate behavior change from the current client-side loop, which continues past a dispatch failure (`internal/index.html:13979-13983`, "Error on X — continuing…"). Flagging this explicitly: **for a security-validation sweep, silently skipping a technique because of a transient dispatch error is worse than stopping and surfacing the error** — an operator relying on "we swept everything" needs to know if a technique was actually skipped, not discover it later from a shorter-than-expected results list. If this is wrong, say so during spec review.

### 3. Same-agent conflict prevention

Two new checks, one on each side:

- **`POST /api/vex/sweeps` (new)** — before inserting, checks `variant_runs` for any row with `agent_id = X AND status = 'running'`. If found, `409 Conflict` ("agent has an active variant run — stop it before starting a sweep"). The partial unique index (§1) independently guarantees no two sweeps ever run concurrently on the same agent, even under a race.
- **`POST /api/variants/run` (existing handler, `RunVariants` in `internal/api/variant_handlers.go`)** — gets one new check added at the top, after validating `agentId`/`techniqueId`: query `vex_sweeps` for any row with `agent_id = X AND status = 'running'`. If found, `409 Conflict` ("agent has an active Full Sweep — stop it before running an individual variant test"). This is the only change to an existing endpoint in this sub-project.

Sweeps on different agents are fully independent — the `Dispatcher.tick` loop already iterates all running sweeps regardless of agent, so multiple agents sweep in parallel with no additional work beyond the per-agent uniqueness index.

### 4. API surface (new file `internal/api/vexsweep_handlers.go`)

| Method | Path | Permission | Behavior |
|---|---|---|---|
| POST | `/api/vex/sweeps` | `CanRunVariants` | Body: `{agentId, mode, includeAdvanced}`. Resolves `techniques`/`technique_variant_counts` server-side (same technique source as `GET /api/art/techniques`, same per-technique variant-count derivation `resolveTemplates` already does — never trusts a client-submitted technique list). 409 on same-agent conflict (either kind). Returns the created `Sweep`; dispatch of technique #1 happens on the dispatcher's next tick, not synchronously in the handler. |
| GET | `/api/vex/sweeps/active?agentId=X` | `CanViewVariantRun` | Returns the running sweep for that agent, or 404 if none. This is what powers Sub-project B's resume-on-reload. |
| GET | `/api/vex/sweeps/{id}` | `CanViewVariantRun` | Full detail, with `completedVariants` computed live: `sweep.CompletedVariants + (finished-step count of the in-flight technique's scenario_run.results)` — the same query shape `GetVariantRun` already uses to reconstruct per-variant verdicts, so this number is already variant-granular even though no frontend consumes it smoothly until Sub-project B. |
| GET | `/api/vex/sweeps?status=running` | `CanViewVariantRun` | Lists every currently-running sweep across all agents — direct exposure of `Store.ListRunning`, since the dispatcher already needs that query internally and an operator validating "dozens or hundreds of endpoints in parallel" needs a way to see everything in flight at once. |
| POST | `/api/vex/sweeps/{id}/cancel` | `CanCancelScenarioRun` | Matches the permission the underlying scenario-run cancel already requires (this endpoint delegates to the same cancellation logic). 409 if the sweep isn't `running`. Cancels `current_scenario_run_id` via the identical logic `CancelRun` uses (factored into a shared helper — not copy-pasted), sets sweep `status='stopped'`, `completed_at=NOW()`. `completed_variants` is **not** incremented for the technique that was in flight when cancelled — matches `stopRun`'s existing "remaining steps will not execute" semantics (no partial credit). |

### 5. `main.go` wiring

```go
vexSweepStore := vexsweep.NewStore(pool)
vexSweepDispatcher := vexsweep.NewDispatcher(vexSweepStore, exercise.NewPollScheduler(5*time.Second))
handler := api.New(pool, hub, engine, cfg.JWTSecret).
    // ...existing .With* chain...
    WithVexSweep(vexSweepStore)
vexSweepDispatcher.SetDispatch(handler.dispatchVariantForSweep)
vexSweepDispatcher.Start()
defer vexSweepDispatcher.Stop()
```

`handler.dispatchVariantForSweep` is a small new `Handler` method wrapping the existing `resolveTemplates` + `dispatchVariantRun` pair for a single technique — the same two calls `RunVariants` already makes, just returning the variant count alongside the IDs so the dispatcher can pass the real (not precomputed) count to `AdvanceToNext`.

## Testing

- `internal/vexsweep`: `Store` CRUD tests (Postgres-backed) — `Create` rejects a second `running` sweep for the same agent (409-mappable conflict error) but allows one for a different agent; `GetActiveForAgent` returns the right sweep when multiple agents have running sweeps simultaneously; `AdvanceToNext` correctly transitions to `completed` on the last technique. `Dispatcher` tick tests using a stub `DispatchFn` (no real agent/WS needed — the dispatcher's job is pure orchestration) — advances through a 3-technique sweep credit-by-credit; stops advancing a `stopped` sweep; marks a sweep `failed` (not skip-and-continue) when `DispatchFn` returns an error.
- `internal/api`: `TestCreateVexSweep_RejectsSecondSweepSameAgent`, `TestCreateVexSweep_AllowsConcurrentSweepsDifferentAgents`, `TestCreateVexSweep_RejectsWhenAgentHasRunningVariantRun`, `TestRunVariants_RejectsWhenAgentHasRunningSweep` (the new check on the *existing* handler), `TestCancelVexSweep_StopsSweepAndCancelsCurrentRun`, `TestGetActiveVexSweep_404WhenNoneRunning`, plus RBAC-matrix entries for the 4 new routes.

## Manual QA

None required for this sub-project — it's backend-only, fully covered by the automated tests above. Sub-project B's manual QA (resume-on-reload in a real browser, Stop button visibility after reload, smooth progress rendering) is deferred to that sub-project's own spec, matching this session's established pattern.
