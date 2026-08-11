# Live Runs: Collapse Full Variant Sweep Technique Runs — Design

## Problem

A Full Variant Sweep dispatches one technique at a time; each technique dispatch creates its own
`scenario_runs` row (`internal/api/variant_handlers.go`'s `dispatchVariantRun`). The Live Runs tab
(`orchestrator/wwwroot/index.html`'s `loadRuns()`, backed by `GET /api/scenarios/runs`) renders one
row per `scenario_runs` record with no awareness that a run belongs to a sweep — so while (and
after) a sweep runs, Live Runs shows a new row per technique instead of one row representing the
sweep as a whole. The user wants exactly one row while a sweep is active, and that same one row to
represent it permanently in history afterward too — clicking it should show the necessary
per-technique detail, the same way clicking an individual run does today.

There is already a dedicated Full Sweep progress card on the Scenarios tab (`#vex-sweep-list`,
`renderVexSweepList`), but it only shows currently-*running* sweeps and lives on a different tab —
it does not affect what Live Runs itself shows, and has no history.

## Goals

- While a sweep is running, Live Runs shows exactly one row for it, not one per technique.
- After a sweep completes (or is stopped/fails), that one row persists permanently in Live
  Runs/history — its individual technique runs no longer appear as separate flat rows.
- Clicking the sweep row opens a drill-down list of every technique the sweep dispatched, each
  with its own status/score; clicking any technique inside that list opens today's existing
  single-run detail view (Live panel / results), completely unchanged.
- Every run NOT dispatched by a sweep renders exactly as it does today, in every view.

## Non-goals

- No change to `GET /api/scenarios/runs`'s existing per-row shape or behavior for any consumer
  other than Live Runs. That endpoint is read by 7 other call sites (Dashboard prevention-score
  weighting, Technique Coverage matrix, and others) that need every individual technique run's
  real `results`/`score` data — collapsing or aggregating at that shared endpoint would silently
  break their computations. This feature adds one new field to that endpoint's response and
  changes nothing else about it.
- No change to the existing Scenarios-tab Full Sweep progress card (`#vex-sweep-list`) — it
  already does its job for the "currently running, on the Scenarios tab" case.
- No change to `GET /api/scenarios/runs`'s `LIMIT 100` pagination. Collapsing a sweep's rows to
  one incidentally reduces how much of that budget a single sweep consumes, but changing the
  limit itself is out of scope.
- A sweep whose every child run has aged out of the `LIMIT 100` window (same as any sufficiently
  old individual run today) simply won't appear in Live Runs — this is existing, expected
  pagination behavior, not something this feature needs to solve.

## Design

### 1. Schema: tag each sweep-dispatched run at creation time

Add a nullable column:
```sql
ALTER TABLE scenario_runs ADD COLUMN sweep_id text REFERENCES vex_sweeps(id);
```
Tagged at INSERT time, not backfilled after the fact — correlation must be permanent and exact
(no heuristics like "same agent + running status", which would misfire if a user starts a normal
run on an agent that also has an active sweep).

### 2. Threading the sweep ID through dispatch

`vexsweep.DispatchFn` (`internal/vexsweep/dispatcher.go:12`) gains a `sweepID` parameter:
```go
type DispatchFn func(ctx context.Context, sweepID, agentID, techniqueID, mode string, includeAdvanced bool) (scenarioRunID, variantRunID string, totalVariants int, err error)
```
`Dispatcher.dispatchNext` (`dispatcher.go:76`, which already has `sw.ID` in scope) passes it:
```go
scenarioRunID, variantRunID, _, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Techniques[nextIdx], sw.Mode, sw.IncludeAdvanced)
```
`dispatchVariantForSweep` (`internal/api/variant_handlers.go:638`) and `dispatchVariantRun`
(`variant_handlers.go:548`) both gain a `sweepID string` parameter threaded straight through to
the existing INSERT (`variant_handlers.go:558-564`), which gains one column:
```sql
INSERT INTO scenario_runs
    (scenario_id, agent_id, name, status, results, steps_total, initiated_by, sweep_id)
VALUES ($1, $2, $3, 'running', '[]', $4, 'variant-executor', $5)
RETURNING id
```
`sweepID` is `""` (stored as SQL `NULL`) for every non-sweep call site — `dispatchVariantForSweep`
is the only caller `dispatcher.go` invokes, but `dispatchVariantRun` has other callers (ad-hoc
single-technique variant runs from the picker) that simply pass `""`.

### 3. `GET /api/scenarios/runs`: one new field, nothing else changes

`ListScenarioRuns` (`internal/api/handlers.go:2239`) adds `sweep_id` to its `SELECT`, scans it into
a `*string`, and adds `"sweepId": run.SweepID` (omitempty, null when not sweep-dispatched) to its
existing per-row JSON. Every other field, every other row, the query itself, the `LIMIT 100` — all
unchanged. The 7 other consumers of this endpoint never look at the new field and are unaffected.

### 4. New endpoint: sweep detail + full child-run list

```
GET /api/vex/sweeps/{id}/runs
```
Returns:
```json
{
  "sweep": { /* same shape sweepToJSON already produces, unbounded/authoritative status+progress */ },
  "runs": [ /* every scenario_runs row with this sweep_id, ALL of them, not paginated to 100 */ ]
}
```
This is unbounded (not subject to the 100-row cap `GET /api/scenarios/runs` has) because a sweep
can dispatch far more than 100 techniques over its lifetime — an aggregate pass/fail count or a
drill-down list built only from whatever happens to be in the last-100 window would be silently
wrong for large or older sweeps. This single endpoint serves both consumers below.

### 5. Frontend: grouping in `loadRuns()`

`loadRuns()` keeps fetching `GET /api/scenarios/runs` exactly as today. Rows with a non-null
`sweepId` are excluded from individual rendering; for each *distinct* `sweepId` found in the
fetched page, one call to `GET /api/vex/sweeps/{sweepId}/runs` fetches that sweep's authoritative
summary + full run list, and one synthetic row renders in its place: name "Full Variant Sweep —
`<agent hostname>`", status from `sweep.status` (running/completed/stopped/failed), progress
(`completedVariants`/`totalVariants` while running), and an aggregate pass/fail badge computed the
same way the existing per-run badge is (`(r.results || []).filter(c => c.result === 'fail').length`
vs. total), just summed across every child run in the full `runs` array instead of one run's own
`results` — i.e. total variants failed vs. passed across the whole sweep, not a per-technique
pass/fail count. Sort position: the collapsed row takes
the position of the newest child row present in the fetched (DESC-ordered) page, so it sits where
its most recent activity naturally falls in the list.

If the `GET /api/vex/sweeps/{id}/runs` call fails for a given `sweepId` (network error, etc.),
`loadRuns()` falls back to rendering that sweep's rows individually, exactly as today, rather than
silently hiding them — Live Runs must never show fewer runs than actually exist because of a
failed secondary fetch.

### 6. Frontend: drill-down panel on click

Clicking the collapsed row opens a new panel (reusing the existing overlay/drawer pattern already
used for `openRunPanel`) listing every run from the same `GET /api/vex/sweeps/{id}/runs` response
already fetched for the row's badge — technique, status, score, timestamp, one line each. Clicking
any technique in that list calls the *existing*, unmodified `openRunPanel(runId, name)` or
`viewRunResults(run)` for that specific `scenario_runs` row — no new single-run detail view is
built; only the list wrapping it is new.

## Data flow

```
Sweep dispatches technique  →  scenario_runs row created with sweep_id = sw.ID
                                        │
GET /api/scenarios/runs  ──────────────┤  (unchanged for every consumer except the new sweepId field)
        │                              │
        ├─ Dashboard/Coverage/etc.    (ignore sweepId, unaffected, see every raw row as before)
        │
        └─ loadRuns() (Live Runs)
                │
                ├─ rows with sweepId == null  → render individually, as today
                │
                └─ rows with sweepId == X     → suppress individual rendering
                                                        │
                                        GET /api/vex/sweeps/X/runs
                                                        │
                                        one synthetic "Full Variant Sweep" row
                                        (status + progress from .sweep, badge from .runs)
                                                        │
                                            click → drill-down list (.runs)
                                                        │
                                        click a technique → existing openRunPanel/viewRunResults
```

## Testing

- Go: a test seeding a sweep + several child `scenario_runs` rows sharing its `sweep_id`,
  asserting `GET /api/vex/sweeps/{id}/runs` returns the sweep summary plus every child row
  regardless of how many there are (beyond 100), and that rows with no `sweep_id` never appear.
- Go: a test confirming `dispatchVariantForSweep`/`dispatchVariantRun` correctly persist
  `sweep_id` when called with a non-empty `sweepID`, and persist `NULL` when called with `""`
  (covering the existing ad-hoc single-variant-run call sites, which must be unaffected).
- Go: `ListScenarioRuns` test confirming the new `sweepId` field appears (or is omitted/null)
  correctly and that no other field or row changes shape — a regression guard for the "shared
  endpoint, other consumers unaffected" non-goal.
- Frontend: `node --check` syntax verification (no JS test framework in this project, per
  established convention). Manual browser QA checklist: a running sweep shows one row with live
  progress; a completed/stopped/failed sweep shows one row with correct status/badge in history;
  clicking either opens the drill-down list; clicking a technique inside opens the existing detail
  view; a normal non-sweep run renders unaffected alongside sweep rows in the same list; the
  Dashboard's prevention score and Technique Coverage matrix are visually unchanged before/after
  this change (regression check for the non-goal above).
