# Campaigns (v1) — Design Spec

**Date:** 2026-06-16
**Status:** Approved (brainstormed + design-reviewed via designWavesAdditions.txt)
**Roadmap:** Wave 3 of `docs/superpowers/specs/2026-06-16-audspect-ui-gap-roadmap.md` — the backbone the dashboard "live campaigns" and (later) Findings hang off.

## Goal

Group **one scenario fanned out across many agents** into a single trackable unit ("campaign") with live, aggregated progress, result mix, and a per-agent breakdown. A campaign is a thin grouping + fan-out layer over the existing run engine — each target agent gets an ordinary child run; the campaign aggregates them.

## Non-goals (explicitly deferred)

- Scheduling / recurring campaigns (Wave 5 — needs a scheduler tick + schedule table).
- Multi-scenario suites (M scenarios × N agents).
- Saved/named Agent Groups as a first-class entity.
- Auto-retry of skipped targets.
- Jira / notification integrations.
- Tag *filtering* UI (tags are stored + displayed in v1; filtering later).

## Architecture summary

- A campaign = `campaigns` row + N child `scenario_runs` (each `campaign_id`-linked), all running the **same** scenario/mode/subset.
- Launch fans out by calling a shared `dispatchRun(...)` per target — the exact per-agent core extracted from the current `RunScenario` handler. Unavailable targets (offline / busy / blocked / OS-mismatch on live) are **skipped & recorded**, not failed.
- Rollup (progress, result mix, status) is **compute-on-read** from the child runs — no denormalized counters, no coupling to the result-ingest write path. `started_at`/`completed_at` are the only stamped lifecycle timestamps (completed_at written lazily once terminal).
- The run engine itself is unchanged; campaigns add one table, one nullable FK, and a new handler/route set + UI.

---

## 1. Data model

### 1.1 New table `campaigns`

Added to the `stmts` slice in `orchestrator/internal/db/postgres.go` (idempotent `CREATE TABLE IF NOT EXISTS`):

| Column | Type | Notes |
|---|---|---|
| `id` | text PK | `newID()` (same generator as runs) |
| `name` | text NOT NULL | operator-supplied campaign name |
| `scenario_id` | text NOT NULL | the scenario being fanned out |
| `scenario_name` | text NOT NULL DEFAULT '' | **snapshot** at launch (stable label if the scenario is renamed). No scenario *version* exists in the model; run-level `step_meta` already preserves execution fidelity. |
| `mode` | text NOT NULL DEFAULT 'posture' | `posture` \| `telemetry` \| `lab` — uniform across all child runs |
| `subset` | jsonb NOT NULL DEFAULT '{}' | optional uniform selection: `{techniques?:[],abilities?:[],steps?:[],checks?:[]}` |
| `reason` | text NOT NULL DEFAULT '' | audited justification for live modes |
| `targets` | jsonb NOT NULL DEFAULT '[]' | snapshot of intended agent IDs at launch |
| `skips` | jsonb NOT NULL DEFAULT '[]' | `[{agentId, reason}]` recorded at launch for targets that could not dispatch |
| `notes` | text NOT NULL DEFAULT '' | optional free text |
| `tags` | jsonb NOT NULL DEFAULT '[]' | optional `[string]`; displayed, not yet filterable |
| `created_by` | text | user id (from JWT claims), nullable |
| `created_at` | timestamptz NOT NULL DEFAULT NOW() | row creation |
| `started_at` | timestamptz NOT NULL DEFAULT NOW() | dispatch start (== created_at for run-now; distinct once scheduling lands) |
| `completed_at` | timestamptz | NULL until the campaign is first observed terminal; stamped lazily on read |
| `stopped_at` | timestamptz | NULL unless operator-stopped (the only sticky status input) |

### 1.2 `scenario_runs.campaign_id`

```sql
ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS campaign_id text;
CREATE INDEX IF NOT EXISTS idx_scenario_runs_campaign ON scenario_runs (campaign_id);
```

Ad-hoc runs keep `campaign_id = NULL`. Child runs are otherwise **ordinary runs** — same results/score/detection/step_meta, same report endpoints, same WS lifecycle. No other run-model change.

---

## 2. Fan-out dispatch

### 2.1 Shared `dispatchRun` refactor

Extract the per-agent core of `RunScenario` (`orchestrator/internal/api/handlers.go:591`) into:

```go
// dispatchRun creates and dispatches ONE run of sc on agentID. It performs the
// agent-state gate, OS-compat check, busy guard, run-row insert, and WS dispatch
// — the same logic the single-run endpoint uses. On success returns the new run
// id. When the agent cannot accept the run (offline/busy/blocked state, or live
// mode on an OS-incompatible agent) it returns ("", skipReason, nil) so callers
// (the campaign launcher) can record a skip without treating it as an error.
// err is non-nil only for genuine failures (DB error, etc.).
func (h *Handler) dispatchRun(ctx context.Context, sc *scenario.Scenario, agentID string, opts dispatchOpts) (runID string, skipReason string, err error)
```

`dispatchOpts` carries `mode, confirmLive, confirmLab, reason, techniques, abilities, steps, checks, campaignID, initiatedBy`. The existing single-run `RunScenario` is refactored to call `dispatchRun` with `campaignID=""`, preserving its current behavior and responses (including `osWarning`). **Skip reasons** (verbatim strings for the UI): `"offline"` (agent not connected / WS send failed), `"agent busy"` (a non-stale run already running), `"agent <state>"` (quarantined/restricted/retired), `"os mismatch"` (live mode on incompatible OS — posture is allowed with a warning, so it does NOT skip).

### 2.2 Launch flow — `POST /api/campaigns`

Request:
```json
{ "name":"Q2 Ransomware Readiness", "scenarioId":"sc-...", "agentIds":["ag-1","ag-2"],
  "mode":"posture", "confirmLive":false, "confirmLab":false, "reason":"",
  "techniques":[], "abilities":[], "steps":[], "checks":[],
  "notes":"", "tags":[] }
```
Handler steps:
1. Auth (JWT). Validate: `name` non-empty, scenario exists (`h.engine.Get`), `agentIds` non-empty, mode valid, subset valid (reuse `RunScenario`'s ART/step validation). Live modes require `confirmLive` (and `confirmLab` for lab) — same gates as single-run.
2. Insert the `campaigns` row (`status` is derived, not stored; `targets = agentIds`, `scenario_name = sc.Name`, `started_at = NOW()`).
3. For each `agentId`: `runID, skip, err := h.dispatchRun(ctx, sc, agentId, opts{campaignID:id,...})`. On `err` → abort with 500 (and best-effort delete the empty campaign). On `skip != ""` → append `{agentId, reason:skip}` to a local skips slice. On success → child run created (campaign_id set).
4. Persist `skips` jsonb on the campaign row.
5. Respond `{ "campaignId": id, "dispatched": <n>, "skipped": <m> }`.

Note: within one campaign each agent receives exactly one child run, so the one-run-per-agent busy guard only fires against *pre-existing* runs on that agent.

---

## 3. Aggregation & lifecycle (compute-on-read)

All rollup lives in pure functions in a new `orchestrator/internal/campaign/` package, unit-tested without a DB:

```go
type ChildRun struct { Status string; Results []models.SimulationResult; Score *models.Score; CompletedAt *time.Time }
type Skip struct { AgentID, Reason string }

type Summary struct {
    Status     string `json:"status"`     // running|completed|partial|failed|stopped|empty
    Progress   int    `json:"progress"`   // % of dispatched child runs that are terminal
    Targets    int    `json:"targets"`    // dispatched + skipped (reconciles)
    Dispatched int    `json:"dispatched"`
    Skipped    int    `json:"skipped"`
    Prevented  int    `json:"prevented"`  // step-level, across executed runs (pass|blocked)
    Detected   int    `json:"detected"`   // step-level: fail WITH a detection alert
    Missed     int    `json:"missed"`     // step-level: fail with no detection
    Errored    int    `json:"errored"`    // step-level: error|skipped checks (excluded from mix bar)
}

func DeriveStatus(children []ChildRun, skips int, stopped bool) string
func Aggregate(children []ChildRun, skips int) Summary
```

### 3.1 Status derivation (`DeriveStatus`)
Precedence:
1. `stopped` (stopped_at set) → **stopped**.
2. `len(children) == 0` → **empty** (all targets skipped — "no executable targets", not a failure).
3. any child non-terminal (`running`/`dispatched`) → **running**.
4. all children terminal:
   - all `completed` → **completed**
   - all `failed` → **failed**
   - otherwise (mix incl. `partial`) → **partial**

Run terminal statuses today: `completed`, `partial`, `failed`. (`running` is the only non-terminal.)

### 3.2 Result mix (`Aggregate`)
- **Agent-level (reconciles to target count):** `Targets = Dispatched + Skipped`, where `Dispatched = len(children)`, `Skipped = len(skips)`.
- **Step-level (within executed child runs):** for each child run's results — `pass|blocked` → Prevented; `fail` → Detected if a detection alert exists for that technique (reuse the run's `detection_summary.techniques` / `reporting.classifyDetection`), else Missed; `error|skipped` → Errored (kept out of the mix bar, shown as a footnote, consistent with the scoring taxonomy).
- **Progress** = terminal children ÷ dispatched (0 when none dispatched).

### 3.3 Lazy `completed_at`
When `GET /api/campaigns/{id}` or `/summary` computes a terminal status and `completed_at IS NULL`, issue a one-time `UPDATE campaigns SET completed_at = NOW() WHERE id=$1 AND completed_at IS NULL`. Cheap heal; avoids coupling to result-ingest.

### 3.4 Stop — `POST /api/campaigns/{id}/stop`
Set `stopped_at = NOW()`, then cancel each still-running child run via the existing cancel path (`POST /api/scenarios/runs/{runId}/cancel` logic / `stopRun`). Idempotent.

---

## 4. API surface

All under the JWT-authed group in `orchestrator/internal/api/routes.go`:

| Method | Path | Returns |
|---|---|---|
| `POST` | `/api/campaigns` | create + launch → `{campaignId, dispatched, skipped}` |
| `GET` | `/api/campaigns` | list: each campaign + its `Summary` (one aggregate query, see below) |
| `GET` | `/api/campaigns/{id}` | campaign row + `Summary` + child-run rows (id, agentId, status, score, per-agent result counts) + `skips` |
| `GET` | `/api/campaigns/{id}/summary` | just the `Summary` (lightweight; for dashboard cards + list polling) |
| `POST` | `/api/campaigns/{id}/stop` | `{stopped:true}` |

Child-run reports/results reuse the existing `/api/scenarios/runs/{runId}/...` endpoints (no duplication). The list endpoint computes summaries with a single `scenario_runs` query grouped by `campaign_id` (plus the campaigns rows) to avoid N+1.

Live updates: the existing browser WS already pushes run status/result changes; the Campaigns views re-fetch the affected campaign's `/summary` on a run event whose run belongs to a campaign (the WS run payload carries `runId`; the client maps it via the loaded child-run list, or simply refreshes the open campaign). No new WS message type required for v1.

---

## 5. UI (`orchestrator/wwwroot/index.html`)

- **Nav:** add **Campaigns** under the Operations group (Dashboard / Scenarios / Live Runs / **Campaigns**). New `tab-campaigns` view; wire into `showTab` (`loadCampaigns()` on select).
- **Campaigns list:** status-filter tabs (All/Running/Completed/Partial/Failed/Empty/Stopped) with counts; rows show name, scenario, target count, status badge (+ progress bar for running), a result-mix bar (Prevented/Detected/Missed) and a Skipped chip, started time. Row → detail. Uses `GET /api/campaigns`.
- **Campaign detail:** header (name, status, scenario, target summary, started/by); stat tiles (effectiveness avg, prevented, detected, missed, skipped); per-agent child-run table (agent, status, score, Live/Results actions reusing the existing run drawer `viewRunResults` / live panel); a "Skipped targets" list with reasons. Uses `GET /api/campaigns/{id}`. Stop/Re-run actions (re-run = relaunch a new campaign with the same params via the launch modal preset).
- **Launch Campaign modal:** reuse the run-wizard pattern — Scenario → Targets (multi-select with env/OS filters, "select all filtered") → Options (mode + Customize subset + reason) → Review (with target count, dispatched-vs-skipped preview is post-launch). Name + optional notes/tags on the Review/first step. Dispatches via `POST /api/campaigns`.
- **Dashboard widget:** a **Live / Recent Campaigns** panel (top N by `started_at`) using `/api/campaigns` (or per-card `/summary`), each row linking to detail. Sits alongside the existing dashboard panels.

Reuse: status badges (`sbadge`), result-mix bar (the dashboard donut / a segmented bar), the run drawer, and the wizard CSS already shipped. JS validated via the existing `new Function(<script>)` check.

---

## 6. Scoring reuse

No new scoring math. Per-child scores come from the existing run scoring; campaign "effectiveness" shown in detail = average of child `score.preventionScore` over scored children (or omitted when none scored). The step-level mix reuses the same verdict classification already used by the kill-chain / detection layer.

## 7. Testing

- `internal/campaign` pure functions: `TestDeriveStatus` (running/completed/partial/failed/stopped/empty precedence) and `TestAggregate` (reconciliation `targets = dispatched + skipped`, prevented/detected/missed/errored counts, progress %). Table-driven, no DB — same style as `detect.Score`.
- `dispatchRun` refactor: assert the single-run endpoint behavior is unchanged (existing `internal/api` tests still pass; add a focused test that a skip reason is returned for a busy/offline agent if feasible without a live DB, else cover via the pure launcher logic).
- Frontend: JS syntax validation; manual click-through (launch on mixed online/offline agents, verify dispatched/skipped reconcile, stop, detail per-agent drill-in).

## 8. Migration / compatibility

- Additive only: new `campaigns` table + `scenario_runs.campaign_id` (nullable) + index, all `IF NOT EXISTS` in `EnsureSchema`. Existing runs unaffected (`campaign_id` NULL). No data backfill. Clients get it on the next bundle deploy + server restart (schema auto-applies).

## 9. File structure

| File | Change |
|---|---|
| `orchestrator/internal/db/postgres.go` | + `campaigns` table, `scenario_runs.campaign_id` column + index |
| `orchestrator/internal/campaign/campaign.go` | new — `Summary`, `ChildRun`, `Skip`, `DeriveStatus`, `Aggregate` (pure) |
| `orchestrator/internal/campaign/campaign_test.go` | new — unit tests |
| `orchestrator/internal/api/handlers.go` | extract `dispatchRun`; refactor `RunScenario` to use it |
| `orchestrator/internal/api/campaign_handlers.go` | new — create/list/detail/summary/stop handlers |
| `orchestrator/internal/api/routes.go` | + 5 campaign routes |
| `orchestrator/wwwroot/index.html` | + Campaigns nav/list/detail, Launch modal, dashboard widget |
