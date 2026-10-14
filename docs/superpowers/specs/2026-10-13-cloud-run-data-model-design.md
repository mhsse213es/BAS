# Cloud Run Data Model & Lifecycle — Design

**Date:** 2026-10-13
**New package:** `orchestrator/internal/cloudrun/` (Go type)
**New file:** `orchestrator/internal/db/cloudrun_store.go` (persistence)
**Schema change:** new table `cloud_runs` (no existing table modified)

## Context and motivation

This is sub-project #1 of a 5-part decomposition of "wire `orchestrator/internal/cloudgraph/`'s already-built standalone capabilities (evaluators, `CloudPlan`/`CloudReachable`, `RunMultiAccount`, `ComposeHybridPath`, `ExecuteCloudRansomwareScenario`, `AzureDiscoveryClient`) into the live orchestrator" — a gap `CLOUD_BAS_MASTERY_GAP_ANALYSIS.md`'s 2026-10-13 addendum named but didn't design. The full decomposition, in build order:

1. **Cloud run data model & lifecycle** (this spec)
2. Cloud scenario execution harness (the orchestrator-side "executor" that actually calls `cloudgraph` functions and records a result)
3. API endpoint(s) to trigger a cloud run
4. Multi-account campaign fan-out (connecting `RunMultiAccount`/`CloudCampaignScope` to a real reporting surface)
5. Hybrid (AD-to-cloud) and cloud-ransomware scenario wiring

This sub-project exists because of a finding made while grounding the decomposition in real code: **the entire live dispatch path assumes a connected endpoint agent.** Every real dispatch call (`TriggerScan`, `SafeScan`, etc. in `orchestrator/internal/api/handlers.go`) ends in `h.hub.SendToAgent(agentID, ...)` over WebSocket — the agent runs a command and POSTs results back. The `scenario_runs` table backing every run has `agent_id text NOT NULL` with `CONSTRAINT fk_agent FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE` (`orchestrator/internal/db/postgres.go:124-136`), plus a partial unique index on `agent_id` for the dispatch busy-guard. 52 files touch `scenario_runs`. The `findings` table (behind dashboards/reporting) has the identical shape one layer up: `agent_id text NOT NULL` with a unique constraint on `(agent_id, technique_id, control_class)` (`postgres.go:325-350`).

A cloud scenario has no agent — a cloud permission check or discovery call is executed by the orchestrator itself, calling a cloud API directly, not dispatched to any remote process. Reusing `scenario_runs`/`findings` would mean either loosening a load-bearing invariant that dozens of files assume holds, or faking an `agent_id` value for a cloud account — both rejected (see "Approaches considered" below). This spec instead defines a **separate `cloud_runs` table**, explicitly **not** attempting to unify with the `findings`/`scenario_runs` reporting surface in this increment. That unification — if wanted later — is real, named future work (likely requiring `agent_id` to generalize into a provider-neutral `subject_id` across both tables), not something to smuggle into this sub-project.

## Approaches considered

- **Extend `scenario_runs`** (loosen `agent_id` to nullable, add `execution_kind='cloud'`): rejected. Weakens an invariant (NOT NULL + FK + busy-guard unique index) that ~52 files assume holds, for a benefit (shared listing) that's only partial anyway since `findings` has the identical agent-centric shape one layer up.
- **Separate table, but synthesize an `agent_id` from the cloud account ID to also write into `findings`**: rejected. This is the "satisfy a schema with data that doesn't mean what the schema says it means" trap — cloud accounts would start appearing as if they were registered endpoint agents everywhere agent-health/dashboard logic touches that column. A cosmetic short-term win with a real long-term correctness cost.
- **Separate `cloud_runs` table** (this spec): adopted. Touches zero existing tables; nothing already depending on `scenario_runs`'/`findings`' `agent_id` semantics can break.

## Scope

- **In scope:** the `cloud_runs` table, its CHECK constraints, the `cloudrun.CloudRun` Go type, and four store functions (`InsertCloudRun`, `UpdateCloudRunStatus`, `GetCloudRun`, `ListCloudRuns`).
- **Out of scope (explicitly deferred, not silently dropped):**
  - **The result JSON's internal shape.** `cloud_runs.result` is opaque `jsonb` / `json.RawMessage` in Go. This sub-project defines the *lifecycle* a run goes through, not what a `CloudPlan` search or `ExecuteCloudRansomwareScenario` run actually produces as evidence — that's sub-project #2's job.
  - **Campaign-level grouping.** No `campaign_id` column. A `RunMultiAccount` fan-out becomes multiple `cloud_runs` rows (one per account); aggregating them into a campaign view is sub-project #4's job. Adding a grouping column now would be guessing at a shape that project hasn't earned yet.
  - **Unifying with `findings`/`scenario_runs` for dashboards and cross-cutting reporting.** Real future work, contingent on generalizing `agent_id` across both tables — a materially bigger, riskier migration than this sub-project.
  - **Any API endpoint, HTTP handler, or UI.** Sub-project #3's job entirely. This spec produces a schema and a Go persistence layer only — nothing yet calls `InsertCloudRun` from a live request.
  - **List filtering by provider/status/account/etc.** `ListCloudRuns` takes only a limit for now; filter parameters are speculative until sub-project #3 reveals real needs.

## Schema

New table, added alongside the existing migrations in `orchestrator/internal/db/postgres.go`:

```sql
CREATE TABLE IF NOT EXISTS cloud_runs (
    id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    scenario_id   text        NOT NULL,
    provider      text        NOT NULL,
    account_id    text        NOT NULL DEFAULT '',
    tenant_id     text        NOT NULL DEFAULT '',
    region        text        NOT NULL DEFAULT '',
    status        text        NOT NULL DEFAULT 'pending',
    result        jsonb,
    error         text,
    initiated_by  text,
    started_at    timestamptz NOT NULL DEFAULT NOW(),
    completed_at  timestamptz,
    CONSTRAINT cloud_runs_status_check   CHECK (status IN ('pending','running','completed','failed','partial')),
    CONSTRAINT cloud_runs_provider_check CHECK (provider IN ('aws','azure','gcp'))
)
```

No `agent_id`, no FK to `agents` — the entire point of this table's existence. `provider`/`account_id`/`tenant_id`/`region` are flattened, queryable columns (mirroring `cloudgraph.AccountScope`'s fields) rather than a nested `jsonb` blob, since "every run against account X" is an obvious future query, consistent with `findings`'/`scenario_runs`' own flat-columns style.

An index on `(status)` is deferred — not added speculatively; `ListCloudRuns`' current form (order by `started_at`, bounded limit, no status filter) doesn't need one yet, and adding one later is a one-line, zero-risk migration whenever a real filtered query exists.

## Go type

New package `orchestrator/internal/cloudrun/types.go` — kept separate from `cloudgraph` since lifecycle/persistence tracking is a different concern from `cloudgraph`'s pure graph/evaluation scope (mirrors how `rwevidence` is its own domain package, distinct from `adprimitive`/`adchain`):

```go
package cloudrun

import (
	"encoding/json"
	"time"
)

// Status is a cloud_runs.status value.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusPartial   Status = "partial"
)

// CloudRun is one execution of one cloud scenario against one account
// scope. Result is deliberately opaque -- this package defines the
// lifecycle a run goes through, not what a given scenario's execution
// harness (a later sub-project) actually produces as evidence.
type CloudRun struct {
	ID          string
	ScenarioID  string
	Provider    string
	AccountID   string
	TenantID    string
	Region      string
	Status      Status
	Result      json.RawMessage
	Error       string
	InitiatedBy string
	StartedAt   time.Time
	CompletedAt *time.Time
}
```

## Lifecycle / state machine

- A run is created as `StatusPending` or `StatusRunning` — this sub-project doesn't decide which. That depends on whether sub-project #2's execution harness dispatches synchronously (create already-`running`) or through a queue (create `pending`, flip to `running` when picked up). Neither the schema nor the store functions foreclose either path.
- Terminal states: `completed` (ran to conclusion), `failed` (couldn't run at all -- e.g. an evaluator error, a malformed scenario reference), `partial` (ran but didn't fully resolve -- mirrors `cloudgraph`'s own existing honesty-about-uncertainty pattern: a `CloudPlan` search that exhausted `maxHops` without confirming a path is not the same as a clean failure, and must not be recorded as one).
- **One `cloud_runs` row = one execution of one scenario against one account scope.** Multi-hop results (an entire `CloudPath`) live inside that single row's `result` column. Multi-*account* fan-out (`RunMultiAccount`) becomes multiple `cloud_runs` rows, one per account -- grouping/aggregating those is sub-project #4's job, not this table's.

## Store functions

New file `orchestrator/internal/db/cloudrun_store.go`, package `db` (mirrors `rwevidence_store.go`'s conventions -- validate before writing, clear error wrapping with the run's identifying fields in the message):

```go
func InsertCloudRun(ctx context.Context, pool *pgxpool.Pool, run *cloudrun.CloudRun) error
func UpdateCloudRunStatus(ctx context.Context, pool *pgxpool.Pool, id string, status cloudrun.Status, result json.RawMessage, errMsg string) error
func GetCloudRun(ctx context.Context, pool *pgxpool.Pool, id string) (*cloudrun.CloudRun, error)
func ListCloudRuns(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*cloudrun.CloudRun, error)
```

- `InsertCloudRun`: caller supplies `run.ID` already generated (matching `scenario_runs`' existing convention of generating the run ID in Go before insert, so it's known immediately to whatever triggers the run -- e.g. for returning it in an API response before the run even starts).
- `UpdateCloudRunStatus`: the one call sub-project #2's execution harness makes at completion. Sets `completed_at = NOW()` only when `status` is one of the three terminal values (`completed`/`failed`/`partial`); leaves it null when transitioning to `running`. `result`/`errMsg` are both optional (empty/nil is valid -- e.g. a transition to `running` has neither).
- `GetCloudRun`/`ListCloudRuns`: straightforward reads. `ListCloudRuns` takes only `limit` (ordered `started_at DESC`) -- no filter parameters, per the Scope section above.

## Error handling

- `InsertCloudRun`/`UpdateCloudRunStatus` return a plain Go `error` on any SQL failure (constraint violation, connection failure) -- no panics, no silent swallowing. A caller passing an invalid `Status` or `Provider` value gets the database's own CHECK-constraint error surfaced, not a pre-validated application-level rejection -- unlike `rwevidence`'s `CapabilityResult.Valid()` pre-check, there's no equivalent domain-level validation to add here since `cloudrun.Status`/the provider string are simple enum-shaped values the Go compiler and the DB constraint already jointly guard; a second validation layer would be redundant for this sub-project's scope.
- `GetCloudRun` on a missing ID returns `(nil, pgx.ErrNoRows)` (or wraps it) -- the standard pgx idiom, not a custom "not found" sentinel, matching how other single-row lookups in this codebase behave.

## Testing

Following `content_registry_schema_test.go`'s exact harness (`package db_test`, `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {...})` -- a real Postgres, not mocked):

1. **Schema idempotency** -- running the `cloud_runs` migration twice produces no error.
2. **CHECK constraints** -- `cloud_runs_status_check`/`cloud_runs_provider_check` reject every invalid value and accept every valid one (table-driven).
3. **Insert/Get round-trip** -- `InsertCloudRun` then `GetCloudRun` preserves every field exactly, including a non-trivial `Result` JSON blob (proves `json.RawMessage` round-trips through `jsonb` without reformatting-induced mismatches).
4. **Status transitions** -- `UpdateCloudRunStatus` to each of the three terminal statuses sets `completed_at` to a non-null, recent timestamp; a transition to `running` leaves `completed_at` null.
5. **List ordering and limit** -- `ListCloudRuns` returns rows newest-`started_at`-first, respects the `limit` argument exactly (insert N rows, request limit < N, assert the returned count and that it's the N most recent).
