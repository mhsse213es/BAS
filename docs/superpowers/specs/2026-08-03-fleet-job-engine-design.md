# Fleet Job Engine (Sub-project 6, Phases 1+2) — Design

## 1. Problem statement

Sub-projects 4 and 5 built a proven single-endpoint remediation pipeline (dispatch a fix, verify it, optionally roll it back, optionally BAS-validate the control) but explicitly deferred everything that requires acting on *many* endpoints at once: batch execution, scheduled/maintenance-window runs, fleet-wide progress, and recurring revalidation. Each of those needs some notion of "one logical operation, many independently-tracked targets" — and the codebase has already reinvented a version of that primitive three separate times, none of them reusable:

- `internal/connector.Scheduler` — a ticker-driven threat-intel sync loop, single global target, no per-target state.
- `exercise.PollScheduler` — a bare `Start(tick func(ctx))`/`Stop()` ticker interface, reused 5× in `main.go` (verify-sync, search indexing, OpenAEV sync, exercise polling, variant-sweep polling). A useful low-level tick primitive, but carries no job/target persistence itself.
- `internal/api/revalidation.go`'s `StartRevalidationLoop` — a 2-minute ticker polling `finding_tickets` for ITSM-resolved tickets, dispatching one re-run each, gated by a `revalidation_dispatched_at` flag column so it never double-fires. Structurally a one-off, single-purpose "job with a dispatched flag," hand-rolled.
- `internal/vexsweep` — the closest real precedent: a persisted `Sweep` row tracks one agent's sequential progress through many techniques, survives reloads/crashes, and is advanced by a `Dispatcher.Tick()` called from an `exercise.PollScheduler`. Proves the tick-driven advance-by-one-step pattern works well in this codebase, but is scoped to one agent per sweep — it has no notion of fanning out to *many* agents under one logical operation.

**Goal of this sub-project:** build one generic, persisted `Job`/`JobTarget` model — infrastructure, not a remediation feature — and prove it with exactly one real consumer: batch remediation (dispatch one remediation catalog entry to N agents, track each independently). Every later capability (Tier 3 maintenance-window scheduling, recurring BAS revalidation, drift history, notifications, ownership, SLA, exceptions, a Campaign layer above jobs) becomes a separate future sub-project that builds on this engine rather than reinventing it — this cycle does not build any of those.

## 2. Scope

**In scope (Phases 1+2 of the original 10-phase proposal):**
- Generic `internal/jobs` package: `Job`/`JobTarget` types, `jobs`/`job_targets` tables, a `Tick()`-driven dispatch loop.
- One real consumer: batch remediation, fanning out an existing single-endpoint remediation to an explicit list of agents.

**Explicitly out of scope, deferred to future sub-projects:**
- Tier 3 (scheduled/maintenance-window remediation) — a job creation path with `ScheduledAt` in the future; structurally trivial once this engine exists, but not built this cycle.
- Persisted progress counters as a dedicated UI feature (`Total`/`Completed`/`Succeeded`/`Failed`/`Cancelled` columns) — this cycle computes `Job.State` by aggregating `JobTarget.State` on read (same lazy-aggregation style as `GetAgentRiskSummary`), not via dedicated rollup columns.
- Continuous/recurring BAS revalidation (T+24h/7d/30d follow-up jobs) and drift history (a time series of pass/fail per check, not just the latest).
- Job-event notifications (job started/completed/failed/partially-failed/timed-out).
- Ownership (team/individual assignment on a job) and SLA (deadline + breach detection).
- Exceptions (maintenance-freeze exclusion of specific targets from an otherwise-fleet-wide job).
- A Campaign layer aggregating multiple jobs under one named initiative.
- Caldera as a job-target executor — no change; `internal/remediation`'s existing ART-only dispatch is untouched.
- Migrating any of the three existing scheduler-shaped mechanisms (`connector.Scheduler`, the revalidation loop, `vexsweep`) onto this engine. They stay exactly as they are; this is new infrastructure for new work, not a refactor of shipped code.
- Migrating Sub-project 4's existing single-endpoint remediation dispatch onto `Job`/`JobTarget`. It stays untouched, unchanged, and fully independent of this engine.

## 3. Architecture

New sibling package `internal/jobs`, mirroring how `internal/remediation` sits alongside `internal/actions`: same-shaped conventions (status vocabulary, `CreatedBy`, audit-log calls) without sharing schema or execution code with anything else.

`internal/jobs` owns exactly two things: the `Job`/`JobTarget` persistence layer, and a generic `Tick(ctx)` that advances *any* running job by dispatching some of its still-`pending` targets, each via an injected per-type dispatch function — the same dependency-injection shape `vexsweep.Dispatcher` already uses (`SetDispatch(fn)`, to avoid an `internal/jobs` → `internal/api` import cycle). `internal/jobs` itself never imports `internal/remediation` or `internal/api`; it knows nothing about what a "batch_remediation" job actually does — that's supplied by `internal/api` at wiring time in `main.go`, keyed by `Job.Type`.

`internal/api` supplies the one dispatch function this cycle needs: for `Type:"batch_remediation"`, dispatching a `JobTarget` means calling the *exact same* code Sub-project 4's `ExecuteRemediation` handler already calls for a single endpoint — pre-flight (`OSSupported`, already-compliant check), `INSERT remediation_requests`, `dispatchRemediationStep`. The created `remediation_requests.id` is stored on the `JobTarget` as `RefID`. From then on, that target's outcome is *only* ever updated by polling `remediation_requests.status` for that `RefID` on a later tick — `internal/jobs` never receives or interprets a scenario result directly, and Sub-project 4's fix→verify→rollback continuation hooks in `remediation_continuation.go` are not touched at all.

The `Tick()` loop is driven by a `main.go`-constructed `exercise.PollScheduler` (`jobsScheduler := exercise.NewPollScheduler(5 * time.Second)`, the same interval already used for `exScheduler`/`vexSweepScheduler`) — no new ticker primitive.

## 4. Data model

```go
// internal/jobs/types.go

package jobs

import (
	"encoding/json"
	"time"
)

const (
	JobStateRequested = "requested"
	JobStateRunning   = "running"
	JobStateCompleted = "completed" // every target reached a terminal state, all succeeded
	JobStatePartial   = "partial"   // every target reached a terminal state, some failed
	JobStateFailed    = "failed"    // every target reached a terminal state, none succeeded
	JobStateCancelled = "cancelled"
)

const (
	TargetStatePending    = "pending"
	TargetStateDispatched = "dispatched"
	TargetStateCompleted  = "completed"
	TargetStateFailed     = "failed"
	TargetStateCancelled  = "cancelled"
)

type Job struct {
	ID          string
	Type        string // "batch_remediation" this cycle; extensible to future job types
	State       string
	Payload     json.RawMessage // type-specific; for batch_remediation: {"remediationId":"...","reason":"..."}
	CreatedBy   string
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
}

type JobTarget struct {
	ID          string
	JobID       string
	AgentID     string
	State       string
	RefID       string // remediation_requests.id created for this target, once dispatched
	Error       string
	RetryCount  int // column exists for forward-compat; no auto-retry logic built this cycle
	MaxRetries  int
	StartedAt   *time.Time
	CompletedAt *time.Time
}
```

```sql
-- internal/db/postgres.go, appended after technique_verification_runs' indexes

CREATE TABLE IF NOT EXISTS jobs (
	id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
	type         text        NOT NULL,
	state        text        NOT NULL,
	payload      jsonb       NOT NULL DEFAULT '{}',
	created_by   text        NOT NULL DEFAULT '',
	created_at   timestamptz NOT NULL DEFAULT NOW(),
	started_at   timestamptz,
	completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs (state);

CREATE TABLE IF NOT EXISTS job_targets (
	id           text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
	job_id       text        NOT NULL REFERENCES jobs(id),
	agent_id     text        NOT NULL,
	state        text        NOT NULL,
	ref_id       text        NOT NULL DEFAULT '',
	error        text        NOT NULL DEFAULT '',
	retry_count  int         NOT NULL DEFAULT 0,
	max_retries  int         NOT NULL DEFAULT 0,
	started_at   timestamptz,
	completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_job_targets_job_id ON job_targets (job_id);
CREATE INDEX IF NOT EXISTS idx_job_targets_state ON job_targets (state) WHERE state = 'pending';
```

`Job.State` starts at `requested` on creation and is thereafter written only by `Tick()` (§5) — never computed lazily on read. Each tick that touches a job recomputes its aggregate state from that job's current `JobTarget.State` values and persists it, so `GET /api/jobs/{jobId}` (§6) always returns an already-current stored value, no on-request aggregation. There are still no dedicated progress-count columns (`Total`/`Completed`/`Succeeded`/`Failed`) — that granularity is the explicitly-deferred Phase 4; this cycle only persists the single rolled-up `State` string.

## 5. Dispatch loop

```go
// internal/jobs/dispatch.go

// DispatchFn creates whatever a job type's one target execution actually
// is (e.g. a remediation_requests row + dispatchRemediationStep call) and
// returns a RefID to poll for that target's outcome, or an error if
// dispatch itself failed (agent offline, catalog entry missing, etc).
type DispatchFn func(ctx context.Context, job Job, target JobTarget) (refID string, err error)

// StatusFn resolves a dispatched target's current terminal-or-not state by
// reading whatever RefID points at (e.g. remediation_requests.status).
type StatusFn func(ctx context.Context, jobType, refID string) (state string, errText string, terminal bool)
```

`jobDispatchBatchSize = 20` (a package constant, same reasoning as `revalidationBatchSize = 10` — cap how many targets get dispatched in a single tick so a 200-target job doesn't flood the WS hub and every agent's local queue at once).

Each `Tick(ctx)`:
1. For every job in `running` or `requested` state, poll all of that job's `dispatched` targets via `StatusFn`; terminal ones get `State`/`Error`/`CompletedAt` written.
2. Across all running jobs, dispatch up to `jobDispatchBatchSize` still-`pending` targets via `DispatchFn`, in `JobTarget.CreatedAt`/`ID` order — oldest jobs' targets drain first.
3. Any job whose targets are now all terminal transitions from `requested`/`running` to `completed`/`partial`/`failed` per §4; `requested` jobs with at least one target already dispatched move to `running`.

## 6. API surface

- `POST /api/jobs/batch-remediation` — body `{remediationId, reason, agentIds: []string}`. Same tier-gated permission as Sub-project 4's single-endpoint `ExecuteRemediation` (Tier 1 catalog entry → `auth.CanExecuteRemediation`, Tier 2 → `auth.CanApproveRemediation`) — batch dispatch of a Tier 2 remediation to 50 machines is not a lesser action than dispatching it to one, so it gets no separate, weaker policy. Validates the catalog entry exists and isn't Tier 4 (manual-guidance entries can't be dispatched at all, same rule as the single-endpoint path) before creating the `Job` + one `JobTarget` per listed `agentId`.
- `GET /api/jobs/{jobId}` — the job plus every target's current state, `Job.State` returned exactly as `Tick()` last persisted it per §4 (Viewer+, read-only, same tier as `GetAgentRisk`).
- `POST /api/jobs/{jobId}/cancel` — marks the job `cancelled` and every still-`pending` target `cancelled`, stopping future ticks from dispatching them. Targets already `dispatched` are **not** force-cancelled (that WS message already went out) — an operator cancels an individual in-flight target the same way they always could, via Sub-project 4's existing `POST /api/remediation-requests/{requestId}/cancel` using the target's `RefID`. Requires the same permission as job creation.

## 7. Error handling

- **Dispatch failure for one target** (agent offline, catalog lookup fails) — `DispatchFn` returns an error, that `JobTarget` goes straight to `failed` with the error text, the rest of the batch is unaffected. Matches Sub-project 4's own per-target error handling exactly (this cycle doesn't add a new error taxonomy).
- **Job with zero targets reaching `completed`** — if every target lands in `failed`, the job's aggregate state is `failed`, not `completed`; `partial` is reserved for a genuine mix.
- **No lazy-timeout detection for `job_targets` this cycle** — a target's own `remediation_requests` row already gets Sub-project 4's existing `reapTimedOutRemediation` staleness handling on read; a stuck target surfaces there, and the job's own aggregate state naturally reflects it once that row's status resolves.

## 8. Testing

- `internal/jobs`: unit tests for `Tick()`'s dispatch cap (more than `jobDispatchBatchSize` pending targets → only that many get dispatched in one call), state aggregation (`completed`/`partial`/`failed`/`cancelled` derivation from various target-state combinations), and cancel semantics (pending → cancelled, dispatched → untouched).
- `internal/api`: `POST /api/jobs/batch-remediation` DB-backed tests reusing Sub-project 4's `registerFixtureScenario`/`startFakeAgent` helpers — creating a job with 3 agent IDs produces 3 `job_targets` rows and, after a manual `Tick()` call, 3 `remediation_requests` rows with matching `RefID`s. RBAC matrix rows for all 3 new routes.
- No new signature-verification or scenario-fixture edge cases beyond what Sub-project 4/5 already cover, since dispatch reuses their exact code path.

## 9. Explicitly deferred (future sub-projects)

Every item listed in §2's "out of scope" section is deferred, not cut — the schema and package boundary are designed so each slots in without a redesign: `Job.Payload` is already a free-form `jsonb` for new job types (e.g. `bas_revalidation`), `JobTarget.RetryCount`/`MaxRetries` columns already exist for when auto-retry logic is built, and `ScheduledAt` (Tier 3) is a one-column addition to `Job` with no change to the dispatch loop's shape (a job simply isn't eligible for tick-dispatch until `now >= ScheduledAt`).
