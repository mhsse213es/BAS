# Initiative Layer — Design

**Status:** approved by user in chat, pending written-spec review
**Origin:** Fleet Job Engine, Sub-project 6 (2026-08-03) — user proposed a `Campaign → Job → Target` hierarchy above the existing `Job`/`JobTarget` model as future work; deferred at the time. Picked up now as the last item in the Endpoint Health & Remediation initiative besides Phase 9 (SLA), which was not selected this round.

**Naming note:** the concept was designed and approved under the working name "Campaign," matching the user's original 2026-08-03 wording. Before writing the implementation plan, grounding in the current codebase surfaced that `campaigns` (table), `/api/campaigns*` (routes), and `CanCreateCampaign`/`CanStopCampaign` (permissions) already exist and mean something unrelated — a BAS scenario-execution run (Campaign Group Targeting, 2026-08-10, ADR-016: `scenario_id`/`mode`/`subset`/`targets`, start/stop/pause/resume). Reusing "Campaign" would have collided outright (`CREATE TABLE IF NOT EXISTS campaigns` would have silently no-op'd against the wrong schema) and would have been confusing even without the collision — two unrelated concepts sharing one noun. Renamed to **Initiative** throughout. Every design decision below is unchanged from what was approved in chat; only the noun changed.

## Problem

`internal/jobs` (Job Engine, Sub-projects 6–12) tracks one logical fleet-wide operation per `Job` row — e.g. "apply remediation X to these N agents," or "run scheduled assessment Y." Three job types exist in production today: `batch_remediation`, `bas_revalidation`, `scheduled_assessment`.

A real security initiative is usually made of several such operations spread over time and possibly of different types — e.g. "Q3 2026 Patch Compliance" = a `scheduled_assessment` job, followed by one or more `batch_remediation` jobs for whatever it found failing, followed by `bas_revalidation` jobs confirming the fixes held. Today these are unrelated `Job` rows with no persistent link between them. Audspect cannot answer: what initiative did these jobs belong to, which remediation jobs came from which assessment's failures, or what the initiative's overall status is.

## Scope

**In scope (this sub-project):**
- `internal/initiatives` package: `Initiative` domain type, lifecycle, aggregation.
- `initiatives` table + `jobs.initiative_id` column (migration).
- REST API: create/list/get/close/archive an initiative; assign/reassign/detach a job's initiative membership.
- `audit_logs` integration for every membership change and lifecycle transition.
- Tests (package-level + handler-level).

**Explicitly out of scope (deferred, not this sub-project):**
- Any `wwwroot` UI — initiatives list/detail/progress views, job-creation-screen initiative picker. Follow-on sub-project once this API is stable and consumed.
- Auto-orchestration ("Initiative Workflow") — an initiative defining dependencies between jobs and auto-creating follow-on jobs when a prior one completes. This sub-project is a relationship/aggregation model only; jobs remain independently, manually executed. Workflow is a clean future extension once the aggregation model has proven out, not a prerequisite for it.
- Reopening a closed/archived initiative — no reverse lifecycle transition in V1. If governance later needs it, that's a separate decision.
- Initiative membership at any level below `Job` (targets, results, findings) — the initiative aggregates whatever the Job itself produces; it never reaches into execution detail. Keeps `Initiative → Job → (execution/results, unchanged)` rather than `Initiative → Job execution → individual findings`.
- Phase 9 (SLA) — the other item deferred from Sub-project 6's original 10-phase proposal. Not addressed here; the user explicitly did not select it this round.

## Data model

```sql
CREATE TABLE IF NOT EXISTS initiatives (
    id          text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    state       text        NOT NULL DEFAULT 'active', -- active | closed | archived
    created_by  text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT NOW(),
    closed_at   timestamptz,
    archived_at timestamptz
);

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS initiative_id text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_jobs_initiative_id ON jobs (initiative_id) WHERE initiative_id <> '';
```

`id` uses the same `gen_random_uuid()::text` default as `jobs.id`/`job_targets.id`. `initiative_id = ''` means unassigned — same convention `job_targets.owner_id` already uses for "no owner" (Sub-project 12). No FK constraint, matching this codebase's established convention for these lightweight text-reference columns (`requested_by`/`approved_by`/`created_by`/`owner_id` are all unconstrained text elsewhere in the schema).

### Lifecycle

Strict forward-only funnel, no reverse transition:

```
active ──close──> closed ──archive──> archived
```

- `active`: jobs can be assigned/reassigned/detached freely.
- `closed`: the operator has declared the initiative done. New assignments are rejected (409); detach is still allowed (correcting a mistaken membership shouldn't require reopening the whole initiative).
- `archived`: read-only historical state. Requires the initiative to already be `closed` — archiving directly from `active` is rejected (409). This forces the explicit "I'm declaring this initiative complete" step before it can be moved out of the working view.

### Progress (derived, not stored)

Computed on read, same precedent as `jobs.ComputeProgress` (Sub-project 10), `models.ComputeScore`, `driftanalytics.ComputeDriftStats` — no persisted counters:

```sql
SELECT state, COUNT(*) FROM jobs WHERE initiative_id = $1 GROUP BY state
```

Bucketed by `Job.State` (`requested`/`running`/`completed`/`partial`/`failed`/`cancelled` — the existing `jobs.JobState*` constants, unchanged). `PercentComplete` is a `float64`, matching `jobs.JobProgress.PercentComplete`'s existing type exactly: (terminal job count) / total * 100, where terminal = `completed|partial|failed|cancelled` — same terminal-based-not-success-based semantics `JobProgress.PercentComplete` already uses.

Progress is **never** the same field as lifecycle state. An initiative showing 100% job progress is not automatically `closed` — new jobs can be tagged in later while `active`, and the operator alone decides when the initiative itself is done. This was the core reason for an explicit lifecycle rather than a purely derived one: `all-jobs-terminal` cannot silently flip an initiative from "done" back to "in progress" just because a new job got tagged in next week.

## Components

**`internal/initiatives` (new package, mirrors `internal/jobs`'s shape — plain `Store` over `*pgxpool.Pool`, zero cross-package imports, zero business rules beyond its own lifecycle funnel):**

```go
type Initiative struct {
    ID          string
    Name        string
    Description string
    State       string // active | closed | archived
    CreatedBy   string
    CreatedAt   time.Time
    ClosedAt    *time.Time
    ArchivedAt  *time.Time
}

type Progress struct {
    Total           int
    Requested       int
    Running         int
    Completed       int
    Partial         int
    Failed          int
    Cancelled       int
    PercentComplete float64
}

func (s *Store) Create(ctx context.Context, name, description, createdBy string) (Initiative, error)
func (s *Store) Get(ctx context.Context, id string) (Initiative, error)
func (s *Store) List(ctx context.Context, state string) ([]Initiative, error) // state == "" means all
func (s *Store) Close(ctx context.Context, id string) (Initiative, error)     // rejects if not currently active
func (s *Store) Archive(ctx context.Context, id string) (Initiative, error)   // rejects if not currently closed
func (s *Store) ComputeProgress(ctx context.Context, id string) (Progress, error)
```

**`internal/jobs` (one additive method, no changes to existing dispatch/state/notify/schedule/freeze code):**

```go
// SetJobInitiative assigns, reassigns, or clears (initiativeID == "") a
// job's initiative membership. Pure plumbing -- no rule about initiative
// state lives here, matching SetTargetOwner's shape; the caller
// (internal/api) enforces "only an active initiative accepts new members."
func (s *Store) SetJobInitiative(ctx context.Context, jobID, initiativeID string) (Job, error)
```

`Job` gains `InitiativeID string` (json tag-free, matching every other field on that type per existing convention).

**`internal/api/initiative_handlers.go` (new file — the integration layer enforcing cross-package rules, same role `job_dispatch.go` already plays gluing `internal/jobs` to `internal/remediation`/`internal/notifications`):**

| Method | Path | Behavior |
|---|---|---|
| POST | `/api/initiatives` | Body `{name, description}`. Creates with `state=active`. |
| GET | `/api/initiatives` | Optional `?state=active\|closed\|archived`. |
| GET | `/api/initiatives/{initiativeId}` | Initiative + `ComputeProgress` + lightweight member-job list (`id`, `type`, `state`, `createdAt`, `completedAt` per job — no target-level nesting). |
| POST | `/api/initiatives/{initiativeId}/close` | `active → closed`. 409 if not currently active. |
| POST | `/api/initiatives/{initiativeId}/archive` | `closed → archived`. 409 if not currently closed. |
| PATCH | `/api/jobs/{jobId}/initiative` | Body `{"initiativeId": "..."}` to assign/reassign, `{"initiativeId": ""}` to detach. Assigning to a non-`active` initiative → 409. Assigning to a nonexistent initiative → 404. Detach always allowed. |

All 6 endpoints reuse `CanExecuteRemediation` (Analyst+Admin) — same tier as creating the underlying jobs, no new permission introduced. This mirrors the initiative's established default (new permissions only introduced when a genuinely new risk class appears, e.g. `CanApproveRemediation` for freezes/webhooks because those can silently affect the whole fleet); initiative create/close/archive/assign is judged operational, not that category of risk.

## Audit trail

Every membership change and lifecycle transition writes one row to the existing `audit_logs` table via the existing `h.auditLog(r, action, resource, detail, outcome)` helper (`internal/api/audit.go`) — no new mechanism:

| Action | Resource | Detail |
|---|---|---|
| `initiatives.job_assigned` | initiative ID | `{jobId, previousInitiativeId}` |
| `initiatives.job_detached` | initiative ID | `{jobId}` |
| `initiatives.closed` | initiative ID | `{}` |
| `initiatives.archived` | initiative ID | `{}` |

`actor_id` is resolved from the JWT context by `auditLog` itself, per every other handler already writing to this table.

## Error handling

- Assign to non-`active` initiative → 409, body includes the initiative's current state.
- Assign to nonexistent initiative ID → 404.
- Close a non-`active` initiative → 409.
- Archive a non-`closed` initiative → 409.
- Detach (`initiativeId: ""`) always succeeds regardless of the (former) initiative's state.
- None of this touches `internal/jobs`' existing dispatch/status/notify/schedule/freeze code paths — purely additive column + one new plumbing method.

## Testing

- `internal/initiatives`: `testcontainers`-backed package tests for `Create`/`Get`/`List` (with and without state filter)/`Close`/`Archive`, including the funnel-order rejections (`Archive` before `Close`, `Close` on an already-closed initiative), and `ComputeProgress` across a mixed set of job states (including zero-jobs and all-terminal cases).
- `internal/jobs`: one new test for `SetJobInitiative` (assign, reassign, clear).
- `internal/api`: handler tests for all 6 endpoints, covering the 409/404 paths above and asserting an `audit_logs` row is written after each assign/detach/close/archive. `rbac_matrix_test.go`'s `routeMatrix` table gains 6 new rows (`tierPermission`, `auth.CanExecuteRemediation`) — that file's own `TestRBACMatrix_NoDrift` fails the build otherwise, since every route mounted in `routes.go` must appear there.

## Spec self-review

- **Placeholder scan:** none found — every field, endpoint, and SQL statement above is concrete.
- **Internal consistency:** lifecycle funnel (`active → closed → archived`, no reverse) is stated once and referenced consistently in the error-handling table; progress semantics are stated once (terminal-based `PercentComplete`, matching `JobProgress`) and not contradicted elsewhere. Naming is consistently "Initiative" throughout after the rename.
- **Scope check:** single sub-project, backend/API only, no UI — confirmed focused enough for one implementation plan. UI and auto-orchestration are named explicitly as separate future sub-projects rather than left ambiguous.
- **Ambiguity check:** "can an initiative be archived directly from active" — resolved explicitly (no, must pass through closed). "Does detach require the initiative to be active" — resolved explicitly (no, always allowed). "What RBAC tier" — resolved with an explicit proposal and rationale, flagged as the one point most likely to get revised on review. "Does `initiatives` collide with any existing table/route" — checked this pass; confirmed clear (only `campaigns` collided, which is why the rename happened).
