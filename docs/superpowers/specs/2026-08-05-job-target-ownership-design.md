# Job-Target Ownership (Phase 8) — Design

**Date:** 2026-08-05
**Status:** Approved, ready for implementation plan
**Sub-project:** 12th sub-project of the Endpoint Health & Remediation initiative — original Phase 8 of the 10-phase Fleet Job Engine proposal (Sub-project 6), the second of the two remaining original phases (Phase 9, SLA, depends on both this and Phase 7).

## Problem

Sub-project 11 (Phase 7) gave the system a way to *alert* when a `JobTarget` fails or gets deferred, but nothing ties that alert to a specific accountable person. A `target_failed` notification currently broadcasts to every connected browser and every configured webhook — everyone's problem is no one's problem. Phase 8 closes that gap: a failed/deferred target can be assigned an owner, that owner is notified on assignment (reusing Phase 7's delivery pipeline), and an owner can find everything currently assigned to them across every job.

## Scope

**In scope:** an `owner_id`/`assigned_at` pair on `JobTarget`, a manual assignment endpoint, an `EventTargetAssigned` notification on assignment, a cross-job "my assigned targets" query endpoint.

**Out of scope (explicitly deferred):** auto-assignment by rule (round-robin, `env_label`-to-team mapping — no team concept exists in this codebase at all, see Grounding below), job-level ownership (only `JobTarget`s are owned, not whole `Job`s), any notion of reassignment history/audit trail beyond the single current `owner_id` (the existing `audit_logs` table already records the assign action itself via the standard `h.auditLog` call, so a dedicated ownership-history table would be redundant), SLA clocks (that's Phase 9, which consumes this phase's `owner_id`/`assigned_at` but is not designed here).

## Grounding

A fresh read of the schema (`internal/db/postgres.go`) confirmed there is no existing ownership/assignee/team concept anywhere in this codebase to build on:
- `users` has only `id, username, password_hash, role (analyst/admin/...), is_active, tenant_id` — `role` is a permission tier, not a team or assignment construct.
- `remediation_requests` has `requested_by`/`approved_by` (who *took* an action, at a point in time) but nothing for "who's responsible going forward."
- `agents.env_label` (free-text, e.g. `"Production"`) is the only existing grouping dimension, and Sub-project 7 explicitly declined to use it for group-scoped maintenance freezes — the same reasoning applies here: no rule-based auto-assignment without first defining what a "team" even is in this system, which is out of scope.
- `job_targets` (`internal/db/postgres.go:1269-1281`) has `id, job_id, agent_id, state, ref_id, error, retry_count, max_retries, created_at, started_at, completed_at` — no owner column.

None of `requested_by`/`approved_by`/`created_by` anywhere in this codebase carry a foreign-key constraint to `users.id` — they're bare strings trusting the auth layer's `claims.UserID`. `owner_id` follows the same convention for consistency, not because FK integrity doesn't matter, but because it's the established local pattern.

## Data Model

Purely additive to the existing `job_targets` table — no new table, matching this initiative's dominant precedent (`scheduled_at` in Sub-project 7, `continuous_validation` in Sub-project 8):

```sql
ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS owner_id    text NOT NULL DEFAULT '';
ALTER TABLE job_targets ADD COLUMN IF NOT EXISTS assigned_at timestamptz;
CREATE INDEX IF NOT EXISTS idx_job_targets_owner_id ON job_targets (owner_id) WHERE owner_id != '';
```

`owner_id = ''` means unassigned (the same empty-string-as-absent convention `error`/`ref_id` already use on this exact table — not a real SQL NULL). `assigned_at` is `NULL` when unassigned, set to `NOW()` on assignment, and cleared back to `NULL` when ownership is cleared (`owner_id` set back to `''`).

## Assignment API

**`POST /api/job-targets/{targetId}/assign`** — body `{"ownerId": "user-123"}`. An empty `ownerId` clears ownership. `CanExecuteRemediation` (Analyst+Admin — the same tier as executing the remediation itself; deciding who investigates a failure isn't a heavier action than running the fix that produced it).

New `jobs.Store` method, alongside the existing `MarkTargetTerminal`/`MarkTargetDeferred` family in `internal/jobs/store.go`:

```go
// SetTargetOwner assigns or clears a JobTarget's owner. ownerID == "" clears
// ownership and nulls assigned_at back out. Returns the updated JobTarget,
// or pgx.ErrNoRows if targetID doesn't exist (via QueryRow+Scan on the
// UPDATE ... RETURNING, same no-match-is-ErrNoRows behavior every other
// QueryRow-based lookup in this codebase already relies on).
func (s *Store) SetTargetOwner(ctx context.Context, targetID, ownerID string) (JobTarget, error) {
    // UPDATE job_targets SET owner_id=$1,
    //   assigned_at = CASE WHEN $1 = '' THEN NULL ELSE NOW() END
    // WHERE id=$2 RETURNING ...
}
```

This is a direct API-handler-driven mutation, not part of `Dispatcher.Tick()`'s dispatch loop — same shape as `CancelJob`, which also calls a `Store` method directly from `internal/api` rather than going through the tick/notify machinery Phase 7 built for state-transition events.

## Notification Integration

`notifications.EventType` gains an 8th value, `EventTargetAssigned` (`"target_assigned"`), `SeverityInfo`. `internal/api`'s new `AssignJobTarget` handler emits it directly — no `NotifyFn`/`Dispatcher` involvement at all, since assignment isn't a `Tick()`-driven state transition (`internal/api` already imports `internal/notifications` directly for exactly this reason — `CancelJob`, Sub-project 11, established the same pattern):

```go
func (h *Handler) AssignJobTarget(w http.ResponseWriter, r *http.Request) {
    targetID := chi.URLParam(r, "targetId")
    var req struct{ OwnerID string `json:"ownerId"` }
    if json.NewDecoder(r.Body).Decode(&req) != nil {
        jsonError(w, "invalid body", http.StatusBadRequest)
        return
    }
    target, err := h.jobsStore.SetTargetOwner(r.Context(), targetID, req.OwnerID)
    if errors.Is(err, pgx.ErrNoRows) {
        jsonError(w, "job target not found", http.StatusNotFound)
        return
    }
    if err != nil {
        jsonError(w, err.Error(), http.StatusInternalServerError)
        return
    }
    if req.OwnerID != "" && h.notifications != nil {
        h.notifications.Emit(r.Context(), notifications.Event{
            Type: notifications.EventTargetAssigned, JobID: target.JobID, TargetID: target.ID, AgentID: target.AgentID,
            Severity: notifications.SeverityInfo, Message: "assigned to " + req.OwnerID,
            Metadata: map[string]any{"ownerId": req.OwnerID},
        })
    }
    h.auditLog(r, "jobs.target_assigned", targetID, map[string]any{"ownerId": req.OwnerID}, "ok")
    respond(w, map[string]any{"target": target})
}
```

Clearing ownership (`req.OwnerID == ""`) does not emit a notification — there's no one to alert about an un-assignment; `h.auditLog` still records it for the compliance trail regardless of direction.

## Query Surface

**`GET /api/job-targets?ownerId=X&state=Y`** — the first query in this codebase that lists `JobTarget` rows across every job rather than scoped to one (`ListTargets(ctx, jobID)` remains job-scoped and unchanged). `ownerId` is required; `state` is an optional filter, mirroring `notifications.ListFilter`'s shape. `CanExecuteRemediation`.

```go
func (s *Store) ListTargetsByOwner(ctx context.Context, ownerID, state string) ([]JobTarget, error) {
    // SELECT ... FROM job_targets WHERE owner_id = $1 [AND state = $2] ORDER BY assigned_at DESC
}
```

No default state filtering is baked into the backend — it returns every target ever assigned to that owner, terminal or not. The `state` param lets a client cheaply ask for just `state=failed` ("my open work") without the backend guessing what "my queue" should mean.

## Testing

- **`SetTargetOwner`** — container-backed: assigning sets both `owner_id` and `assigned_at`; clearing (`ownerID=""`) resets `owner_id` to `""` and `assigned_at` back to `NULL`.
- **`ListTargetsByOwner`** — container-backed: returns only the given owner's targets across multiple distinct jobs; the `state` filter narrows correctly; an owner with zero assignments gets an empty slice, not an error.
- **`AssignJobTarget` handler** — container-backed, same inspection pattern as Sub-project 11's `TestCancelJob_EmitsJobCancelledNotification`: assigning a non-empty owner emits exactly one `EventTargetAssigned` (verified via `notifStore.List`); clearing ownership emits nothing.
- **RBAC matrix** — 2 new rows in `internal/api/rbac_matrix_test.go`: `POST /api/job-targets/{targetId}/assign` and `GET /api/job-targets`, both `CanExecuteRemediation`.

## Dependencies

Builds on Sub-project 6's `jobs.Store`/`JobTarget` (`internal/jobs`) and Sub-project 11's `notifications.Service`/`Event`/`EventType` (`internal/notifications`) and the `internal/api` ↔ `internal/notifications` direct-import bridge `CancelJob` established. No dependency on the SLA phase (9) — this phase produces `owner_id`/`assigned_at` as data Phase 9 will consume, but doesn't design or assume anything about how Phase 9 uses it.
