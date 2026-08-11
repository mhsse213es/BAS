# Scheduled Assessments: Edit — Design

## Problem

Once a Scheduled Assessment is created, nothing about it can change. The only per-schedule action is Cancel (`Store.DisableSchedule`, sets `enabled=false` permanently, one-way — no re-enable path exists either). Changing a schedule's scenario, mode, targets, recurrence, or timezone today means cancelling it and creating an entirely new one from scratch, losing `LastOccurrenceAt`/`LastSpawnedJobID` continuity.

## Why this isn't a pure oversight-fix

`jobs.Schedule`'s Mode/ApprovedBy/ApprovedAt/ApprovalVersion/Reason fields exist specifically because Telemetry-mode schedules carry a standing authorization captured once at creation — the code comment is explicit: "schedules are immutable, so this can never go stale." Editing breaks that invariant unless the edit path re-establishes the authorization against the *new* configuration, not silently keeps the old approval attached to changed targets/recurrence/scenario.

The actual authorization mechanic (confirmed from `CreateScheduledAssessment`, `orchestrator/internal/api/scheduled_assessment_handlers.go:107-124`) is simpler than a review workflow: the person creating (or, per this design, editing) a Telemetry-mode schedule must **already hold** `CanApproveRemediation` themselves and supply a non-empty `reason` — the backend stamps them as approver on the spot (`ApprovedBy = claims.UserID`, `ApprovedAt = now`). There is no separate approval-request queue to design around.

## Goals

- Every field of an existing schedule (scenario, mode, targets, recurrence, timezone, end date, concurrency limit) is editable in one place.
- Editing a Telemetry-mode schedule (or changing a schedule *to* Telemetry mode) requires the editor to hold `CanApproveRemediation` and supply a reason, exactly like creation — the approval is re-stamped fresh, `ApprovalVersion` increments so the history shows a re-approval happened, not the original one persisting.
- Editing a Posture-mode schedule (or changing *to* Posture mode) needs no authorization; approval fields are cleared.
- Saving an edit always re-enables the schedule (`Enabled = true`), regardless of whether it was Cancelled beforehand — editing a Cancelled schedule is how you revive it.
- Edit reuses the existing Create wizard, prefilled with the schedule's current values, rather than a second UI.

## Non-goals

- No change to how a Job is spawned from a Schedule occurrence (`Store.MarkScheduleOccurrenceHandled`, the poll-and-spawn logic) — editing only ever affects **future** spawns. A Job already spawned from a prior occurrence is a fully independent row, untouched by editing the Schedule it came from.
- No partial/field-level PATCH semantics — the update endpoint takes the same full request shape `CreateScheduledAssessment` already does (a complete replacement of the editable fields), not a sparse diff.
- No new approval-request/review workflow. The authorization rule is unchanged from what creation already enforces (editor holds `CanApproveRemediation` + supplies a reason) — this design does not add multi-party approval.

## Design

### Backend

A new `Store.UpdateSchedule(ctx, id string, sch Schedule) (Schedule, error)` in `internal/jobs/schedule.go`, structurally mirroring `CreateSchedule`'s `INSERT` (same column list) as an `UPDATE ... WHERE id = $N`, over every editable column: `payload, agent_ids, group_ids, day_of_week, time_of_day, timezone, enabled, recurrence_type, run_at, day_of_month, end_date, concurrency_limit, mode, approved_by, approved_at, approval_version, reason`. `id`, `type`, `created_by`, `created_at` are immutable identity/audit fields and are never touched by an update.

A new `PUT /api/scheduled-assessments/{id}` handler (`UpdateScheduledAssessment`), same permission as create (`CanExecuteRemediation`), reusing `CreateScheduledAssessment`'s exact request struct and recurrence-type validation block. New logic specific to update:
1. Fetch the existing schedule via `GetSchedule` (404 if not found) — needed to read its current `ApprovalVersion` before incrementing.
2. If `req.Mode == "telemetry"`: require `CanApproveRemediation` + non-empty `reason` (identical gate to creation); set `ApprovedBy = claims.UserID`, `ApprovedAt = now`, `ApprovalVersion = existing.ApprovalVersion + 1`.
3. If `req.Mode == "posture"`: `ApprovedBy/ApprovedAt/Reason` reset to zero-values, `ApprovalVersion = 0`.
4. `Enabled = true` unconditionally.
5. Call `UpdateSchedule`, audit-log `jobs.schedule.update` (mirroring the existing `jobs.schedule.create` entry's fields, plus the previous/new `ApprovalVersion`).

### Frontend

Every schedule row in `renderScheduledAssessmentsList()` gains an "Edit" button, shown regardless of `Enabled`/Cancelled status (unlike the existing Cancel button, which only shows when Enabled). Clicking it calls a new `openSchedWizardForEdit(id)` — looks up the schedule in the already-loaded `SCHED.schedules` array by ID, then does everything `openSchedWizard()` already does (reset selection state, fetch fresh groups/agents, open the overlay, jump to step 1) plus prefilling every field from the schedule's current values: `SCHED.selGroups`/`SCHED.selAgents` from `GroupIDs`/`AgentIDs`, the scenario/mode selects and recurrence/timezone/end-date/concurrency/reason inputs from the schedule's `Payload` (parsed) and direct fields. A new `SCHED.editingId` (`null` when creating, the schedule's ID when editing) is set here; `openSchedWizard()` explicitly resets it to `null`.

The wizard's `<h3>` title (currently static "New Scheduled Assessment" text, gains an `id`) and the final step's button label switch based on `SCHED.editingId` — "Edit Scheduled Assessment" / "Save Changes" vs. "New Scheduled Assessment" / "Create Schedule".

`submitScheduledAssessment()` branches on `SCHED.editingId`: `null` keeps today's `POST /api/scheduled-assessments` path unchanged; non-null sends the same payload via `PUT /api/scheduled-assessments/{editingId}` and shows "Scheduled assessment updated" instead of "created". Every other part of the wizard (`schedBuildPayload`, `renderSchedReview`, the Telemetry authorization checkbox step, recurrence-type panes) is reused completely unchanged — the review step's authorization warning already re-derives from whatever `#sched-mode`/`#sched-reason` currently hold, so it naturally re-prompts for authorization when editing a schedule into or within Telemetry mode.

## Testing

Go tests for `UpdateSchedule` (persists every editable field correctly, leaves identity fields untouched) and `UpdateScheduledAssessment` (editing to Telemetry mode requires `CanApproveRemediation` + reason and stamps a fresh `ApprovedBy`/incremented `ApprovalVersion`; editing to Posture mode clears approval fields; editing a Cancelled schedule sets `Enabled = true`; 404 for an unknown schedule ID). Frontend: `node --check` plus manual QA (flagged as deferred, same caveat as every other frontend task this session): editing a Posture schedule's targets and recurrence persists correctly with no authorization prompt; editing a Telemetry schedule re-prompts for authorization and updates `ApprovalVersion`; editing a Cancelled schedule re-enables it; the wizard correctly prefills every field when opened for edit.
