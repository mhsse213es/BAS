# Scheduled Assessments — Design

## Why

Security posture is not static — Windows updates, EDR policy changes, GPO edits, firewall rule changes, and new software deployments can silently break a control that passed validation last week. Without scheduled execution, BAS only proves "it worked when someone remembered to click Run." Enterprises expect recurring validation (daily smoke tests, weekly ATT&CK chains, monthly full assessments) without manual dependency.

BAS scheduling must be architecturally different from vulnerability-scanner scheduling. A vulnerability scanner discovers and checks; BAS *executes attacks* and generates real detections/alerts. Scheduling therefore must be tightly scoped and controlled, not "run everything against everything, hourly" — that produces alert storms and SOC fatigue, not continuous validation.

This feature is called **Scheduled Assessments** (never "Periodic Scan" — that name implies vulnerability-scanner behavior it does not have).

## Architecture: extend the existing Fleet Job Engine, don't build a second one

`internal/jobs` already provides a generic, persisted `Job`/`JobTarget` model with a `Tick()`-driven dispatch loop, and a recurring-schedule layer (`job_schedules`) that spawns fresh one-shot `Job`s on a timer, skipping a new occurrence if the previous spawn is still non-terminal. Today it has exactly one job type wired in end-to-end (`batch_remediation`, plus the event-triggered `bas_revalidation`).

Scheduled Assessments is a **new job type** (`scheduled_assessment`) on this same engine, plus targeted extensions to the schedule model where it's currently too narrow for this use case (weekly-only recurrence, no end date, no per-schedule concurrency, no group-based targeting, no execution-mode authorization). The dispatch loop, status polling, notifications, audit logging, maintenance freezes, and duplicate-run prevention are all reused unchanged. Nothing about the *execution* of a scenario run changes — a scheduled assessment dispatches through the exact same per-agent path the existing `POST /api/scenarios/{id}/run` (and the Re-run wizard) already uses.

## Assessment/Profile

A schedule references an existing **Scenario**, optionally narrowed to a saved technique/step subset — the same subset picker the Re-run wizard already offers. No new "Profile" entity. This keeps the feature purely additive: nothing about how scenarios are authored, validated, or run changes.

## Execution mode and authorization

Three existing run modes: `posture` (read-only checks, safe anywhere), `telemetry` (real, identity-safe techniques — generates real EDR/SIEM alerts), `lab` (full-fidelity emulation, isolated-range only).

- **Posture**: schedulable by default (Analyst+Admin, same tier as batch remediation).
- **Telemetry**: schedulable, but requires a **Scheduled Execution Authorization** — a standing, Admin-only, auditable approval captured at schedule-creation time. This is a real security control, not a UI confirmation dialog: it's recorded as data (`approvedBy`, `approvedAt`, `approvalVersion`), and the scheduler supplies this authorization but does **not** bypass the execution engine's own mode-safety checks — `RunScenario`'s existing telemetry-mode logic still runs, per-target, exactly as it does for an interactive run.
- **Lab**: never schedulable. The schedule-creation request only accepts `posture`/`telemetry` — lab is structurally excluded, not merely discouraged.

**Schedules are immutable — no edit endpoint.** To change anything about a schedule (mode, targets, technique scope, recurrence), cancel it and create a new one. Since telemetry-mode creation always requires a fresh Admin approval, this gets the same safety property a "does this edit require re-approval" diff-check would provide, with none of the complexity or risk of getting that diff logic wrong.

## Recurrence

Extends the existing weekly-only model to four types — covers every example in the original brief without a cron parser or its UI:

- `once` — a single absolute `runAt` timestamp, no recurrence.
- `daily` — `timeOfDay` only.
- `weekly` — existing `dayOfWeek` + `timeOfDay` (unchanged).
- `monthly` — `dayOfMonth` + `timeOfDay`.

All types carry an IANA `timezone` (existing field, unchanged validation) and an optional `endDate` (no spawns after this date). Cron is explicitly deferred — add it later only if a real use case shows these four can't express it.

`nextOccurrenceSince` becomes a small per-type switch instead of one weekly-only function; each branch is independent date math, easy to test in isolation.

## Targets: live group resolution

`Schedule` gains `GroupIDs []string` alongside the existing `AgentIDs []string`. Effective targets at spawn time = explicit `AgentIDs` ∪ live-resolved recursive members of `GroupIDs`, using the existing `agent_groups` hierarchy's recursive membership query (`GET /api/agents?groupId=`'s underlying resolution). Resolution happens fresh on every spawn — adding an endpoint to a targeted group is picked up automatically on the next occurrence, no schedule edit needed. Group-membership drift is normal fleet management and does **not** require re-authorization; only an operator explicitly changing *which* group(s)/agents a schedule targets does (which, since schedules are immutable, means cancel-and-recreate — always re-authorized by construction).

## Concurrency

A **per-schedule** concurrency limit (`Schedule.ConcurrencyLimit`, 0 = unlimited), copied onto the spawned `Job.ConcurrencyLimit`. This throttles *simultaneous execution*, not total scope — a schedule targeting 200 endpoints with `concurrencyLimit=10` runs 10 at a time until all 200 have eventually executed, it does not cap the assessment at 10 endpoints total.

Mechanism: `Dispatcher.Tick()`'s pending-target dispatch loop currently pulls up to `jobDispatchBatchSize` (20) pending targets globally per tick with no per-job awareness. This adds an in-tick in-flight count per job (existing dispatched-and-non-terminal targets for that job, plus how many this tick has already dispatched for it); once a job hits its `ConcurrencyLimit`, its remaining pending targets for this tick are simply left `pending` (no new target state) and picked up on a later tick once a slot frees. The global `jobDispatchBatchSize` cap still applies on top — the stricter of the two always wins.

## Guardrails — what's reused vs. new

| Guardrail | Status | Mechanism |
|---|---|---|
| Duplicate-run prevention | Reused, unchanged | `spawnDueSchedules` already skips a new occurrence if the previous spawn is non-terminal |
| Execution window / change-control respect | Reused, unchanged | Existing `agent_maintenance_freezes` — dispatch-time per-agent block, auto-resumes when freeze lifts |
| Kill/disable | Reused, unchanged | `DisableSchedule` (exposed as cancel) |
| Audit trail | Reused, unchanged | `h.auditLog` on create/cancel |
| Failure notification | Reused, new job type wired in | Existing job-level terminal-event notifications (`JobFailed`/`JobPartial`) |
| Unattended-run indication | New, UI/report only | Label schedule-originated runs distinctly in the run drawer/report — no new engine mechanism |
| Concurrency limit | **New** | Described above |
| Max targets per run | Explicitly deferred | No demonstrated need; existing scope controls (group membership + concurrency) considered sufficient for V1 |
| Cooldown between runs | Explicitly deferred | Redundant with duplicate-run prevention for V1 |

## Data model changes

`jobs.Schedule` gains: `RecurrenceType`, `RunAt *time.Time` (for `once`), `DayOfMonth int` (for `monthly`), `EndDate *time.Time`, `ConcurrencyLimit int`, `GroupIDs []string`, `Mode string`, `ApprovedBy string`, `ApprovedAt *time.Time`, `ApprovalVersion int`, `Reason string`. All additive columns on `job_schedules`; no existing column changes. Every row created via the existing `CreateJobSchedule` endpoint (`batch_remediation`) has `RecurrenceType=""`, so `nextOccurrenceSince`'s per-type switch treats empty as an alias for `weekly` and falls through to the exact existing `DayOfWeek`+`TimeOfDay` logic unchanged — zero migration needed for schedules that already exist, and `CreateJobSchedule` itself is untouched.

`jobs.Job` gains `ConcurrencyLimit int`, populated only when spawned from a `Schedule` that sets one; existing job-creation call sites (`CreateBatch` for ad-hoc batch jobs) are unaffected.

## New job type: `scheduled_assessment`

`scheduledAssessmentPayload{ScenarioID, Mode, Techniques, Steps}` (mirrors the relevant subset of `RunScenario`'s request shape). `dispatchScheduledAssessmentTarget` extracts and reuses `RunScenario`'s core per-agent dispatch step (the same OS-compatibility/agent-state checks, same `scenario_runs` row creation, same agent dispatch) as a shared function — mirroring exactly how `dispatchBatchRemediationTarget` already reuses `ExecuteRemediation`'s logic rather than duplicating it. `scheduledAssessmentTargetStatus` polls `scenario_runs` by the run ID returned as `RefID`, mirroring `batchRemediationTargetStatus`'s poll-by-refID shape. Both are registered in the existing `dispatchJobTarget`/`statusForJobTarget` type-switches (`internal/api/job_dispatch.go`) alongside the two existing cases.

## API surface

- `POST /api/scheduled-assessments` — create. Mode-conditional permission: `CanExecuteRemediation` for `posture`, `CanApproveRemediation` for `telemetry` (matching the existing tier-gated pattern in `CreateJobSchedule`). For `telemetry`, the request must also include a non-empty `reason` — the same required-justification field batch remediation already uses — which together with the caller's Admin-tier permission *is* the authorization act; there is no separate "I agree" ceremony beyond that. The server records `approvedBy` (the authenticated caller's user ID), `approvedAt` (server timestamp), `approvalVersion=1`, and `reason` on the created row, and this triple appears in the `jobs.schedule.create` audit-log entry alongside the existing fields. A `posture`-mode request leaves the three approval fields empty (no authorization needed for read-only checks).
- `GET /api/scheduled-assessments` — list.
- `POST /api/scheduled-assessments/{id}/cancel` — disable (reuses `DisableSchedule`).

No PUT/edit endpoint (see Authorization section above).

## Non-goals (V1)

- Cron recurrence.
- Max-targets-per-run cap.
- Cooldown-between-runs.
- Schedule editing (cancel-and-recreate instead).
- Lab-mode scheduling (permanently excluded, not just V1-deferred).
- A new "Assessment Profile" entity (schedules reference existing Scenarios).
- **UI page.** This spec covers the backend engine + API only, matching how every other sub-project in this initiative has been scoped (engine first, UI as a distinct follow-on sub-project) — job-schedules has no dashboard UI today at all. A "Scheduled Assessments" page (create/list/cancel, target-group picker, mode+authorization flow, recurrence picker) is a separate, explicitly-flagged follow-on, not silently dropped.

## Testing

- `nextOccurrenceSince`'s four recurrence branches, unit-tested independently (no DB) — mirrors the existing weekly-only test coverage pattern.
- Concurrency-limit dispatch throttling: a `Tick()` test asserting a job with `ConcurrencyLimit=N` never has more than N non-terminal targets at once across multiple ticks.
- Live group-resolution: a schedule targeting a group picks up an agent added to that group *after* the schedule was created, on the next spawn.
- Telemetry-mode creation without approval fields → 400; with them → schedule created with `approvalVersion=1`.
- Lab mode in a create request → rejected.
- End-to-end: a `scheduled_assessment` job dispatches, and `scenario_runs` gets a row identical in shape to one created via the interactive `RunScenario` path for the same scenario/agent/mode.
