# Scheduled Assessments UI — Design

## Why

The Scheduled Assessments backend (create/list/cancel API, recurrence engine, live
group resolution, Scheduled Execution Authorization for telemetry mode) shipped
complete in a prior sub-project, but with no frontend — it was explicitly scoped
out as a follow-on. This spec covers that follow-on: a page in the orchestrator
dashboard (`orchestrator/wwwroot/index.html`) to create, list, and cancel
scheduled assessments.

This is a **frontend-only** project. No backend changes. Every field and
permission rule below already exists and is already enforced server-side; the
UI's job is to present it correctly and never claim to enforce anything the
server doesn't independently enforce itself.

## Non-goals (V1)

- No technique/step subset picker — a schedule always runs the full scenario.
  The existing "Customize" subpicker (used by the interactive Run wizard) is not
  reused here.
- No editing of an existing schedule. Schedules are immutable by backend design
  — the only lifecycle action besides create is cancel.
- No computed "next run" timestamp. The backend does not persist or expose one;
  inventing one client-side would mean re-implementing the Go recurrence/skip
  logic in JS, which can silently drift from the real scheduler. The UI shows
  the recurrence rule as authored (e.g. "Weekly · Sunday · 02:00 · Asia/Kolkata")
  plus `LastOccurrenceAt`, never a predicted next-fire time.
- No filter/segment tabs on the list (e.g. "Active" vs "Cancelled") — V1 is one
  flat list.
- No changes to the existing single-select agent-group tree in the Agents tab.
  The Targets step gets its own new multi-select component.

## Navigation

New `nav-item` under the **Operations** group, positioned between **Live Runs**
and **Campaigns**:

```
Operations
├── Dashboard
├── Scenarios
├── Live Runs
├── Scheduled Assessments   ← new
└── Campaigns
```

Visible only when `ROLE === 'admin' || ROLE === 'analyst'` — the same tier the
API itself requires (`CanExecuteRemediation`, Analyst+Admin; Viewer excluded).
This mirrors the existing `nav-integrations` admin-only visibility toggle
already wired in `bootApp()`.

`data-tab="scheduled-assessments"`, mapped to a new `<div id="tab-scheduled-assessments">`.

## List view

A table, one row per schedule, styled like the existing Reports/Integrations
tab tables:

| Column | Source | Notes |
|---|---|---|
| Assessment | `scenarios.find(s => s.id === payload.scenarioId).name` | `Schedule` has no name field; the scenario name is resolved client-side against the already-loaded `scenarios` array, decoding `scenarioId` out of the schedule's `Payload` JSON. |
| Mode | `sch.Mode` | Badge: "Posture" / "Telemetry". |
| Targets | `sch.GroupIDs` (names resolved via the loaded agent-group tree) + `sch.AgentIDs.length` | e.g. "Finance Group + 3 agents". |
| Recurrence | `sch.RecurrenceType`, `sch.DayOfWeek`/`DayOfMonth`/`RunAt`, `sch.TimeOfDay`, `sch.Timezone` | Pure presentation, e.g. "Weekly · Sunday · 02:00 · Asia/Kolkata", "Once · Aug 15, 2026 · 02:00 · Asia/Kolkata". No date arithmetic beyond formatting the stored fields. |
| Last run | `sch.LastOccurrenceAt` | Formatted timestamp, or "Never". |
| Status | `sch.Enabled` | Badge: "Enabled" / "Cancelled". |
| Actions | — | "Cancel" button; hidden once `Enabled === false`. |

Empty state (no schedules of type `scheduled_assessment` returned): "No
scheduled assessments yet" + an inline "+ New Schedule" call to action.

A schedule row is never removed after cancellation — `Enabled` flips to false
and the row stays, matching the backend's cancel = disable (not delete)
semantics.

## Create flow — dedicated wizard modal

A new modal (`sched-overlay` / reusing the `wz-modal` visual scaffold the Run
wizard already defines, but its own separate flow — not an extension of the
Run wizard). A schedule is a different object than a `scenario_run` with a
different field set, lifecycle, and authorization model; the two wizards share
CSS and a couple of sub-components, not a workflow.

**Step 1 — Scenario**
Single `<select>` populated from the already-loaded `scenarios` array. Full
scenario only, no subset picker.

**Step 2 — Targets**
A new `AgentTargetSelector` component with two parts:
- **Groups**: a checkbox multi-select tree, adapted from `renderAgentGroupTree`'s
  hierarchy-rendering logic into a new function (the existing single-select
  Agents-tab tree component is untouched). Checking a group selects *that
  group's ID* only — it does not cascade-select or persist descendant group
  IDs, and does not expand into a frozen list of current member agents.
  Caption: "Groups are resolved live at execution time — agents added later
  are automatically included."
- **Agents**: a flat checkbox multi-select list of individual agents, styled
  like the Run wizard's "Run on Additional Agents" checklist. Caption:
  "Individual agents are explicitly included in this schedule."

Overlap between a selected group's live membership and an explicitly selected
individual agent is deduplicated server-side (already implemented —
`unionAgentIDs` in `spawnDueSchedules`); the UI does not attempt to detect or
warn about overlap.

**Step 3 — Mode & Recurrence**
- Mode `<select>`: **Admin** sees Posture and Telemetry. **Analyst** sees only
  Posture — Telemetry is not rendered as an option at all (not shown-disabled).
  Lab is never an option, for any role. Hiding Telemetry from non-Admins is a
  UX simplification only; the server independently rejects a telemetry-mode
  request from a non-Admin regardless of what the UI allows through.
  - Selecting Telemetry reveals a prominent warning ("This assessment executes
    real, alert-generating techniques against the selected targets and will
    run unattended.") and a required **Reason** text field.
- Recurrence type `<select>`: Once / Daily / Weekly / Monthly. Fields shown
  change per type:
  - Once: Date, Time, Timezone
  - Daily: Time, Timezone
  - Weekly: Day of week, Time, Timezone
  - Monthly: Day of month (1–28), Time, Timezone
- Optional **End date**.
- Optional **Concurrency limit** (blank = unlimited).

**Step 4 — Review & Authorize**
Read-only summary of every field from steps 1–3. For Telemetry mode: the same
warning banner, the entered reason, and a required "I authorize this recurring
unattended execution" checkbox that gates the "Create Schedule" button. This
checkbox is a client-side confirmation UX gate only — the actual Scheduled
Execution Authorization record (`ApprovedBy`/`ApprovedAt`/`ApprovalVersion`/
`Reason`) is captured server-side from the authenticated Admin's identity and
the submitted reason at `POST /api/scheduled-assessments` time, exactly as the
backend already implements it.

On submit: `POST /api/scheduled-assessments` with the assembled payload, close
modal, toast success/error, refresh the list.

## Cancel flow

Row-level "Cancel" button → native `confirm()` dialog (matching existing
patterns like agent-group delete) → `POST /api/scheduled-assessments/{id}/cancel`
→ refresh the list. No separate confirmation modal.

## Viewing existing telemetry schedules as a non-Admin

An Analyst can see a Telemetry-mode schedule in the list (Mode badge, targets,
recurrence, authorization implied by its presence) even though they could not
have created one. They can still cancel it — cancellation uses the same
`CanExecuteRemediation` tier as create/list for all three routes; it is not
Admin-gated on the backend, so the UI does not gate it either.

## Testing plan

This is a static frontend change (HTML/CSS/JS in `wwwroot/index.html`, no Go
code). Verification is manual browser QA against a running orchestrator:
- Nav item visibility per role (Admin/Analyst see it, Viewer does not).
- Create flow: full happy path for Posture (Analyst) and Telemetry (Admin);
  Telemetry option absent for Analyst; validation errors surfaced from the API
  (e.g. reason missing) shown as toasts, not swallowed.
- List rendering: recurrence description formatting for all 4 recurrence
  types, target summary with groups+agents, empty state, Last run formatting
  including "Never".
- Cancel flow: confirmation, row updates to Cancelled, row is not removed.

Per this project's established backlog pattern, this manual QA pass is
deferred and tracked alongside the rest of the Pending Manual QA Backlog
memory rather than blocking implementation.
