# Re-run Feature (Live Runs Results Drawer) — Design

## Context

The run-results drawer (`orchestrator/wwwroot/index.html`, `viewRunResults`) has always rendered "Compare" and "Re-run" as permanently disabled placeholder buttons (`index.html:11018-11019`, `disabled ... title="... — coming soon"`). The code's own comment confirms neither was ever wired up: "Compare/Re-run are NOT real features anywhere in this app today."

This surfaced as a real need while investigating a production cleanup-verdict issue: a scenario run ("Atomic Red Team - Selective Techniques") showed 45 genuine cleanup failures concentrated in one technique (T1112, Modify Registry), but the server only stores the `reverted/partial/leaked` verdict, never the cleanup command's own error output. The fastest way to get a real answer is to re-run just the affected techniques against the same agent and inspect the result directly — which today means manually reopening the scenario picker, reselecting the scenario, reselecting the agent, and reselecting the technique subset from scratch.

## Goal

Make "Re-run" on a completed run's results actually work: one click reopens the existing "Run Scenario" wizard pre-filled with that run's scenario and agent, so the operator can immediately adjust (mode, privilege, technique subset) and dispatch, instead of reconstructing the run configuration by hand.

## Non-Goals

- **Compare** stays disabled — out of scope for this change, not touched.
- No "linked rerun" concept — the new run has no relationship back to the original in the data model. It is a completely independent run, identical in every way to one started via any other "Run" entry point in the app (Endpoint Mastery's per-layer Run button, the Scenarios tab, Safe Scan). If a future need arises to compare a run against its "parent," that belongs to Compare, not Re-run.
- No new backend endpoint, no new permission, no new dispatch logic. Everything Re-run needs already exists and is already correctly permission-gated.

## Architecture

Re-run is a thin frontend wrapper around existing infrastructure:

- **Dispatch modal**: `openModal(scenarioId, preAgent, lockAgent)` (`index.html:9723`) already exists and is used by every other "Run" entry point in the app. Passing a `scenarioId` pre-selects and locks the scenario step of the wizard; passing `preAgent` pre-selects (but does not lock) the agent dropdown. Mode (posture/telemetry/lab), max-privilege override, and — critically for the motivating use case — a **technique subset** (`_runSelection = {scId, fw, ids}`, already wired into the modal via the existing technique picker) are all adjustable by the operator before submitting.
- **Dispatch endpoint**: the modal's own submit path already posts to `POST /api/scenarios/{id}/run`, already gated server-side by `auth.RequirePermission(auth.CanRunScenario)` (`routes.go:299`) and already routed through `Handler.dispatchRun` (`handlers.go:1165`), which does agent-state gating, OS-compatibility checks, and artifact generation (`applyGeneratedArtifacts`, `handlers.go:1148`). None of this needs to change.
- **Frontend gating**: `CanRunScenario` is "Analyst+Admin" server-side (`internal/auth/permissions.go:31-32`). The frontend already has an established pattern for this exact role check on other Run buttons — `var canRun = ROLE === 'admin' || ROLE === 'analyst';` (e.g. `index.html:7894`, `:16143`). The Re-run button reuses this same check rather than introducing a new permission concept: if the current user can't run scenarios, the button doesn't render as active (matches how "Compare" — and every disabled button pattern in this codebase — already looks: `disabled`, dimmed, tooltip explaining why).

## Exact Change

In `viewRunResults`'s header-toolbar block (`index.html:11011-11020`), replace the disabled Re-run button. Current:

```js
'<button class="btn btn-outline btn-sm" disabled style="opacity:0.5;cursor:not-allowed" title="Re-run this execution — coming soon">Re-run</button>';
```

New — a `canRun` check (same pattern as the existing `emRunLayer`/adversary-template call sites) gates between an active button wired to `openModal` and a disabled one with an explanatory tooltip (not "coming soon" — now "requires Analyst or Admin role", since the feature exists but this operator's role doesn't permit it):

```js
var canRerun = ROLE === 'admin' || ROLE === 'analyst';
actionsHtml =
  '<button class="btn btn-sm btn-outline" onclick="exportRunJSON(\'' + runId + '\')" title="Download full run data as JSON">&#8595; JSON</button>' +
  '<button class="btn btn-sm btn-outline" onclick="openRunReport(\'' + runId + '\')" title="Open self-contained HTML report in new tab">&#8595; HTML Report</button>' +
  '<button class="btn btn-sm btn-outline" onclick="downloadRunPDF(\'' + runId + '\')" title="Download PDF report">&#8595; PDF</button>' +
  '<button class="btn btn-sm btn-outline" onclick="downloadRunCSV(\'' + runId + '\')" title="Download forensic CSV (one row per technique)">&#8595; CSV</button>' +
  '<button class="btn btn-outline btn-sm" disabled style="opacity:0.5;cursor:not-allowed" title="Compare against another run — coming soon">Compare</button>' +
  (canRerun
    ? '<button class="btn btn-outline btn-sm" onclick="openModal(' + JSON.stringify(run.scenarioId) + ', ' + JSON.stringify(run.agentId) + ')" title="Open the run wizard pre-filled with this scenario and agent">Re-run</button>'
    : '<button class="btn btn-outline btn-sm" disabled style="opacity:0.5;cursor:not-allowed" title="Re-run requires the Analyst or Admin role">Re-run</button>');
```

`run.scenarioId` and `run.agentId` are both already-present, already-used fields on the run object (confirmed via existing usage at `index.html:10991` and `:16077`/`:15934` respectively) — no new data plumbing needed.

`openModal` closes the results drawer implicitly by opening its own overlay (`run-overlay`) on top — same behavior every other `openModal` call site already has (e.g. clicking Run from Endpoint Mastery while another panel is open). No special handling needed for "drawer is open, now modal is also open" — this is the existing, already-working interaction pattern.

## Error Handling

None new. `openModal` already handles its own edge cases (no scenarios loaded, no agents registered — both show a toast and return early, `index.html:9725-9726`). If the original run's `scenarioId` no longer matches any current scenario (e.g., deleted since the run happened), `openModal`'s existing scenario-select population (`index.html:9729-9732`) simply won't find a match to mark `selected` — the dropdown opens with nothing pre-selected rather than erroring, matching how `openModal` already degrades when passed a stale ID from any other call site. Same for a retired/removed agent: the agent dropdown's `preAgent === a.agentId` selected-match (`index.html:9746`) simply doesn't match anything, defaulting to whatever the browser's `<select>` shows first — no special-case code needed.

## Testing

No backend changes, so no Go test changes. Manual verification (this is a `wwwroot/index.html` JS change, no existing frontend test harness in this codebase to extend):
1. As Admin or Analyst: open a completed run's results, confirm Re-run is active, click it, confirm the wizard opens pre-filled with the correct scenario (locked, since `scenarioId` is passed) and agent (pre-selected, adjustable) matching the original run.
2. Confirm the technique-subset picker still works normally from this entry point (select a handful of techniques, e.g. just T1112, dispatch, confirm only those run).
3. As a role without `CanRunScenario` (e.g. Viewer, if one exists in this deployment's role set): confirm Re-run renders disabled with the "requires the Analyst or Admin role" tooltip, and that attempting to hit `POST /api/scenarios/{id}/run` directly (bypassing the UI) still 403s server-side — this should already be true and unchanged, just worth confirming nothing in this change accidentally weakens it (it can't, since the endpoint's permission check is untouched).
4. Confirm Compare is unaffected — still disabled, still "coming soon".
