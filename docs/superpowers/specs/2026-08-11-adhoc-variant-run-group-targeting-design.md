# Ad-hoc Variant Run: Agent Group / All Agents Targeting — Design

## Problem

The "Run Variants" card (Scenarios tab, single-agent `#vex-agent` select) lets an operator check one-or-many techniques and run them sequentially against one agent via a client-side queue (`runVariants()` → `_vexRunVariantQueue()` → `_vexWaitAndNext()`, index.html:16655+). It has no group or multi-agent targeting. Full Variant Sweep just gained Agent Group targeting (Sub-project D); this flow was deliberately scoped out of that work at the user's own choice, to be handled as its own sub-project given a real architectural difference between the two flows.

## Why this isn't a copy of Full Sweep's design

Full Sweep's group targeting fans out N independent, stateless `POST /api/vex/sweeps` calls — each sweep is a server-owned job, polled independently, no client-side sequencing. The ad-hoc flow is different: when multiple techniques are checked, `_vexWaitAndNext()` polls the current technique's run to completion *in browser JS state* before dispatching the next one. Multiplying that loop across N agents would mean N parallel client-side sequential queues in one tab — the exact reload-fragility class Full Sweep's original rewrite (Sub-project A) fixed, just recreated here across agents instead of techniques, with no progress UI able to show more than one queue at a time.

## Goals

- Add Individual / Agent Group(s) / All Agents (Admin-only) targeting to the Run Variants card.
- Group(s)/All Agents targeting is valid only when **exactly one technique is checked** — this keeps multi-agent dispatch architecturally identical to Full Sweep's just-shipped pattern (N independent stateless `POST /api/variants/run` calls, no queue, since there's only one technique per agent).
- Reuse the group-resolution helpers already built this session (`gpFlattenGroups`, `resolveGroupTargetAgents`) and the `ROLE === 'admin'` All-Agents gate already established for the Run Scenario wizard — no new backend permission.

## Non-goals

- No change to multi-technique behavior. Checking 2+ techniques still only works in Individual mode, dispatched exactly as today via the existing client-side queue (`_vexRunVariantQueue`/`_vexWaitAndNext`), completely unmodified.
- No new progress UI. Multi-agent dispatch relies on a summary toast (per-agent success/failure) plus the existing Live Runs tab to check results afterward — each dispatch creates a normal `scenario_runs` row, already visible there individually. `#vex-result-panel`, `pollVariantRun`, `stopVex()` are untouched and only ever run for the Individual-mode path.
- No backend changes. `POST /api/variants/run` keeps its existing `{agentId, techniqueId, executionMode, includeAdvanced}` shape, called once per resolved agent.
- No restriction on the technique checklist's UI itself (e.g. auto-converting to single-select in Group(s) mode) — the invalid multi-technique + Group(s)/All combination is caught at Run-click time with a toast, not prevented structurally. Simpler, consistent with how Full Sweep's own blast-radius validation works.

## Design

### Target Mode toggle

A radio toggle (Individual / Agent Group(s) / All Agents) is added to the Run Variants card, same visual pattern as Full Sweep's card. Individual mode is the default and is pixel-identical to today — the existing `<select id="vex-agent">` is unchanged. Agent Group(s) mode shows a checkbox list of groups (`gpFlattenGroups`) with a resolved-agent-count summary (`resolveGroupTargetAgents`, no OS filtering — same reasoning as Full Sweep: this flow has no scenario/supportedOs concept). All Agents mode is a simple notice, shown only when `ROLE === 'admin'`.

### Scope guard

`runVariants()` gains a check at its top: if the active target mode is Group(s)/All Agents and more than one technique is checked, it shows a toast — *"Group/All-Agent targeting requires exactly one technique — uncheck the rest, or switch to Individual for a multi-technique run."* — and returns without dispatching anything. This guard runs before any network call.

### Dispatch (Group(s)/All Agents mode, single technique)

1. Resolves the target agent list (group members, or every agent for All Agents mode).
2. Shows a confirm only for 2+ resolved agents (mirroring the Run Scenario wizard's precedent of a lightweight confirm for multi-agent posture-equivalent dispatches — this is a much lighter action than a sweep, so no "blast-radius" framing needed, just "Run technique X on N agents?").
3. Fires `POST /api/variants/run` once per resolved agent via `Promise.all`, each call normalized to `{agentId, ok, error}` — one agent's failure (offline, conflict, etc.) never blocks the others, same isolation pattern used everywhere else this session.
4. Shows a summary toast: *"Dispatched to N agents"* or, on partial/total failure, the same per-agent failure-listing wording Full Sweep's summary toast already uses.

### Dispatch (Individual mode)

Completely unchanged — `runVariants()`'s existing single-agent, one-or-many-technique client-side queue path.

## Testing

Frontend-only change (no Go code touched). `node --check` syntax verification, plus a standalone Node harness re-confirming the reused group-resolution helpers and the dispatch-summary branching logic (same technique used for Full Sweep's Sub-project D verification this session). Manual QA checklist: Individual mode (single and multi-technique) unchanged; Group(s) mode with exactly one technique dispatches to every resolved agent; checking a second technique while in Group(s) mode and clicking Run shows the scope-guard toast and dispatches nothing; All Agents mode is invisible to non-Admin users; a group containing an already-busy or offline agent still dispatches to the others and reports that failure in the summary toast; Live Runs shows one row per successfully-dispatched agent afterward.
