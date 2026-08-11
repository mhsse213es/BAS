# Full Variant Sweep: Agent Group Targeting — Design

## Problem

The Full Variant Sweep card (Scenarios tab, `#vex-sweep-card`) only lets an operator start a sweep against one agent at a time (`<select id="vex-sweep-agent">`, single value posted to `POST /api/vex/sweeps`). Validating a fleet means clicking "Start Sweep" once per agent, one at a time. The Run Scenario wizard already gained Individual/Agent Group(s)/All Agents targeting earlier this session; Full Sweep has no equivalent.

## Goals

- Let an operator select one individual agent (unchanged) or one-or-many Agent Groups, and launch one independent sweep per resolved agent from a single "Start Sweep" click.
- Each launched sweep remains exactly what it is today: a fully independent, self-contained, sequential per-agent job (`vex_sweeps` row, `agent_id` uniqueness constraint unchanged). Multi-agent targeting is N independent dispatches, never a new "multi-agent sweep" entity.
- Reuse the group-resolution helpers already built for the Run Scenario wizard (`gpFlattenGroups`, `buildGroupDescendantMap`, `resolveGroupTargetAgents`) — no new resolution logic.
- A clear blast-radius confirmation before dispatch, since each sweep is an hours-scale job.

## Non-goals

- No "All Agents" target mode. Given the per-agent cost (every ART technique, sequentially, potentially hours per agent), launching against the entire fleet from one click is out of scope — an operator who wants that can select every group.
- No hard cap on the number of agents a single launch can target. The blast-radius confirm is the only gate.
- No backend changes. `POST /api/vex/sweeps` already dispatches one sweep per `agentId`; multi-agent targeting is purely a client-side fan-out over that existing endpoint, exactly like the Run Scenario wizard's group targeting fans out over `POST /api/scenarios/{id}/run`.
- No change to the existing sweep progress list (`#vex-sweep-list`, `renderVexSweepList`, polled via `GET /api/vex/sweeps?status=running`) — it already renders one card per running sweep regardless of how many exist, so N newly-created sweeps need no changes there.
- No change to Live Runs' sweep-collapsing (this session's prior work) — it already handles any number of concurrent sweeps as independent collapsed rows.
- No OS-eligibility filtering. Unlike the Run Scenario wizard (which filters a group's agents against a specific scenario's `supportedOs`), a sweep has no scenario/supportedOs concept — it resolves ART techniques per-agent OS server-side regardless. Every resolved agent is targeted; an incompatible or offline agent simply fails its own `POST /api/vex/sweeps` call, reported like any other per-agent dispatch failure.

## Design

### Target Mode toggle in the sweep card

The card gains a small radio toggle (Individual Agent / Agent Group(s)) above the existing controls. Individual mode is the default and is pixel-identical to today's behavior — the existing `<select id="vex-sweep-agent">`, mode select, Advanced Pack checkbox, and Start Sweep button are unchanged.

Agent Group(s) mode replaces the agent `<select>` with a checkbox list of every group, flattened via the existing `gpFlattenGroups(agentGroupTree, 0, null, [])` (same helper the Run Scenario wizard's Group(s) mode already uses) — each row shows the group's `totalAgentCount`. A summary line below the list shows the resolved agent count (e.g. "14 agent(s) across 2 group(s)"), computed via the existing `resolveGroupTargetAgents(selectedGroupIds)` helper — no OS filtering applied (see Non-goals).

The existing live "this agent already has a running sweep" hint (`_vexCheckAgentSweepConflict()`) stays exactly as-is for Individual mode (it's driven by the single `<select>`'s `onchange`). It does not run in Group(s) mode — checking N agents live on every checkbox click isn't practical, and conflicts surface naturally in the post-dispatch summary instead (see below).

### Dispatch

Clicking "Start Sweep" in Group(s) mode:
1. Resolves the checked groups to an agent-ID list via `resolveGroupTargetAgents`.
2. Shows one blast-radius confirm: *"This will start N independent sweeps across M group(s). Each sweep runs every ART technique sequentially against its agent and may take hours. Proceed?"* — replacing, not stacking with, the existing single-agent confirm (which only fires in Individual mode).
3. Fires `POST /api/vex/sweeps` once per resolved agent via `Promise.all`, each call normalized to a resolved `{agentId, ok, error}` result (same isolation pattern `confirmRun()` already uses for the Run Scenario wizard — one agent's failure, e.g. already-sweeping 409 or an offline agent, never blocks the others).
4. Shows a summary toast: *"Started N sweeps"* or, if some failed, *"Started N/M sweeps. Failed: agent-x (already sweeping), agent-y (offline)"* — same wording pattern as the Run Scenario wizard's multi-dispatch summary.
5. Calls `pollVexSweeps()` immediately after (already done today for the single-agent path) so every newly-created sweep's card appears without waiting for the next 3s tick.

## Testing

Frontend-only change (no Go code touched), so no Go test additions — consistent with how the Run Scenario group-targeting feature was verified. `node --check` syntax verification, plus a standalone Node harness exercising the group-resolution call against synthetic fixtures if the existing helpers need any adaptation (they're expected to be reused unmodified). Manual browser QA checklist: Individual mode is unchanged (regression check); selecting 2+ groups with overlapping membership doesn't double-dispatch to the same agent; the blast-radius confirm shows the correct count; a group containing an agent that's already sweeping still starts the others and reports that one failure in the summary toast; `#vex-sweep-list` shows all newly-started sweeps as separate cards without a page reload.
