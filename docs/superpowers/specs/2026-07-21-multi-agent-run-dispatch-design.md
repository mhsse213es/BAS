# Multi-Agent Run Dispatch — Design

**Status:** Approved (pending final user sign-off on this written doc)

## Problem

The "Run Scenario" modal (`#modal-agent`, `orchestrator/wwwroot/index.html`) only lets an operator pick one agent via a plain `<select>`. Running the same scenario against several agents means reopening the modal and repeating the whole flow once per agent. The app already has a proper multi-select-with-filters picker for this exact need, but only inside the much heavier "New Campaign" flow (name, threat-informed packs, notes) — most operators just want to run one scenario against a handful of agents right now, not build a campaign.

## Architecture — additive, not a rewrite

`modal-agent` stays exactly as it is today and keeps driving every piece of UI logic currently threaded through "the one agent": the OS-mismatch warning, live-mode (telemetry/lab) gating, the posture check-catalog picker, privilege-tier rendering. None of that changes. It becomes the **Primary Agent**.

A new **"Run on Additional Agents"** section appears below it — a scrollable checkbox list of every *other* enrolled agent compatible with the scenario's `supportedOs`, plus a "Select All" button, hidden entirely when there are zero eligible additional agents (single-agent fleet, or every other agent is OS-incompatible). The primary agent never appears in this list, so there is no dedup case to handle structurally (a defensive dedupe still runs in code, cheap and harmless).

**Dispatch order is fixed and deterministic:** `[primary, ...additional in list order]`. The list order is the same order agents already render in elsewhere in the app (the loaded `agents` array), filtered to OS-compatible and excluding primary. This ordering is preserved through dispatch and result reporting — not because completion arrives in that order (requests are concurrent), but so results are always *displayed* in one stable, predictable order, which is also what a future grouped-runs UI would want.

No backend changes are required. `POST /api/scenarios/{scenarioId}/run` already takes exactly one `agentId` per call (confirmed via `internal/api/handlers.go:1216-1235` — plain `json.NewDecoder(...).Decode(&req)`, no `DisallowUnknownFields()`, so an unrecognized JSON field is silently ignored, not rejected) and every other existing single-agent test/behavior (OS-mismatch, live-mode confirm, execution-window checks, etc.) is untouched. Multi-agent becomes "call that same endpoint once per agent, in order, independently."

## Confirmation dialog

Shown whenever **2 or more** agents are targeted, regardless of mode. **Unchanged for the single-agent case** — zero new friction for the existing common path (posture mode today has no confirmation at all; that stays true for a single agent).

Native `confirm()`, plain text, matching this codebase's existing style (`\n\n`-separated blocks, no HTML). Two variants:

**Posture mode, 2+ agents** (new — today posture has zero confirmation regardless of agent count):
```
Run scenario?

Scenario: Credential Dump
Framework: Atomic Red Team

Agents (4):
• WIN-01
• WIN-02
• WIN-05
• WIN-09

Proceed?
```

**Telemetry/Lab mode, 2+ agents** (merges the existing safety copy with the agent list into one dialog — not two separate popups):
```
TELEMETRY mode runs real, identity-safe techniques and WILL generate EDR/SIEM alerts.

Scenario: Credential Dump
Framework: Atomic Red Team

Agents (4):
• WIN-01
• WIN-02
• WIN-05
• WIN-09

Proceed only on approved, monitored targets. Continue?
```
Lab mode's existing **second** confirmation ("Second confirmation required for LAB mode... isolated lab/range with a snapshot?") stays a simple yes/no — repeating the full agent list a second time would be noise, not signal.

## Customized subset + multi-agent

Allowed (per explicit approval), with a visible caveat for the one case that's genuinely riskier: `posture` framework subsets. A posture check-ID subset comes from one agent's catalog (harvested at enrollment — different agents can expose different catalogs even on the same OS), so a check present on the primary agent may not exist on an additional agent. `art`/`caldera`/`steps` subsets are framework-level IDs already filtered per-agent normally during a regular run, so they need no special handling.

When a posture subset is active **and** 2+ agents are targeted, an inline note appears near the target picker:
> *"This check subset was built from [Primary Agent]'s catalog — any check not present on other selected agents will report not applicable."*

This is informational only — it does not block the run. A check that doesn't exist on a given agent already resolves to "not applicable" today (existing skip-reason behavior, not new).

## Dispatch, progress, and failure handling

- On confirm, the Run button is disabled and its label changes to **"Dispatching to N agents…"** so the operator gets immediate feedback that the click registered (v1 keeps this simple — no per-agent live checklist; that's a reasonable future enhancement, not required now).
- All N requests fire concurrently (`Promise.allSettled`, not `Promise.all` — one agent's failure must never abort or block the others; each request is fully independent).
- Once all settle, one aggregated toast reports the outcome:
  - All succeeded: `Dispatched to 4 agents.`
  - Partial failure: `Dispatched to 3/4 agents. Failed: WIN-07 (offline)` — one line per failed agent, reusing whatever error message the failed response/exception already carries.
  - All failed: `All 4 dispatches failed. WIN-01 (...), WIN-02 (...), ...`
- After settling, same as today's single-agent success path: close the modal, switch to the Runs tab, reload the run list — regardless of partial failure, since the successful ones did create real runs worth seeing.

## Forward-compat: `batchId` (no behavioral change now)

Each dispatch in a multi-agent batch includes a client-generated `batchId` in the POST body (`crypto.randomUUID()`, with a fallback string generator for older browsers without it). The backend does not read, store, or use this field in this pass — it is inert, silently ignored by the existing decode. This is purely a forward-compat hook: a later backend change (persisting `batch_id`/`dispatch_group_id` on `scenario_runs` and grouping them in the Runs page — e.g. "Credential Dump · Batch: 4 agents ▾ WIN-01 Complete / WIN-02 Running / ...") becomes additive against an already-populated field instead of requiring every historical multi-agent run to be re-labeled or every existing frontend caller to change. **Explicitly out of scope for this implementation**: any backend storage of `batchId`, any Runs-page grouped display. This spec only guarantees the field exists on the wire, named consistently, from day one.

## Out of scope

- Backend persistence/grouping of `batchId` (noted above — deliberately deferred).
- A live per-agent progress checklist during dispatch (static "Dispatching to N agents…" label is enough for v1).
- OS/environment filter dropdowns in the Additional Agents list (that's what the Campaign modal is for — this picker is deliberately simpler: a flat, pre-filtered checklist + Select All, matching the original ask).
- Any change to the Campaign flow itself.
