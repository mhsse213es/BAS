# Run Scenario Wizard: Agent Group Targeting — Design

## Problem

The Run Scenario wizard (`openModal()`/`confirmRun()` in `orchestrator/wwwroot/index.html`) lets a user target one primary agent plus any number of individually-checked "Additional Agents." It has no way to target a whole Agent Group. A user who wants to run a scenario across, say, all 40 agents in "Mumbai Branch Servers" must find and check every one by hand.

Agent Groups (hierarchical, with recursive descendant membership) already exist as a first-class concept, used by both Campaigns and Scheduled Assessments for group-based targeting. This spec extends the same convenience to the lighter-weight, single-click Run Scenario wizard — without adopting Campaigns' heavier snapshot/reporting machinery, which is out of scope here.

## Goals

- Let a user select one individual agent, multiple individual agents (already possible), one Agent Group, multiple Agent Groups, or (Admin only) all agents — as the target for a single Run Scenario dispatch.
- Reuse the existing per-agent dispatch mechanism (`confirmRun()`'s `Promise.all` fan-out) unchanged.
- No backend changes. Group resolution happens entirely client-side from data already loaded in the browser.

## Non-goals

- No new backend endpoint, no new permission, no persisted "group run" entity. This is not a Campaigns replacement.
- No change to how results are displayed after dispatch (existing per-agent success/failure toast + Runs tab behavior is unchanged).
- No change to OS-compatibility semantics — group-resolved agents go through the exact same eligibility filter individually-picked agents already do.

## Design

### Target Mode selector

The wizard's Target step gains a mode selector with three options, rendered as radio buttons above the existing agent picker:

- **Individual** (default) — today's UI: primary agent `<select>` + "Additional Agents" checkbox list. Unchanged.
- **Group(s)** — a checkbox list of every Agent Group, flattened from the already-loaded `agentGroupTree` global using the existing `gpFlattenGroups(nodes, depth, excludeId, out)` helper (`index.html:6655`), indented by depth. Each row also shows the group's `totalAgentCount` (already present on each tree node) as a hint.
- **All Agents** — a single checkbox/notice, no group list. Only rendered when `ROLE === 'admin'` (module-level global already used for the identical gate on Campaigns' "All Agents" option, `index.html:7586`). Hidden entirely for non-Admins — not shown-then-disabled.

Switching modes clears the other modes' selection state so stale picks can't silently persist across a mode switch.

### Resolving groups/all to agent IDs (client-side, no API call)

New helper function `resolveGroupTargets(selectedGroupIds)`:

1. Walk `agentGroupTree` once, building a `Set` of every node's `id -> [descendant ids incl. self]` — a straightforward recursive collection, structurally the same walk `gpFlattenGroups` already does, just collecting IDs instead of `{id,label}` pairs.
2. Union the descendant sets for every group ID in `selectedGroupIds`.
3. Filter the global `agents` array (already loaded for the primary-agent dropdown; each row carries `.groupId` per `GetAgents`' existing `a.group_id` column) to those whose `groupId` is in the union.
4. Return that agent list.

"All Agents" mode reuses the same downstream step (5, below) over the full `agents` array — no separate code path beyond skipping steps 1-3.

### OS eligibility (reuses existing logic, not duplicated)

5. Run the resolved agent list through the same filter `eligibleAdditionalAgents()` already applies (`supported.indexOf(cmpAgentOS(a)) === -1` exclusion against `sc.supportedOs`) — extracted so both call sites share the one filter function rather than copy-pasting the condition.
6. Agents excluded by the OS filter are counted, not silently dropped from view: a summary line renders under the group/all checkboxes, e.g. *"12 of 15 group agents eligible (3 skipped: OS mismatch)."* If zero agents remain eligible, the Run button stays disabled with an explanatory message (same disabled-button pattern `renderRunMode()` already uses for a fully OS-mismatched single agent).

### Wiring into the existing dispatch path

7. The resolved, OS-filtered agent ID list is written into `_addlSel` (the same object `renderAdditionalAgents()`'s checkboxes already populate) with no primary agent set. `confirmRun()`'s existing line `var agentIds = [primaryId].concat(additionalAgentIds())` needs one small adjustment: when Target Mode is Group(s)/All, there is no meaningful single "primary" agent, so `agentIds` is built directly from the resolved set (`additionalAgentIds()`'s existing filter logic, just without requiring a primary to exclude) rather than needing a synthetic primary. Everything downstream of that line — mode confirms, `baseBody`, the `dispatches` map, `Promise.all`, result toast — is untouched.

### Blast-radius confirmation

8. When Target Mode is Group(s) or All (regardless of run mode — posture included), `confirmRun()` shows one additional explicit confirm before its existing mode-specific confirms:
   *"This will run on N agents across M group(s). Proceed?"* (or *"...on all N agents.*" for All mode). This is additive to, not a replacement for, the existing posture/telemetry/lab confirms — a Group-targeted Telemetry run still gets both this confirm and the existing Telemetry warning.

## Data flow summary

```
agentGroupTree (loaded once via loadAgentGroupTree(), already exists)
agents[] (loaded once via loadAgents(), already exists, each row has .groupId)
        │
        ▼
User checks Group(s) / All in Target Mode
        │
        ▼
resolveGroupTargets(selectedGroupIds) ─── pure client-side set math, no API call
        │
        ▼
eligibleAdditionalAgents()-style OS filter (shared helper)
        │
        ▼
_addlSel populated  ──────────────────────────────────────────┐
        │                                                       │
        ▼                                                       │
confirmRun() blast-radius confirm (new, Group/All only)          │
        │                                                       │
        ▼                                                       │
agentIds = resolved set (existing additionalAgentIds() logic, no synthetic primary)
        │
        ▼
EXISTING Promise.all fan-out: one POST /api/scenarios/{id}/run per agent — unchanged
```

## Testing

Frontend-only change (no Go code touched), so no Go test additions. Verification is manual browser QA against the running dashboard:
- Individual mode still behaves exactly as before (regression check).
- Selecting a single group with a mix of Windows/Linux agents against a Windows-only scenario shows the correct eligible/skipped counts and dispatches only to eligible agents.
- Selecting multiple groups with overlapping membership (a parent + one of its children) does not double-dispatch to the same agent (the `Set`-based union in `resolveGroupTargets` guarantees this).
- Non-Admin user does not see the "All Agents" option at all.
- Admin user selecting "All Agents" and confirming dispatches to every OS-eligible agent.
- The blast-radius confirm appears for Group/All targeting even in posture mode. Posture mode already shows a lightweight confirm for any manually-picked 2+ agent set (`confirmRun()`'s existing `multi` branch); for Group/All targeting that same branch's copy is replaced with the Group/All-aware wording ("...across M group(s)") rather than stacking two separate confirms.

No visual redesign is in scope — this reuses existing CSS classes/patterns already used by the "Additional Agents" checkbox list and the Campaigns modal's target-type radio.
