# Campaign Group Targeting — Design

## Why

The Run Scenario wizard already handles the fast "run this on 1-3 known
agents right now" path. What's missing is a way to launch a scenario
against an operationally meaningful population — an Agent Group — while
still getting a single trackable entity in history with a per-agent
breakdown. That entity already exists: **Campaigns**. `campaigns` (one row
per multi-agent launch, `targets jsonb` holding the resolved snapshot) and
`scenario_runs.campaign_id` (linking every child run back to its parent)
already are the "one scenario, many agents, tracked collectively" concept.
What's missing is Agent Group as a targeting *input* — today `CreateCampaign`
only accepts an explicit, client-collected `agentIds` list.

This spec adds Agent Group (and a guarded All Agents) as targeting modes on
the existing Campaign launch flow. The Run Scenario wizard is untouched.

## Architecture

```
                 SCENARIO
                    |
          +---------+---------+
          |                   |
    RUN SCENARIO           CAMPAIGN
     quick path           operational path
          |                   |
      1-3 agents        Campaign Targets
                              |
                  +-----------+-----------+
                  |           |           |
                Agent       Agents       All
                Group    (existing OS/   Agents
             (new, this   env-filtered  (new, this
                spec)      checklist)     spec,
                                         Admin-only)
                  |           |           |
                  +-----------+-----------+
                              |
                    server-side resolution
                     (live, at POST time)
                              |
                       exclusions applied
                              |
                    campaigns.targets snapshot
                     (frozen from this point on)
                              |
                     Per-Agent Execution
                     (existing dispatchRun,
                      unchanged)
```

A Campaign targets exactly one thing: a single Agent Group, an explicit
agent list, or the entire eligible fleet. Multiple groups per campaign is
explicitly out of scope (see Non-goals) — one campaign, one clear targeting
intent, matching how it's already reported and audited.

## Data model

Extend `campaigns` (no new table):

```sql
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS target_type text NOT NULL DEFAULT 'agents';
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS target_group_id bigint;
```

- `target_type` is `'group' | 'agents' | 'all'`.
- `target_group_id` is set only when `target_type = 'group'`; references
  `agent_groups.id` (`bigint`, matching that table's `BIGSERIAL` PK — see
  `orchestrator/internal/db/agent_groups_schema.go:22`). No FK constraint
  needed (agent-group deletion doesn't need to cascade into historical
  campaigns — a campaign already run keeps its resolved `targets` snapshot
  regardless of whether the group still exists).
- `DEFAULT 'agents'` means every existing campaign row reads as
  `target_type='agents'` with no backfill migration — correct, since every
  campaign created before this change was, in fact, an explicit agent list.
- `targets jsonb` (already exists) keeps its current job unchanged: the
  frozen, resolved agent-ID snapshot, for every mode. This is the
  "resolve once at launch, then it's immutable" guarantee already built
  into Campaigns — nothing new needed here, `target_type`/`target_group_id`
  just record *how* that snapshot was produced, for display and audit.

## Backend

**Group resolution, deduplicated into one place.** The recursive
group-and-descendants query already exists in two places:
`internal/jobs.Store.ResolveGroupAgentIDs` (Scheduled Assessments) and
inline in `GET /api/agents`'s `groupId` filter (`internal/api/handlers.go:576-593`).
This spec adds a third caller (`CreateCampaign`) — rather than a third copy,
extract the query into one shared helper (e.g.
`internal/agentgroups.ResolveMembers(ctx, pool, groupID int64) ([]string, error)`,
or a method the `api` package can call without a hard dependency on
`internal/jobs`) and have all three call sites use it. This is a
targeted refactor of code this change touches anyway, not unrelated
cleanup.

**`CreateCampaign` request additions** (`internal/api/campaign_handlers.go`):
- `targetType string` — `"group" | "agents" | "all"`. Defaults to `"agents"`
  if omitted, so existing API callers (if any exist outside the frontend)
  keep working unchanged.
- `groupId *int64` — required when `targetType == "group"`.
- `excludeAgentIds []string` — optional, any mode.
- `agentIds []string` stays required when `targetType == "agents"` (today's
  existing behavior, untouched); becomes optional/ignored for `"group"` and
  `"all"`.

**Resolution logic in the handler, before the existing dispatch loop:**
1. `group`: resolve via the shared helper above.
2. `agents`: use `req.AgentIDs` directly (unchanged).
3. `all`: query every agent with `state != 'retired'` (the same "retired
   excluded from default views" convention already used by `agentBucket()`
   on the frontend and mirrored server-side).
4. Subtract `excludeAgentIds` from the resolved set (a plain set
   difference — no new guardrail mechanism, this is presentational
   scoping of an already-guarded operation).
5. Continue into the existing per-agent `dispatchRun` loop unchanged —
   OS-eligibility skips, live-mode guardrails, skip recording all already
   work per-agent and need no changes.
6. Store `target_type`, `target_group_id`, and the final resolved
   `targets` snapshot (post-exclusion) exactly as `targets` is stored
   today.

**All Agents is Admin-only**, enforced server-side (`targetType == "all"`
requires `auth.HasPermission(claims.Role, auth.CanApproveRemediation)` or a
similarly Admin-only check — exact permission TBD at plan time, matching
the precedent of gating a broad/risky action behind the stricter existing
tier rather than inventing a new permission for one field). The frontend
hiding the option for non-Admins (see below) is the UX simplification, not
the security boundary — same split already established for Scheduled
Assessments' Telemetry-mode gating.

**Response additions** (`GetCampaign`, `ListCampaigns`): add `targetType`
and, when applicable, `targetGroupId` to the existing hand-built
`map[string]any` response (`campaign_handlers.go:366-371` and the
list-rollup equivalent) — camelCase, matching this handler's established
convention (distinct from the Scheduled Assessments list, which marshals a
tagless Go struct in PascalCase; Campaigns already uses the manual-map
camelCase convention, and this stays consistent with that).

## Frontend

**Live preview — no new endpoint.** `GET /api/agents?groupId=X` already
performs the identical recursive resolution and returns full agent objects
(OS, status). When a group is picked in the New Campaign modal, the
frontend calls this existing endpoint purely to render the preview (OS
breakdown, online/offline counts, a "View agents" expansion) — this is
cosmetic only. The server independently re-resolves live membership again
at actual `POST /api/campaigns` time, so the preview can never become
stale, trusted data — if group membership changes in the seconds between
opening the picker and clicking Launch, the campaign gets whatever is
actually true at launch, not what the preview showed.

**"New Campaign" modal** (`wwwroot/index.html:4047` onward): the existing
`Targets` label/section becomes `Campaign Targets` with a radio group:

```
Campaign Targets

○ Agent Group
○ Agents
○ All Agents
```

- **Agent Group** (new): a single `<select>` populated from the agent-group
  tree (flattened — reuse the existing hierarchy data, not a new fetch
  shape), plus the live preview block described above.
- **Agents** (existing, relabeled only): today's OS/environment-filtered
  checkbox list (`#cmp-targets`, `cmpSelectAllFiltered()`, etc.) — no
  behavior change, just the radio-group wrapper and label.
- **All Agents** (new): only rendered as a radio option when
  `ROLE === 'admin'` — absent entirely for non-Admins, mirroring the
  Scheduled Assessments Telemetry-mode pattern (hidden, not disabled).
  Shows the target count and a required "I understand this will execute
  against all eligible agents" confirmation checkbox gating the Launch
  button, matching your mockup.

**Exclusions**: a simple "+ Add exclusion" control under the Agent
Group / All Agents sections — a flat list of explicitly excluded agent
IDs, submitted as `excludeAgentIds`. Not available in `Agents` mode
(there, simply don't check the box for an agent you don't want — an
exclusion list would be redundant there).

**Campaign list & detail views**:
- `renderCampaignRows` (`:7324`): a small target-type indicator per row
  (e.g. a group-icon badge next to the agent count, or inline text —
  exact treatment decided at plan time to fit the existing row's compact
  layout).
- `openCampaignDetail`'s "Run summary" panel (`:7395`): one new `kv(...)`
  row — `"Target"` → `"Agent Group — Finance"` / `"Agents — 3 selected"` /
  `"All Agents"`. The group name is resolved client-side against the
  already-loaded group tree (same pattern as Scheduled Assessments' list
  view) — and, thanks to the `CanViewAgentGroups` permission shipped
  immediately before this feature, this now works correctly for Analysts
  too, not just Admins.

## Non-goals

- **No multi-group targeting.** A Campaign targets exactly one group, one
  explicit agent list, or the entire fleet — never a combination. If a
  user needs "Finance + Production," they launch two campaigns. This keeps
  the targeting intent auditable and avoids the overlap/dedup complexity a
  multi-group model would introduce, matching the explicit V1 scope
  decision made during design. If multi-group ever becomes a real
  requirement, the natural evolution is a separate `campaign_targets`
  table (`campaign_id, target_type, target_id`) — but that is not built
  now, and `target_group_id` as a single nullable column is not a
  structural trap that blocks it later.
- **No changes to the Run Scenario wizard.** It stays the fast,
  1-3-explicit-agents path, unchanged.
- **No group-vs-group exclude/include composition** (e.g. "Production
  minus Domain Controllers, but only if also in APAC"). Exclusions are a
  flat agent-ID list only, as scoped in the original proposal.
- **No changes to how a Campaign executes once targets are resolved.**
  `dispatchRun`, skip recording, live-mode guardrails, reporting — all
  unchanged. This spec is entirely about *what a Campaign targets*, not
  how it runs once targets are known.
- **No scheduled/deferred campaigns.** Campaigns launch synchronously at
  creation today, and this spec doesn't change that. "Resolve at launch,
  not at group-selection time" is naturally satisfied because launch and
  creation are the same instant for a Campaign — there's no separate
  "scheduled campaign" concept where those two moments could diverge (that
  would be a different, larger feature, not scoped here).

## Testing plan

- Backend: table-driven tests for the shared group-resolution helper
  (recursion into descendants, empty group, non-existent group ID);
  `CreateCampaign` tests for each `targetType` (group/agents/all),
  exclusion subtraction, All-Agents Admin-gating (403 for Analyst), and
  that a legacy request with no `targetType` still defaults to `"agents"`
  and behaves exactly as before this change.
  `go test ./internal/api/...`, `go test ./internal/agentgroups/...` (or
  wherever the shared helper lands — exact package decided at plan time).
- Frontend: manual browser QA (no automated test suite for this file, per
  this project's established convention) — deferred to the existing
  Pending Manual QA Backlog pattern, not blocking implementation.
