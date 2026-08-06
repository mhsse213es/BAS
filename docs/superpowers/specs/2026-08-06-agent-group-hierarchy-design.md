# Agent Group Hierarchy Design

**Goal:** Replace the cosmetic, flat "Group" column in the Agents table (which actually just renders each agent's self-reported `EnvLabel`) with a real, admin-managed hierarchical group tree — create/rename/delete/move groups, assign agents to them, filter the agent list by group.

## Background

This is the first sub-project of a larger "System Tree" vision (hierarchical org management, group policies with inheritance, dynamic/rule-based group membership, drag-and-drop tree UI, bulk operations — modeled on enterprise EDR/RMM/UEM consoles like Tanium/CrowdStrike). That full vision is far too large for one project; this spec covers only the foundational piece everything else depends on: a real static group hierarchy.

Investigated this session: no `AgentGroup`/hierarchy concept exists anywhere in the codebase today. The `Agent` struct (`orchestrator/internal/models/schema.go:275`) has no group/parent field. The Agents table's "Group" column (`orchestrator/wwwroot/index.html`, `renderAgentRows()`) renders `a.envLabel` — a flat string agents self-report at enroll time (`internal/models/schema.go:283`), not an admin-managed entity. The Fleet Job Engine dispatches bulk work via an explicit `AgentIDs []string` list (`internal/jobs/schedule.go:19`) with no group/selector concept — a real hierarchy integrates cleanly by resolving group membership into an agent-ID list and handing off to the existing dispatch engine unchanged, no changes needed there. No group-scoped RBAC exists either (out of scope here).

## Decisions from brainstorming

- **EnvLabel is replaced, not duplicated.** The Agents table's "Group" column now shows the real, admin-assigned hierarchical group. `EnvLabel` remains as agent metadata, likely useful elsewhere (self-reported context), but stops being what "Group" means in the UI.
- **Ungrouped is an implicit bucket**, not a real row. Every agent with `group_id = NULL` shows under a built-in "Ungrouped" pseudo-node at the tree root. No migration script needed for the ~100% of existing agents that have no group today.
- **Single tree per deployment, no tenant scoping.** Matches [[ADR-013]] (multi-tenancy rollout deferred to Audspect Cloud; on-prem is single-tenant-per-DB) — `agent_groups` carries no `tenant_id`.
- **Real nested tree widget** (not a flat indented admin list) — reviewed both options as a full mockup via the visual-companion brainstorming tool and approved the tree widget: expand/collapse, per-node agent counts, a `⋮` menu per node. Matches where the long-term "System Tree" vision is headed and how comparable enterprise consoles present this.
- **Embedded as a sidebar inside the existing Agents page**, not a separate admin page — Explorer-style (tree on the left, agent table on the right), selecting a node filters the table. One page, matches how Tanium/CrowdStrike structure this.
- **Delete is blocked, not cascading**, until the group has zero direct agents and zero subgroups. Deleting a non-trivial subtree could otherwise silently reassign a large number of a real customer's agents to Ungrouped in one click — too risky for a first version. The error message names exactly what's still in the way (e.g. "Finance has 38 agents and 2 subgroups — move or remove them first").

## 1. Data model

New table `agent_groups`: `id` (uuid/serial, matching this codebase's existing ID convention), `name`, `parent_id` (nullable, self-referencing FK — `NULL` means root-level), `created_at`.

`agents` gains one new nullable column: `group_id` (FK to `agent_groups.id`, `NULL` = Ungrouped). Single-parent membership only — an agent belongs to exactly one group at a time, matching "move agent between groups" semantics (not multi-membership).

Schema creation follows this codebase's existing convention: an idempotent `EnsureAgentGroupSchema(ctx, pool)` function (same shape as `EnsureIOCSchema` at `internal/db/ioc.go:16`, `EnsureContentSchema` at `internal/db/content_schema.go:24`), called from `cmd/server/main.go` alongside the other `Ensure*Schema` calls — not a separate migration-file system, which this codebase doesn't use.

**Circular-reference protection:** moving a group under one of its own descendants must be rejected server-side via an ancestor-walk check before the parent change is applied.

## 2. Backend API

All admin-only (matches existing agent-management RBAC tier):

- `POST /api/agent-groups` — create; body `{name, parentId?}`.
- `PATCH /api/agent-groups/{id}` — rename and/or move; body `{name?, parentId?}`. Rejects circular moves (400) and, per the delete-blocking decision, this endpoint is NOT where delete-blocking applies — that's the DELETE verb below.
- `DELETE /api/agent-groups/{id}` — 409 with a specific message if the group has any direct agents or subgroups; 204 on success.
- `GET /api/agent-groups` — full tree as nested JSON; each node carries its own direct agent count and a recursive descendant count (so a collapsed parent still shows "38" for Finance even though only 12 are direct members).
- `PATCH /api/agents/{id}/group` — body `{groupId: string | null}`; assigns/moves a single agent (or clears to Ungrouped).

The existing `GET /api/agents` handler (`internal/api/handlers.go:567`) gains one additive, optional query param: `groupId`. When present, results are filtered to agents whose `group_id` is that group **or any of its descendant groups** (a recursive CTE or an in-memory descendant-set walk, matching whichever pattern is more consistent with how this handler already builds its query) — so selecting "Finance" in the tree surfaces Finance + Servers + Workstations agents together, not just direct members.

No changes anywhere in `internal/jobs` — a future "run bulk assessment on this group" feature (out of scope here) would resolve group membership into an `AgentIDs` list client-side or via a thin new endpoint, then hand off to the existing, unchanged dispatch engine.

## 3. Frontend

A left-hand tree panel embedded in the Agents page (`orchestrator/wwwroot/index.html`, the Operational view under Agents), fetched once from `GET /api/agent-groups` and re-fetched after any create/rename/move/delete. Each node: expand/collapse caret, name, agent-count badge, and a `⋮` menu with exactly four actions — Rename, New subgroup, Move to..., Delete. "Move to..." is a simple search/select picker over the flat tree (not drag-and-drop, which is explicitly deferred to a future sub-project).

Selecting a node calls the existing agent-list fetch with `?groupId=<id>` appended, filtering the table in place — no new table component, reuses `renderAgentRows()`.

The Agents table's "Group" column changes from rendering `a.envLabel` to rendering the agent's real group name (or "Ungrouped"). Each row's existing action menu (`toggleRowMenu`, `internal/wwwroot/index.html:6429`) gains one new item: "Move to group...", opening the same picker dialog used by the tree panel's per-node menu.

## Non-goals

Everything else from the original "System Tree" vision is explicitly out of scope for this sub-project, to be brainstormed separately later if pursued: dynamic/rule-based group membership (auto-membership by OS/tag/compliance-score/etc.), group-level policies with inheritance (scan schedules, compliance policies, RBAC scoping, retention, proxy settings, etc.), drag-and-drop, bulk multi-select-and-move, "copy group structure"/"merge groups"/"archive group", and any bulk-operation UI beyond what the Fleet Job Engine already supports via explicit agent-ID lists.

## Testing

Backend: Go unit tests for `EnsureAgentGroupSchema` (idempotent re-run), the circular-reference rejection, the delete-blocking logic (empty vs. non-empty group), and the recursive `groupId` filter on `GET /api/agents` (parent selection includes descendant-group agents). No automated frontend test framework exists for `wwwroot/index.html` (established pattern) — frontend verification is manual: create a small 2-3-level tree, move agents between groups, confirm the table filters correctly per node, confirm delete is blocked with the right message on a non-empty group and succeeds on an empty one, confirm a circular move attempt is rejected.
