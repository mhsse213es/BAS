# CanViewAgentGroups Permission — Design

## Why

The Scheduled Assessments UI (shipped earlier this session) surfaced a
pre-existing gap: `GET /api/agent-groups` is gated on `CanManageAgentGroups`,
which only `RoleAdmin` holds. Analysts — who can see the Scheduled
Assessments nav tab and use its create/list/cancel actions (all gated
`CanExecuteRemediation`, Analyst+Admin) — get a 403 reading the group tree.
The wizard's Targets step and the list view's group-name resolution both
call this endpoint, so today an Analyst sees "Group targeting requires
Administrator access" (a frontend-only workaround already shipped) instead
of being able to see or target groups at all.

This isn't new to the Scheduled Assessments UI: the pre-existing Agents
tab's group-filter tree calls the same endpoint and has had the identical
silent-403-becomes-empty-tree problem for Analysts the whole time. This fix
resolves it at the root — the permission — rather than patching each
consumer.

## What

A new permission, `CanViewAgentGroups`, read-only, granted to Analyst+Admin
(the same tier as `CanExecuteRemediation`). `GET /api/agent-groups` moves
onto it. Every write/management action on agent groups —
`POST`/`PATCH`/`DELETE /api/agent-groups` (create/rename/move/delete a
group) and `PATCH /api/agents/{agentId}/group` (move one agent into a
group) — stays exactly as-is, gated `CanManageAgentGroups`, Admin-only.
Reading the group hierarchy and reorganizing it are different operations
with different blast radii; only the former needs to widen.

## Non-goals

- `PATCH /api/agents/{agentId}/group` does not move to the new permission.
  Moving an agent between groups is a structural change to the org's
  grouping, not a read, and stays Admin-only alongside the other three
  write routes.
- No frontend changes. The Scheduled Assessments wizard's
  `groupsAccessDenied` fallback message (added in that feature's final-review
  fix wave) is left in place as a defensive fallback — it simply stops
  firing for Analyst/Admin once this ships, and continues to degrade
  honestly rather than silently lying if a future lower-privileged role is
  ever added.
- No change to any other agent-group-adjacent permission or route.

## Implementation

All changes live in the codebase's own well-established
"add a permission constant" pattern — the same four places
`CanManageAgentGroups` itself touches, plus the equivalent test rows:

**`orchestrator/internal/auth/permissions.go`**
- New const `CanViewAgentGroups Permission = "agent-groups:view"`, declared
  immediately next to `CanManageAgentGroups` (same "Admin-only: agent
  state..." comment block gets a one-line note that this one specific
  permission is the exception, Analyst+Admin).
- Add `CanViewAgentGroups: true` to `rolePermissions[RoleAdmin]`.
- Add `CanViewAgentGroups: true` to `rolePermissions[RoleAnalyst]`.
- Add `CanViewAgentGroups` to the `Permissions()` function's enumeration
  slice, in the same relative position as the const declaration (this
  function's iteration order is asserted by a test — see below).

**`orchestrator/internal/auth/permissions_test.go`**
- `TestHasPermission_FullMatrix`: add three rows —
  `{RoleAdmin, CanViewAgentGroups, true}`,
  `{RoleAnalyst, CanViewAgentGroups, true}`,
  `{RoleViewer, CanViewAgentGroups, false}`.
- `TestHasPermission_MatrixIsComplete`: add `CanViewAgentGroups: true` to
  the `tested` map (this test fails loudly if a new permission constant is
  granted to Admin without a corresponding row above — it would already
  catch a missed update here).
- `TestPermissions_Ordering`: add `CanViewAgentGroups` to the `want` slice,
  in the same position it was added to `Permissions()`'s enumeration.

**`orchestrator/internal/api/routes.go`**
- Change the `GET /api/agent-groups` route's
  `r.With(auth.RequirePermission(auth.CanManageAgentGroups))` to
  `r.With(auth.RequirePermission(auth.CanViewAgentGroups))`. The other four
  agent-group routes on the surrounding lines are untouched.

**`orchestrator/internal/api/rbac_matrix_test.go`**
- Update the `{http.MethodGet, "/api/agent-groups", tierPermission,
  auth.CanManageAgentGroups}` row in `routeMatrix` to
  `auth.CanViewAgentGroups`. The `TestRBACMatrix_AuthorizationBoundary` test
  that consumes this matrix will then assert Analyst clears the gate for
  this route and Viewer still gets 403 — no other code needed for that
  coverage, it's driven entirely by the matrix.

## Testing plan

- `go test ./internal/auth/...` — covers the three updated tests above.
- `go test ./internal/api/... -run TestRBACMatrix_AuthorizationBoundary` —
  confirms the route-level behavior change (Analyst now clears
  `GET /api/agent-groups`, Viewer still doesn't).
- No manual/browser QA needed — this is a pure permission-boundary change
  with no UI code touched; the existing (already-shipped) frontend simply
  starts succeeding where it previously degraded to the
  `groupsAccessDenied` message.
