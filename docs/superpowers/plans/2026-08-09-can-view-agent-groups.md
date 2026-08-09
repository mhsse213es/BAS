# CanViewAgentGroups Permission Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split a new read-only `CanViewAgentGroups` permission (Analyst+Admin) off the Admin-only `CanManageAgentGroups`, and regate `GET /api/agent-groups` onto it so Analysts can read the agent-group hierarchy without gaining any write/management capability.

**Architecture:** Backend-only. One new `Permission` constant, granted to Analyst and Admin in the existing `rolePermissions` map, added to the existing `Permissions()` enumeration, and substituted onto exactly one route's `RequirePermission` gate. Every other agent-group route (create/rename/move/delete a group, move an agent into a group) stays on `CanManageAgentGroups`, unchanged.

**Tech Stack:** Go, existing `internal/auth` permission/role framework, existing `internal/api` chi-router route gating, existing Go `testing` package.

## Global Constraints

- Backend-only. No frontend file (`orchestrator/wwwroot/index.html`) is touched by this plan.
- Only `GET /api/agent-groups` moves to the new permission. `POST /api/agent-groups`, `PATCH /api/agent-groups/{id}`, `DELETE /api/agent-groups/{id}`, and `PATCH /api/agents/{agentId}/group` all stay gated `CanManageAgentGroups`, Admin-only — do not touch these four routes' gates.
- The new permission constant's string value is `"agent-groups:view"` (mirrors the existing `CanManageAgentGroups = "agent-groups:manage"` naming pattern).
- `RoleViewer` must NOT receive this permission — it holds no permissions today (`rolePermissions[RoleViewer] = {}`) and this plan does not change that.

---

### Task 1: Add `CanViewAgentGroups` permission and regate the read route

**Files:**
- Modify: `orchestrator/internal/auth/permissions.go:80` (const block), `:220` (RoleAdmin map), `:269` (RoleAnalyst map), `:298` (Permissions() enumeration)
- Modify: `orchestrator/internal/auth/permissions_test.go:10-45` (TestHasPermission_FullMatrix), `:54-106` (TestHasPermission_MatrixIsComplete), `:108-150` (TestPermissions_Ordering)
- Modify: `orchestrator/internal/api/routes.go:425`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:216`

**Interfaces:**
- Consumes: nothing new — this task only adds a constant to the existing `Permission` type and existing `rolePermissions map[Role]map[Permission]bool` structure, and existing `auth.RequirePermission(perm Permission) func(http.Handler) http.Handler` middleware.
- Produces: `auth.CanViewAgentGroups` (a `Permission` constant), granted to `RoleAdmin` and `RoleAnalyst`, withheld from `RoleViewer`. Nothing later in this plan consumes it — this is the only task.

This is one task: every edit here is small, mechanical, and only makes sense verified together (a partial application — e.g. the route regated but the role grant missing — would break Analyst access, which is the entire point of the change), so splitting it further would create an intermediate state with no independent value.

- [ ] **Step 1: Write the failing tests**

In `orchestrator/internal/auth/permissions_test.go`, find this exact block (inside `TestHasPermission_FullMatrix`):

```go
		{RoleViewer, CanVerify, false},
		{RoleViewer, CanUploadEvidence, false},
		{RoleViewer, CanDeleteEvidence, false},
		{RoleViewer, CanReview, false},
		{RoleViewer, CanExport, false},
		{RoleViewer, CanCurateThreatIntel, false},
		{RoleViewer, CanReviewThreatIntel, false},
	}
```

Replace it with:

```go
		{RoleViewer, CanVerify, false},
		{RoleViewer, CanUploadEvidence, false},
		{RoleViewer, CanDeleteEvidence, false},
		{RoleViewer, CanReview, false},
		{RoleViewer, CanExport, false},
		{RoleViewer, CanCurateThreatIntel, false},
		{RoleViewer, CanReviewThreatIntel, false},

		{RoleAdmin, CanViewAgentGroups, true},
		{RoleAnalyst, CanViewAgentGroups, true},
		{RoleViewer, CanViewAgentGroups, false},
	}
```

Next, in the same file, find this exact block (inside `TestHasPermission_MatrixIsComplete`'s `tested` map):

```go
		CanSetAgentState: true, CanStopAgent: true, CanRemoveAgent: true, CanViewLicense: true, CanViewConnectionConfig: true, CanManageAgentGroups: true,
```

Replace it with:

```go
		CanSetAgentState: true, CanStopAgent: true, CanRemoveAgent: true, CanViewLicense: true, CanViewConnectionConfig: true, CanManageAgentGroups: true, CanViewAgentGroups: true,
```

Next, in the same file, find this exact block (inside `TestPermissions_Ordering`'s `want` slice):

```go
		CanSetAgentState, CanStopAgent, CanRemoveAgent, CanViewLicense, CanViewConnectionConfig, CanManageAgentGroups, CanListUsers, CanCreateUser,
```

Replace it with:

```go
		CanSetAgentState, CanStopAgent, CanRemoveAgent, CanViewLicense, CanViewConnectionConfig, CanManageAgentGroups, CanViewAgentGroups, CanListUsers, CanCreateUser,
```

In `orchestrator/internal/api/rbac_matrix_test.go`, find this exact line:

```go
	{http.MethodGet, "/api/agent-groups", tierPermission, auth.CanManageAgentGroups},
```

Replace it with:

```go
	{http.MethodGet, "/api/agent-groups", tierPermission, auth.CanViewAgentGroups},
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd orchestrator
go build ./... 2>&1 | head -20
```

Expected: a compile error — `undefined: CanViewAgentGroups` (or `auth.CanViewAgentGroups`) — from one or more of the three files just edited. The package won't build yet because the constant doesn't exist. This compile failure is this step's "RED" — Go doesn't let you run tests against code that doesn't compile, so the build error itself is the expected failure signal here.

- [ ] **Step 3: Add the permission constant and grant it**

In `orchestrator/internal/auth/permissions.go`, find this exact line:

```go
	CanManageAgentGroups    Permission = "agent-groups:manage"
```

Replace it with:

```go
	CanManageAgentGroups    Permission = "agent-groups:manage"
	// CanViewAgentGroups is read-only and, unlike every other permission in
	// this block, is granted to Analyst as well as Admin -- reading the
	// group hierarchy is not a management action.
	CanViewAgentGroups      Permission = "agent-groups:view"
```

Next, in the same file, find this exact line (inside `rolePermissions[RoleAdmin]`):

```go
		CanSetAgentState: true, CanStopAgent: true, CanRemoveAgent: true, CanViewLicense: true, CanViewConnectionConfig: true, CanManageAgentGroups: true,
```

Replace it with:

```go
		CanSetAgentState: true, CanStopAgent: true, CanRemoveAgent: true, CanViewLicense: true, CanViewConnectionConfig: true, CanManageAgentGroups: true, CanViewAgentGroups: true,
```

Next, in the same file, find this exact block (inside `rolePermissions[RoleAnalyst]`):

```go
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,
		CanViewResponseActions: true,
		CanExecuteRemediation:  true,
	},
	RoleViewer: {},
```

Replace it with:

```go
		CanApproveExerciseStep: true, CanInjectExerciseEvidence: true, CanLookupIOC: true,
		CanViewResponseActions: true,
		// Read-only counterpart to the admin-only CanManageAgentGroups --
		// analysts can see and target agent groups, not create/rename/
		// move/delete them.
		CanViewAgentGroups: true,
		CanExecuteRemediation: true,
	},
	RoleViewer: {},
```

Next, in the same file, find this exact line (inside `Permissions()`'s enumeration slice):

```go
		CanSetAgentState, CanStopAgent, CanRemoveAgent, CanViewLicense, CanViewConnectionConfig, CanManageAgentGroups, CanListUsers, CanCreateUser,
```

Replace it with:

```go
		CanSetAgentState, CanStopAgent, CanRemoveAgent, CanViewLicense, CanViewConnectionConfig, CanManageAgentGroups, CanViewAgentGroups, CanListUsers, CanCreateUser,
```

- [ ] **Step 4: Regate the route**

In `orchestrator/internal/api/routes.go`, find this exact line:

```go
		r.With(auth.RequirePermission(auth.CanManageAgentGroups)).Get("/api/agent-groups", h.GetAgentGroups)
```

Replace it with:

```go
		r.With(auth.RequirePermission(auth.CanViewAgentGroups)).Get("/api/agent-groups", h.GetAgentGroups)
```

Do not modify the four lines immediately following it (`Post`, `Patch .../{id}`, `Delete .../{id}`, `Patch .../{agentId}/group`) — all four stay on `auth.CanManageAgentGroups`.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd orchestrator
go build ./...
go test ./internal/auth/... -v
```

Expected: clean build, then `TestHasPermission_FullMatrix`, `TestHasPermission_MatrixIsComplete`, and `TestPermissions_Ordering` all PASS.

```bash
go test ./internal/api/... -run TestRBACMatrix_AuthorizationBoundary -v
```

Expected: PASS. This is a container-backed test (spins up Postgres via testcontainers) — if Docker isn't available in this environment, confirm `docker info` succeeds first; this project's established convention is to run Docker-gated Go tests directly rather than deferring them.

- [ ] **Step 6: Run the full affected-package suites**

```bash
cd orchestrator
go test ./internal/auth/...
go test ./internal/api/...
```

Expected: `internal/auth` fully green. `internal/api` green except the pre-existing, unrelated `TestSearchOperators_ReturnsSupportedList` failure (a known stale test, untouched by this change — confirm via `git status` / `git diff` that this task's diff never touches `search_handlers.go` or `search_handlers_test.go`). If any *other* `internal/api` test fails, treat it as a real regression from this change and investigate before proceeding.

- [ ] **Step 7: Commit and push**

```bash
cd orchestrator
git add internal/auth/permissions.go internal/auth/permissions_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(auth): CanViewAgentGroups permission for Analyst+Admin read access

Splits a read-only permission off the Admin-only CanManageAgentGroups so
Analysts can read GET /api/agent-groups. Every write/management route
(create/rename/move/delete a group, move an agent into a group) stays
Admin-only, unchanged."
git push
```

---

## Self-Review

**1. Spec coverage:**
- New `CanViewAgentGroups` permission, Analyst+Admin, Viewer excluded — Step 3.
- `GET /api/agent-groups` regated onto it — Step 4.
- The other four agent-group routes explicitly left untouched — Step 4's note, verified by the diff only ever touching one line in `routes.go`.
- Three existing exhaustiveness/ordering test guards updated (`TestHasPermission_FullMatrix`, `TestHasPermission_MatrixIsComplete`, `TestPermissions_Ordering`) — Step 1/3.
- `rbac_matrix_test.go`'s route-level assertion updated — Step 1.
- Testing plan from the spec (`go test ./internal/auth/...`, `go test ./internal/api/... -run TestRBACMatrix_AuthorizationBoundary`) — Step 5/6.
- No frontend changes — no `wwwroot/index.html` edit appears anywhere in this plan.

**2. Placeholder scan:** no TBD/TODO; every step shows the literal exact-match old/new code; no "similar to Task N" references (this plan has only one task).

**3. Type consistency:** the constant name `CanViewAgentGroups` and its string value `"agent-groups:view"` are used identically everywhere they appear (const declaration, both role-map grants, the `Permissions()` enumeration, both test files, `routes.go`) — no alternate spelling or casing introduced anywhere in the plan.
