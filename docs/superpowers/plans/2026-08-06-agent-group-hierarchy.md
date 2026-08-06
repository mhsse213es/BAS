# Agent Group Hierarchy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the cosmetic, EnvLabel-based "Group" column in the Agents table with a real, admin-managed hierarchical group tree — create/rename/delete/move groups, assign agents, filter the agent list by group.

**Architecture:** A new `agent_groups` table plus one new nullable `agents.group_id` column, no hard FK constraint (this codebase doesn't use them elsewhere — referential integrity and the circular-reference check both need application-level logic anyway). Five REST endpoints under a new admin-only permission. The existing agent list endpoint gains one additive `groupId` filter. Frontend adds a tree panel to the existing Agents page and swaps the "Group" column's data source.

**Tech Stack:** Go (`pgx/v5`, `chi`), vanilla JS in `orchestrator/wwwroot/index.html`, PostgreSQL.

## Global Constraints

- No hard DB-level FK constraint between `agents.group_id` and `agent_groups.id` — matches this codebase's existing loosely-coupled schema convention (no visible `REFERENCES` clauses elsewhere), and a DB FK wouldn't prevent parent-cycles anyway, which needs an app-level walk regardless.
- Single-parent membership only: one agent belongs to exactly one group (or none) at a time. No multi-membership.
- `EnvLabel` (`agents.env_label`) is untouched everywhere except the one place it's currently mislabeled "Group" (`index.html:6400`) — it still powers its own, separate "Environment" filter dropdown (`index.html:7186`, `:7421`) and the Agent Detail drawer's "Environment" field (`index.html:14570`). Do not remove or rename `EnvLabel` anywhere.
- Delete is blocked (409), never cascading, until a group has zero direct agents and zero subgroups.
- No tenant scoping (`agent_groups` has no `tenant_id`), no dynamic/rule-based membership, no policies, no drag-and-drop — all explicitly out of scope per the spec's Non-goals.

---

### Task 1: Data model — `agent_groups` table and `agents.group_id`

**Files:**
- Create: `orchestrator/internal/db/agent_groups_schema.go`
- Test: `orchestrator/internal/db/agent_groups_schema_test.go`
- Modify: `orchestrator/cmd/server/main.go:100-103`

**Interfaces:**
- Produces: `db.EnsureAgentGroupSchema(ctx context.Context, pool *pgxpool.Pool) error` — creates `agent_groups` and adds `agents.group_id`. Task 2's handlers query/write these tables/columns directly via SQL, no Go struct/DAO layer is produced here (matches how `GetAgents`/other handlers already do raw SQL, not a repository pattern).

- [ ] **Step 1: Write the failing idempotency test**

Create `orchestrator/internal/db/agent_groups_schema_test.go`:

```go
package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

// EnsureAgentGroupSchema must be safe to call repeatedly (startup runs it
// every boot) and must leave both the new table and the new agents column
// in place.
func TestEnsureAgentGroupSchema_Idempotent(t *testing.T) {
	ctx := context.Background()
	if err := db.EnsureAgentGroupSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("first EnsureAgentGroupSchema: %v", err)
	}
	if err := db.EnsureAgentGroupSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("second EnsureAgentGroupSchema (idempotency): %v", err)
	}

	var tableExists bool
	err := sharedDB.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'agent_groups')`,
	).Scan(&tableExists)
	if err != nil {
		t.Fatalf("checking agent_groups table: %v", err)
	}
	if !tableExists {
		t.Error("agent_groups table was not created")
	}

	var columnExists bool
	err = sharedDB.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agents' AND column_name = 'group_id')`,
	).Scan(&columnExists)
	if err != nil {
		t.Fatalf("checking agents.group_id column: %v", err)
	}
	if !columnExists {
		t.Error("agents.group_id column was not added")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureAgentGroupSchema_Idempotent -v`
Expected: `FAIL` — `db.EnsureAgentGroupSchema` is undefined (compile error). (If this instead reports "no such database"/skips, follow this codebase's established `TEST_DATABASE_URL` convention for DB-backed tests — see how `sharedDB` is initialized in the `internal/db` test package to confirm the skip behavior before proceeding; do not point it at the client production database.)

- [ ] **Step 3: Implement `EnsureAgentGroupSchema`**

Create `orchestrator/internal/db/agent_groups_schema.go`:

```go
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureAgentGroupSchema creates the agent_groups table and adds agents.group_id.
// Idempotent — safe to call on every startup. Must run after EnsureSchema
// (the agents table must already exist for the ALTER TABLE to succeed).
//
// No FK constraint from agents.group_id to agent_groups.id or from
// agent_groups.parent_id to agent_groups.id — this codebase doesn't use hard
// FKs elsewhere, and a cycle in parent_id (e.g. moving a group under its own
// descendant) has to be rejected at the application layer regardless, since a
// plain self-referencing FK can't express "no cycles."
func EnsureAgentGroupSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS agent_groups (
			id         BIGSERIAL PRIMARY KEY,
			name       TEXT NOT NULL,
			parent_id  BIGINT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_groups_parent_id ON agent_groups(parent_id)`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS group_id BIGINT`,
		`CREATE INDEX IF NOT EXISTS idx_agents_group_id ON agents(group_id)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("agent group schema: %w", err)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureAgentGroupSchema_Idempotent -v`
Expected: `PASS`.

- [ ] **Step 5: Wire the call into `main.go`**

In `orchestrator/cmd/server/main.go`, replace (currently lines 100-103):

```go
	if err := db.EnsureIOCEnrichmentSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] ioc enrichment schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")
```

with:

```go
	if err := db.EnsureIOCEnrichmentSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] ioc enrichment schema bootstrap: %v", err)
	}
	if err := db.EnsureAgentGroupSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] agent group schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")
```

- [ ] **Step 6: Build and run the full db package test suite**

Run: `cd orchestrator && go build ./... && go test ./internal/db/... -v`
Expected: build succeeds, all tests in the package pass (including the new one and everything pre-existing — confirms no regression).

- [ ] **Step 7: Commit**

```bash
git add internal/db/agent_groups_schema.go internal/db/agent_groups_schema_test.go cmd/server/main.go
git commit -m "$(cat <<'EOF'
feat(db): add agent_groups table and agents.group_id column

New EnsureAgentGroupSchema, following the existing EnsureIOCSchema/
EnsureContentSchema pattern -- idempotent, wired into main.go's
startup schema-verification sequence. No hard FK constraints, matching
this codebase's existing convention; the circular-reference check for
group moves has to be application-level regardless.
EOF
)"
git push
```

---

### Task 2: Backend API — 5 endpoints, permission, and the groupId filter

**Files:**
- Create: `orchestrator/internal/api/agent_groups_handlers.go`
- Create: `orchestrator/internal/api/agent_groups_handlers_test.go`
- Modify: `orchestrator/internal/auth/permissions.go` (new `CanManageAgentGroups` permission)
- Modify: `orchestrator/internal/auth/permissions_test.go` (mirror the new permission in existing test expectations)
- Modify: `orchestrator/internal/api/routes.go` (register 5 new routes)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (5 new table entries)
- Modify: `orchestrator/internal/api/handlers.go:567-608` (`GetAgents` — add `groupId` filter)
- Modify: `orchestrator/internal/models/schema.go:275-299` (`Agent` struct — add `GroupID`/`GroupName`)

**Interfaces:**
- Consumes: `agent_groups` table and `agents.group_id` column from Task 1.
- Produces: `GET /api/agent-groups` (nested tree JSON), `POST /api/agent-groups`, `PATCH /api/agent-groups/{id}`, `DELETE /api/agent-groups/{id}`, `PATCH /api/agents/{id}/group`, and `GET /api/agents?groupId=<id>` — all consumed by Task 3's frontend.

- [ ] **Step 1: Add the `Agent` struct fields**

In `orchestrator/internal/models/schema.go`, replace (currently lines 275-299):

```go
type Agent struct {
	AgentID       string        `json:"agentId"`
	Hostname      string        `json:"hostname"`
	IPAddress     string        `json:"ipAddress"`
	OSVersion     string        `json:"osVersion"`
	Username      string        `json:"username"`
	Status        string        `json:"status"` // idle | scanning | offline (connectivity)
	State         AgentState    `json:"state"`  // active | restricted | quarantined | retired (lifecycle)
	EnvLabel      string        `json:"envLabel"`
	HasReport     bool          `json:"hasReport"`
	BinaryHash    string        `json:"binaryHash,omitempty"`
	BinaryTrusted bool          `json:"binaryTrusted"`
	Policy        *PolicyBundle `json:"policy,omitempty"`
	EnrolledAt    *time.Time    `json:"enrolledAt,omitempty"`
	LastUpdate    time.Time     `json:"lastUpdate"`
	Sims          int           `json:"sims"` // scenario runs dispatched to this agent (all time)
	// StoppedBy/StoppedAt/StopReason are set when an Admin dispatches a
	// durable remote stop (see StopAgent handler); cleared on re-enroll.
	// StoppedBy holds the raw user ID (matches audit_logs.actor_id);
	// StoppedByName is resolved read-time via a users join for display.
	StoppedBy     *string    `json:"stoppedBy,omitempty"`
	StoppedByName *string    `json:"stoppedByName,omitempty"`
	StoppedAt     *time.Time `json:"stoppedAt,omitempty"`
	StopReason    *string    `json:"stopReason,omitempty"`
}
```

with:

```go
type Agent struct {
	AgentID       string        `json:"agentId"`
	Hostname      string        `json:"hostname"`
	IPAddress     string        `json:"ipAddress"`
	OSVersion     string        `json:"osVersion"`
	Username      string        `json:"username"`
	Status        string        `json:"status"` // idle | scanning | offline (connectivity)
	State         AgentState    `json:"state"`  // active | restricted | quarantined | retired (lifecycle)
	EnvLabel      string        `json:"envLabel"`
	HasReport     bool          `json:"hasReport"`
	BinaryHash    string        `json:"binaryHash,omitempty"`
	BinaryTrusted bool          `json:"binaryTrusted"`
	Policy        *PolicyBundle `json:"policy,omitempty"`
	EnrolledAt    *time.Time    `json:"enrolledAt,omitempty"`
	LastUpdate    time.Time     `json:"lastUpdate"`
	Sims          int           `json:"sims"` // scenario runs dispatched to this agent (all time)
	// StoppedBy/StoppedAt/StopReason are set when an Admin dispatches a
	// durable remote stop (see StopAgent handler); cleared on re-enroll.
	// StoppedBy holds the raw user ID (matches audit_logs.actor_id);
	// StoppedByName is resolved read-time via a users join for display.
	StoppedBy     *string    `json:"stoppedBy,omitempty"`
	StoppedByName *string    `json:"stoppedByName,omitempty"`
	StoppedAt     *time.Time `json:"stoppedAt,omitempty"`
	StopReason    *string    `json:"stopReason,omitempty"`
	// GroupID/GroupName are the agent's hierarchical group assignment (nil =
	// Ungrouped). GroupName is resolved read-time via a join, same pattern
	// as StoppedByName above.
	GroupID   *int64  `json:"groupId,omitempty"`
	GroupName *string `json:"groupName,omitempty"`
}
```

- [ ] **Step 2: Add the `CanManageAgentGroups` permission**

In `orchestrator/internal/auth/permissions.go`, replace (currently lines 74-79):

```go
	// Admin-only: agent state, license, connection config.
	CanSetAgentState        Permission = "agents:set-state"
	CanStopAgent            Permission = "agents:stop"
	CanRemoveAgent          Permission = "agents:remove"
	CanViewLicense          Permission = "license:view"
	CanViewConnectionConfig Permission = "config:view-connection"
```

with:

```go
	// Admin-only: agent state, license, connection config.
	CanSetAgentState        Permission = "agents:set-state"
	CanStopAgent            Permission = "agents:stop"
	CanRemoveAgent          Permission = "agents:remove"
	CanViewLicense          Permission = "license:view"
	CanViewConnectionConfig Permission = "config:view-connection"
	CanManageAgentGroups    Permission = "agent-groups:manage"
```

Then, in the same file, find the admin role's permission map (currently at line 219: `CanSetAgentState: true, CanStopAgent: true, CanRemoveAgent: true, CanViewLicense: true, CanViewConnectionConfig: true,`) and add `CanManageAgentGroups: true` to that same line:

```go
		CanSetAgentState: true, CanStopAgent: true, CanRemoveAgent: true, CanViewLicense: true, CanViewConnectionConfig: true, CanManageAgentGroups: true,
```

Then find the canonical ordered list inside `func Permissions(role Role) []Permission` (currently at line 297: `CanSetAgentState, CanStopAgent, CanRemoveAgent, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,`) and add `CanManageAgentGroups` there too:

```go
		CanSetAgentState, CanStopAgent, CanRemoveAgent, CanViewLicense, CanViewConnectionConfig, CanManageAgentGroups, CanListUsers, CanCreateUser,
```

(Both additions are required — `Permissions()` only ever returns permissions present in its own canonical list, even if the role map grants them, so omitting either half means the permission silently never appears for anyone.)

- [ ] **Step 3: Mirror the permission in `permissions_test.go`**

In `orchestrator/internal/auth/permissions_test.go`, find the three lines matching `CanSetAgentState: true, CanStopAgent: true, CanRemoveAgent: true, CanViewLicense: true, CanViewConnectionConfig: true,` (line 72) and `CanSetAgentState, CanStopAgent, CanRemoveAgent, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,` (line 124) — add `CanManageAgentGroups` to each in the same position as Step 2's edits (`CanManageAgentGroups: true` after `CanViewConnectionConfig: true,` on line 72; `CanManageAgentGroups` after `CanViewConnectionConfig,` on line 124). Line 226 (`CanSetAgentState, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,`) is a *different*, smaller role's expected list (no `CanStopAgent`/`CanRemoveAgent` present) — leave it unchanged, since `CanManageAgentGroups` is admin-only same as `CanStopAgent`/`CanRemoveAgent`, not part of that smaller role.

- [ ] **Step 4: Run the permissions package tests**

Run: `cd orchestrator && go test ./internal/auth/... -v`
Expected: `PASS` for all tests — confirms the new permission is consistently registered everywhere the existing tests check for completeness.

- [ ] **Step 5: Write the failing handler tests**

Create `orchestrator/internal/api/agent_groups_handlers_test.go`:

```go
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A group with no agents and no subgroups deletes cleanly.
func TestDeleteAgentGroup_EmptyGroupSucceeds(t *testing.T) {
	env := newTestEnv(t) // existing test harness -- see other *_test.go files in this package for its exact constructor name/shape if this doesn't match
	defer env.cleanup()

	createBody, _ := json.Marshal(map[string]string{"name": "Temp Group"})
	req := httptest.NewRequest(http.MethodPost, "/api/agent-groups", bytes.NewReader(createBody))
	req = req.WithContext(env.adminContext(req.Context()))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create group: status %d body %s", w.Code, w.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/agent-groups/"+itoa(created.ID), nil)
	delReq = delReq.WithContext(env.adminContext(delReq.Context()))
	delW := httptest.NewRecorder()
	env.router.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusNoContent {
		t.Errorf("delete empty group: status %d, want 204", delW.Code)
	}
}

// A group with agents in it cannot be deleted -- 409, not a silent cascade.
func TestDeleteAgentGroup_NonEmptyGroupBlocked(t *testing.T) {
	env := newTestEnv(t)
	defer env.cleanup()

	createBody, _ := json.Marshal(map[string]string{"name": "Finance"})
	req := httptest.NewRequest(http.MethodPost, "/api/agent-groups", bytes.NewReader(createBody))
	req = req.WithContext(env.adminContext(req.Context()))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	var created struct {
		ID int64 `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &created)

	agentID := env.seedAgent(t) // existing helper elsewhere in this package that inserts a bare test agent row -- check other handler tests for the exact name
	assignBody, _ := json.Marshal(map[string]int64{"groupId": created.ID})
	assignReq := httptest.NewRequest(http.MethodPatch, "/api/agents/"+agentID+"/group", bytes.NewReader(assignBody))
	assignReq = assignReq.WithContext(env.adminContext(assignReq.Context()))
	assignW := httptest.NewRecorder()
	env.router.ServeHTTP(assignW, assignReq)
	if assignW.Code != http.StatusOK {
		t.Fatalf("assign agent to group: status %d body %s", assignW.Code, assignW.Body.String())
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/agent-groups/"+itoa(created.ID), nil)
	delReq = delReq.WithContext(env.adminContext(delReq.Context()))
	delW := httptest.NewRecorder()
	env.router.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusConflict {
		t.Errorf("delete non-empty group: status %d, want 409", delW.Code)
	}
}

// Moving a group under its own descendant must be rejected, not silently applied.
func TestPatchAgentGroup_CircularMoveRejected(t *testing.T) {
	env := newTestEnv(t)
	defer env.cleanup()

	parentID := env.createAgentGroup(t, "Parent", nil)
	childID := env.createAgentGroup(t, "Child", &parentID)

	moveBody, _ := json.Marshal(map[string]int64{"parentId": childID})
	req := httptest.NewRequest(http.MethodPatch, "/api/agent-groups/"+itoa(parentID), bytes.NewReader(moveBody))
	req = req.WithContext(env.adminContext(req.Context()))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("circular move: status %d, want 400", w.Code)
	}
}

// GET /api/agents?groupId=X must include agents in X's subgroups, not just
// direct members.
func TestGetAgents_GroupIDFilterIncludesDescendants(t *testing.T) {
	env := newTestEnv(t)
	defer env.cleanup()

	parentID := env.createAgentGroup(t, "Finance", nil)
	childID := env.createAgentGroup(t, "Servers", &parentID)

	agentID := env.seedAgent(t)
	assignBody, _ := json.Marshal(map[string]int64{"groupId": childID})
	assignReq := httptest.NewRequest(http.MethodPatch, "/api/agents/"+agentID+"/group", bytes.NewReader(assignBody))
	assignReq = assignReq.WithContext(env.adminContext(assignReq.Context()))
	env.router.ServeHTTP(httptest.NewRecorder(), assignReq)

	req := httptest.NewRequest(http.MethodGet, "/api/agents?groupId="+itoa(parentID), nil)
	req = req.WithContext(env.adminContext(req.Context()))
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get agents by group: status %d body %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !bytes.Contains([]byte(body), []byte(agentID)) {
		t.Errorf("agent %s (in child group Servers) missing from parent group Finance's filtered list: %s", agentID, body)
	}
}

func itoa(n int64) string {
	return json.Number(bytesToStr(n)).String()
}
func bytesToStr(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
```

Note: this test file references `newTestEnv`, `env.adminContext`, `env.seedAgent`, and `env.createAgentGroup` as if a shared test harness already exists in this package (`internal/api`) — **before writing the real version of this file, grep `internal/api/*_test.go` for the actual existing test-setup helper names and constructor shape** (e.g. `TestMain`, a shared router/pool fixture, however admin-role JWT claims get injected into a test request's context elsewhere in this package) and adjust every one of these calls to match the real, already-established pattern rather than inventing new helper names. `env.createAgentGroup(t, name, parentID)` is a new small helper you'll need to add (a thin wrapper that POSTs and returns the created ID, reused by all four tests here) — write it once, alongside the test functions, following whatever helper-declaration convention the existing test file(s) in this package use.

- [ ] **Step 6: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestDeleteAgentGroup|TestPatchAgentGroup|TestGetAgents_GroupIDFilter" -v`
Expected: `FAIL` — compile errors (handlers/routes don't exist yet), or `newTestEnv`/`adminContext`/`seedAgent` mismatches once you've corrected them to the real harness names — either way, confirms nothing here accidentally passes before implementation exists.

- [ ] **Step 7: Implement the handlers**

Create `orchestrator/internal/api/agent_groups_handlers.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// AgentGroupNode is one node in the tree returned by GET /api/agent-groups.
type AgentGroupNode struct {
	ID               int64            `json:"id"`
	Name             string           `json:"name"`
	ParentID         *int64           `json:"parentId,omitempty"`
	DirectAgentCount int              `json:"directAgentCount"`
	TotalAgentCount  int              `json:"totalAgentCount"` // direct + all descendants
	Children         []AgentGroupNode `json:"children,omitempty"`
}

// GET /api/agent-groups — the full tree, nested, with per-node agent counts.
// Admin-only (CanManageAgentGroups, enforced by the route).
func (h *Handler) GetAgentGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(), `SELECT id, name, parent_id FROM agent_groups ORDER BY name`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type flat struct {
		ID       int64
		Name     string
		ParentID *int64
	}
	var flats []flat
	for rows.Next() {
		var f flat
		if err := rows.Scan(&f.ID, &f.Name, &f.ParentID); err != nil {
			rows.Close()
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		flats = append(flats, f)
	}
	rows.Close()

	directCounts := map[int64]int{}
	countRows, err := h.db.Query(r.Context(),
		`SELECT group_id, COUNT(*) FROM agents WHERE group_id IS NOT NULL GROUP BY group_id`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for countRows.Next() {
		var gid int64
		var cnt int
		if err := countRows.Scan(&gid, &cnt); err != nil {
			countRows.Close()
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		directCounts[gid] = cnt
	}
	countRows.Close()

	childrenOf := map[int64][]flat{}
	var roots []flat
	for _, f := range flats {
		if f.ParentID == nil {
			roots = append(roots, f)
		} else {
			childrenOf[*f.ParentID] = append(childrenOf[*f.ParentID], f)
		}
	}

	var build func(f flat) AgentGroupNode
	build = func(f flat) AgentGroupNode {
		node := AgentGroupNode{ID: f.ID, Name: f.Name, ParentID: f.ParentID, DirectAgentCount: directCounts[f.ID]}
		total := node.DirectAgentCount
		for _, c := range childrenOf[f.ID] {
			child := build(c)
			total += child.TotalAgentCount
			node.Children = append(node.Children, child)
		}
		node.TotalAgentCount = total
		return node
	}

	out := make([]AgentGroupNode, 0, len(roots))
	for _, r := range roots {
		out = append(out, build(r))
	}
	respond(w, out)
}

// POST /api/agent-groups — create. Body: {name, parentId?}.
func (h *Handler) CreateAgentGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		ParentID *int64 `json:"parentId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	var id int64
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO agent_groups (name, parent_id) VALUES ($1, $2) RETURNING id`,
		body.Name, body.ParentID).Scan(&id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondStatus(w, map[string]any{"id": id, "name": body.Name, "parentId": body.ParentID}, http.StatusCreated)
}

// PATCH /api/agent-groups/{id} — rename and/or move. Body: {name?, parentId?}.
func (h *Handler) UpdateAgentGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var body struct {
		Name     *string `json:"name"`
		ParentID *int64  `json:"parentId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if body.ParentID != nil {
		if *body.ParentID == id {
			jsonError(w, "a group cannot be its own parent", http.StatusBadRequest)
			return
		}
		// Walk upward from the proposed new parent; if we reach id, this move
		// would create a cycle (id would become an ancestor of itself).
		cur := *body.ParentID
		for {
			var next *int64
			err := h.db.QueryRow(r.Context(), `SELECT parent_id FROM agent_groups WHERE id = $1`, cur).Scan(&next)
			if err != nil {
				jsonError(w, "parent group not found", http.StatusBadRequest)
				return
			}
			if next == nil {
				break
			}
			if *next == id {
				jsonError(w, "cannot move a group under its own descendant", http.StatusBadRequest)
				return
			}
			cur = *next
		}
	}

	if body.Name != nil {
		if _, err := h.db.Exec(r.Context(), `UPDATE agent_groups SET name = $1 WHERE id = $2`, *body.Name, id); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if body.ParentID != nil {
		if _, err := h.db.Exec(r.Context(), `UPDATE agent_groups SET parent_id = $1 WHERE id = $2`, *body.ParentID, id); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	respond(w, map[string]any{"id": id})
}

// DELETE /api/agent-groups/{id} — blocked (409) unless empty of both direct
// agents and subgroups.
func (h *Handler) DeleteAgentGroup(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var agentCount, subgroupCount int
	if err := h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM agents WHERE group_id = $1`, id).Scan(&agentCount); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM agent_groups WHERE parent_id = $1`, id).Scan(&subgroupCount); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if agentCount > 0 || subgroupCount > 0 {
		jsonError(w, "group has "+strconv.Itoa(agentCount)+" agent(s) and "+strconv.Itoa(subgroupCount)+" subgroup(s) — move or remove them first", http.StatusConflict)
		return
	}
	if _, err := h.db.Exec(r.Context(), `DELETE FROM agent_groups WHERE id = $1`, id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PATCH /api/agents/{agentId}/group — assign/move a single agent. Body: {groupId: number|null}.
func (h *Handler) SetAgentGroup(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		GroupID *int64 `json:"groupId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := h.db.Exec(r.Context(), `UPDATE agents SET group_id = $1 WHERE agent_id = $2`, body.GroupID, agentID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"agentId": agentID, "groupId": body.GroupID})
}
```

- [ ] **Step 8: Add the `groupId` filter to `GetAgents`**

In `orchestrator/internal/api/handlers.go`, replace (currently lines 567-608):

```go
func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT a.agent_id, a.hostname, a.ip_address, a.os_version, a.username, a.status, a.env_label,
		        a.has_report, a.binary_hash, a.binary_trusted, a.last_update,
		        COALESCE(a.state, 'active'), COALESCE(a.policy_json::text, '{}'), a.enrolled_at,
		        (SELECT COUNT(*) FROM scenario_runs sr WHERE sr.agent_id = a.agent_id) AS sims,
		        a.stopped_by, COALESCE(u.username, a.stopped_by), a.stopped_at, a.stop_reason
		 FROM agents a LEFT JOIN users u ON u.id = a.stopped_by
		 ORDER BY a.last_update DESC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	now := time.Now()
	var agents []models.Agent
	for rows.Next() {
		var a models.Agent
		var stateStr, policyRaw string
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSVersion,
			&a.Username, &a.Status, &a.EnvLabel, &a.HasReport,
			&a.BinaryHash, &a.BinaryTrusted, &a.LastUpdate,
			&stateStr, &policyRaw, &a.EnrolledAt, &a.Sims,
			&a.StoppedBy, &a.StoppedByName, &a.StoppedAt, &a.StopReason); err != nil {
			continue
		}
		// Connectivity is heartbeat-driven: a dead/rebooted agent stops updating
		// last_update, so surface it as offline rather than its frozen last status.
		a.Status = models.EffectiveAgentStatus(a.Status, a.LastUpdate, now)
		a.State = models.AgentState(stateStr)
		var p models.PolicyBundle
		if err := json.Unmarshal([]byte(policyRaw), &p); err == nil {
			a.Policy = &p
		}
		agents = append(agents, a)
	}
	if agents == nil {
		agents = []models.Agent{}
	}
	respond(w, agents)
}
```

with:

```go
func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	groupIDParam := r.URL.Query().Get("groupId")
	var groupFilterClause string
	var groupFilterArg any
	if groupIDParam != "" {
		groupID, err := strconv.ParseInt(groupIDParam, 10, 64)
		if err != nil {
			jsonError(w, "invalid groupId", http.StatusBadRequest)
			return
		}
		// Recursive CTE: the target group plus every descendant group,
		// so selecting "Finance" also surfaces agents in "Servers"/"Workstations".
		groupFilterClause = ` AND a.group_id IN (
			WITH RECURSIVE descendants(id) AS (
				SELECT id FROM agent_groups WHERE id = $2
				UNION ALL
				SELECT g.id FROM agent_groups g JOIN descendants d ON g.parent_id = d.id
			)
			SELECT id FROM descendants
		)`
		groupFilterArg = groupID
	}

	query := `SELECT a.agent_id, a.hostname, a.ip_address, a.os_version, a.username, a.status, a.env_label,
	        a.has_report, a.binary_hash, a.binary_trusted, a.last_update,
	        COALESCE(a.state, 'active'), COALESCE(a.policy_json::text, '{}'), a.enrolled_at,
	        (SELECT COUNT(*) FROM scenario_runs sr WHERE sr.agent_id = a.agent_id) AS sims,
	        a.stopped_by, COALESCE(u.username, a.stopped_by), a.stopped_at, a.stop_reason,
	        a.group_id, g.name
	 FROM agents a LEFT JOIN users u ON u.id = a.stopped_by LEFT JOIN agent_groups g ON g.id = a.group_id
	 WHERE 1=1` + groupFilterClause + `
	 ORDER BY a.last_update DESC`

	var rows pgx.Rows
	var err error
	if groupFilterArg != nil {
		rows, err = h.db.Query(r.Context(), query, nil, groupFilterArg)
	} else {
		rows, err = h.db.Query(r.Context(), query, nil)
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	now := time.Now()
	var agents []models.Agent
	for rows.Next() {
		var a models.Agent
		var stateStr, policyRaw string
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSVersion,
			&a.Username, &a.Status, &a.EnvLabel, &a.HasReport,
			&a.BinaryHash, &a.BinaryTrusted, &a.LastUpdate,
			&stateStr, &policyRaw, &a.EnrolledAt, &a.Sims,
			&a.StoppedBy, &a.StoppedByName, &a.StoppedAt, &a.StopReason,
			&a.GroupID, &a.GroupName); err != nil {
			continue
		}
		// Connectivity is heartbeat-driven: a dead/rebooted agent stops updating
		// last_update, so surface it as offline rather than its frozen last status.
		a.Status = models.EffectiveAgentStatus(a.Status, a.LastUpdate, now)
		a.State = models.AgentState(stateStr)
		var p models.PolicyBundle
		if err := json.Unmarshal([]byte(policyRaw), &p); err == nil {
			a.Policy = &p
		}
		agents = append(agents, a)
	}
	if agents == nil {
		agents = []models.Agent{}
	}
	respond(w, agents)
}
```

This uses a `$1`-positioned unused placeholder (`nil`) only when there's no group filter, to keep parameter numbering (`$2` for the group filter) consistent whether or not the clause is present — **before finalizing**, verify `h.db.Query` accepts a `nil` placeholder cleanly in this codebase's pgx version, and if not, switch to building the query string with `$1` for the group filter when present (no leading unused param) instead of a fixed `$2`; check how other handlers in this file conditionally build parameterized `WHERE` clauses (e.g. search for another handler with an optional filter param) and match that exact convention rather than the two-variant sketch above.

Add `"strconv"` to `handlers.go`'s import block if not already present (it already is, confirmed earlier — `internal/api/handlers.go` imports `strconv` for `GetUnifiedTechniques` and others), and confirm `pgx` is already imported (it is, per the existing `"github.com/jackc/pgx/v5"` import for other handlers in this file).

- [ ] **Step 9: Register the 5 routes**

In `orchestrator/internal/api/routes.go`, find where other `auth.RequirePermission`-gated agent routes are registered (near line 420-422, the `CanSetAgentState`/`CanStopAgent`/`CanRemoveAgent` routes) and add:

```go
		r.With(auth.RequirePermission(auth.CanManageAgentGroups)).Get("/api/agent-groups", h.GetAgentGroups)
		r.With(auth.RequirePermission(auth.CanManageAgentGroups)).Post("/api/agent-groups", h.CreateAgentGroup)
		r.With(auth.RequirePermission(auth.CanManageAgentGroups)).Patch("/api/agent-groups/{id}", h.UpdateAgentGroup)
		r.With(auth.RequirePermission(auth.CanManageAgentGroups)).Delete("/api/agent-groups/{id}", h.DeleteAgentGroup)
		r.With(auth.RequirePermission(auth.CanManageAgentGroups)).Patch("/api/agents/{agentId}/group", h.SetAgentGroup)
```

- [ ] **Step 10: Add the RBAC matrix entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, near the existing `CanRemoveAgent` entry (currently line 214), add:

```go
	{http.MethodGet, "/api/agent-groups", tierPermission, auth.CanManageAgentGroups},
	{http.MethodPost, "/api/agent-groups", tierPermission, auth.CanManageAgentGroups},
	{http.MethodPatch, "/api/agent-groups/{id}", tierPermission, auth.CanManageAgentGroups},
	{http.MethodDelete, "/api/agent-groups/{id}", tierPermission, auth.CanManageAgentGroups},
	{http.MethodPatch, "/api/agents/{agentId}/group", tierPermission, auth.CanManageAgentGroups},
```

- [ ] **Step 11: Run the tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/auth/... ./internal/api/... -run "TestDeleteAgentGroup|TestPatchAgentGroup|TestGetAgents_GroupIDFilter|TestRBAC" -v`
Expected: build succeeds, all matched tests `PASS`, including the RBAC matrix confirming all 5 new routes are registered at the correct permission tier.

- [ ] **Step 12: Commit**

```bash
git add internal/api/agent_groups_handlers.go internal/api/agent_groups_handlers_test.go \
        internal/auth/permissions.go internal/auth/permissions_test.go \
        internal/api/routes.go internal/api/rbac_matrix_test.go \
        internal/api/handlers.go internal/models/schema.go
git commit -m "$(cat <<'EOF'
feat(api): agent group hierarchy CRUD + groupId agent filter

5 new admin-only endpoints (CanManageAgentGroups): list the group tree
with recursive per-node agent counts, create/rename/move/delete a
group, and assign an agent to a group. Delete is blocked (409) rather
than cascading until a group has zero direct agents and zero
subgroups. Moving a group under its own descendant is rejected (400)
via an upward parent-chain walk. GET /api/agents gains an additive
groupId filter that recursively includes descendant-group agents, so
selecting a parent group in the UI surfaces its subgroups' agents too.
EOF
)"
git push
```

---

### Task 3: Frontend — tree panel, Agents page integration

**Files:**
- Modify: `orchestrator/wwwroot/index.html`:
  - CSS: a new block for the tree panel (place near the existing `.bld-` / `.st-tech-` blocks for consistency, or wherever this file's other panel-style blocks live)
  - Markup: the Agents page's `#tab-agents` section (currently starting line 1693) — add the tree panel alongside the existing table
  - JS: new functions for fetching/rendering the tree, node actions (rename/new-subgroup/move/delete), and the group-picker dialog
  - `renderAgentRows()` (currently line 6383) — change the "Group" column (currently line 6400, `a.envLabel`) to render `a.groupName || 'Ungrouped'`, and add a "Move to group..." item to each row's action menu (built around `toggleRowMenu`, currently line 6429)
  - Agent list fetch — whatever function currently calls `GET /api/agents` needs to accept/pass an optional `groupId` so selecting a tree node re-fetches filtered

**Interfaces:**
- Consumes: the 5 endpoints and the `groupId` query param from Task 2, and `groupName`/`groupId` fields now present on every `GET /api/agents` row from Task 2.
- Produces: nothing new consumed elsewhere — this is the terminal UI layer.

- [ ] **Step 1: Re-verify current line numbers**

Before writing any code, run:

```bash
grep -n 'id="tab-agents"\|function renderAgentRows\|a\.envLabel\|function toggleRowMenu\|GET.*api/agents\|apicall(.\/api\/agents' orchestrator/wwwroot/index.html
```

Confirm the line numbers still roughly match what's cited above (they were last verified earlier in this same session, but re-check since Task 1/2 didn't touch this file and nothing else should have either — this step exists as a safety check, not because drift is expected).

- [ ] **Step 2: Find and read the current agent-list fetch function**

Run: `grep -n "function loadAgents" orchestrator/wwwroot/index.html`

Read that function in full (likely near where `renderAgentRows`/`renderAgentTiles`/`renderAgentToolbar` are called from, given `loadAgents()` is referenced by the existing "Refresh" button at `index.html:1700`). Identify exactly how it calls `apicall('/api/agents')` today, so Step 5 below can add the `groupId` param without guessing at the function's current shape.

- [ ] **Step 3: Add the tree panel CSS and markup**

Add CSS (place it near the other panel-style blocks already added this session, e.g. after the `.st-tech-*` rules):

```css
.agent-tree-layout { display: flex; gap: 1rem; align-items: flex-start; }
.agent-tree-panel { width: 240px; flex-shrink: 0; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.6rem; }
.agent-tree-hdr { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem; }
.agent-tree-hdr h4 { margin: 0; font-size: 0.8rem; color: var(--text); }
.at-node { display: flex; align-items: center; gap: 4px; padding: 4px 5px; border-radius: 5px; font-size: 0.8rem; color: var(--text); cursor: pointer; }
.at-node:hover { background: var(--elevated); }
.at-node.active { background: rgba(47,129,247,0.15); color: var(--accent); }
.at-caret { width: 12px; font-size: 0.65rem; color: var(--muted); flex-shrink: 0; }
.at-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.at-count { font-size: 0.66rem; color: var(--muted); background: var(--elevated); border: 1px solid var(--border); border-radius: 8px; padding: 0 5px; flex-shrink: 0; }
.at-menu { color: var(--muted); font-size: 0.85rem; padding: 0 3px; flex-shrink: 0; }
.at-children { margin-left: 16px; border-left: 1px solid var(--border); padding-left: 4px; }
.agent-tree-content { flex: 1; min-width: 0; }
```

Add the markup inside `#tab-agents` (wrap the existing agent-table content — everything currently between `#agents-view-operational`'s opening tag and the two-tab switcher — so the tree sits to the left of it). Since this touches an area already restructured twice this session (the privilege-field/technique-selector work and the Deploy-agent-button fix are all downstream of `#agents-view-operational`), **read the current full markup of `#tab-agents` through the end of `#agents-view-operational`'s closing tag before editing**, then wrap it as:

```html
<div class="agent-tree-layout">
  <div class="agent-tree-panel">
    <div class="agent-tree-hdr">
      <h4>Groups</h4>
      <button class="btn btn-outline btn-sm" onclick="createAgentGroupPrompt(null)" title="New root group">+</button>
    </div>
    <div id="agent-tree-root"></div>
  </div>
  <div class="agent-tree-content">
    <!-- existing agent-tiles / agent-toolbar / agent table markup moves here, unchanged -->
  </div>
</div>
```

- [ ] **Step 4: Write the tree fetch/render/actions JS**

Add these functions near `loadAgents()`/`renderAgentRows()`:

```js
var agentGroupTree = [];
var activeAgentGroupId = null; // null = "All" (no filter), otherwise a group id

function loadAgentGroupTree() {
  apicall('/api/agent-groups').then(function(tree) {
    agentGroupTree = Array.isArray(tree) ? tree : [];
    renderAgentGroupTree();
  }).catch(function() { agentGroupTree = []; renderAgentGroupTree(); });
}

function renderAgentGroupTree() {
  var root = document.getElementById('agent-tree-root');
  if (!root) return;
  var allRow = '<div class="at-node' + (activeAgentGroupId === null ? ' active' : '') + '" onclick="selectAgentGroup(null)">' +
    '<span class="at-caret"></span><span class="at-name">All</span></div>';
  root.innerHTML = allRow + agentGroupTree.map(renderAgentGroupNode).join('');
}

function renderAgentGroupNode(node) {
  var hasChildren = node.children && node.children.length;
  var caret = hasChildren ? '&#9662;' : '';
  var active = activeAgentGroupId === node.id ? ' active' : '';
  var html = '<div class="at-node' + active + '" onclick="selectAgentGroup(' + node.id + ')">' +
    '<span class="at-caret">' + caret + '</span>' +
    '<span class="at-name">' + x(node.name) + '</span>' +
    '<span class="at-count">' + node.totalAgentCount + '</span>' +
    '<span class="at-menu" onclick="event.stopPropagation();openAgentGroupMenu(event,' + node.id + ')">&#8942;</span>' +
    '</div>';
  if (hasChildren) {
    html += '<div class="at-children">' + node.children.map(renderAgentGroupNode).join('') + '</div>';
  }
  return html;
}

function selectAgentGroup(groupId) {
  activeAgentGroupId = groupId;
  renderAgentGroupTree();
  loadAgents(); // Step 5 makes this read activeAgentGroupId
}

function openAgentGroupMenu(ev, groupId) {
  var action = prompt('Type: rename / new / move / delete');
  if (action === 'rename') renameAgentGroupPrompt(groupId);
  else if (action === 'new') createAgentGroupPrompt(groupId);
  else if (action === 'move') moveAgentGroupPrompt(groupId);
  else if (action === 'delete') deleteAgentGroupConfirm(groupId);
}

function createAgentGroupPrompt(parentId) {
  var name = prompt('New group name:');
  if (!name) return;
  apicall('/api/agent-groups', { method: 'POST', body: JSON.stringify({ name: name, parentId: parentId }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function renameAgentGroupPrompt(groupId) {
  var name = prompt('New name:');
  if (!name) return;
  apicall('/api/agent-groups/' + groupId, { method: 'PATCH', body: JSON.stringify({ name: name }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function moveAgentGroupPrompt(groupId) {
  var newParent = prompt('Move to parent group ID (blank for root):');
  if (newParent === null) return;
  var parentId = newParent.trim() === '' ? null : parseInt(newParent, 10);
  apicall('/api/agent-groups/' + groupId, { method: 'PATCH', body: JSON.stringify({ parentId: parentId }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgentGroupTree(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}

function deleteAgentGroupConfirm(groupId) {
  if (!confirm('Delete this group?')) return;
  fetch('/api/agent-groups/' + groupId, { method: 'DELETE', credentials: 'same-origin' })
    .then(function(r) {
      if (r.status === 204) { showToast('Group deleted', 'ok'); loadAgentGroupTree(); return; }
      r.json().then(function(j) { showToast(j.error || 'Delete failed', 'err'); });
    }).catch(function(e) { showToast(e.message, 'err'); });
}

function moveAgentToGroupPrompt(agentId) {
  var newGroup = prompt('Move to group ID (blank for Ungrouped):');
  if (newGroup === null) return;
  var groupId = newGroup.trim() === '' ? null : parseInt(newGroup, 10);
  apicall('/api/agents/' + encodeURIComponent(agentId) + '/group', { method: 'PATCH', body: JSON.stringify({ groupId: groupId }) })
    .then(function(res) { if (res && res.error) { showToast(res.error, 'err'); return; } loadAgents(); })
    .catch(function(e) { showToast(e.message, 'err'); });
}
```

This uses `prompt()`/`confirm()` for the node-action menu and the group picker — deliberately minimal (matching the spec's "simple search/select picker" framing at MVP scope, not a polished custom dropdown), consistent with this being the first sub-project of a larger vision where richer pickers/drag-and-drop are explicitly deferred. If a nicer inline dropdown already exists elsewhere in this file as an easy-to-reuse pattern (check for an existing generic "small popover menu" component before assuming `prompt()` is the only option), prefer that instead — but do not build a new custom picker UI component from scratch for this pass.

- [ ] **Step 5: Wire `groupId` into the agent-list fetch and call `loadAgentGroupTree()` on page load**

In `loadAgents()` (found in Step 2), add `activeAgentGroupId` to whatever URL/params it builds for `GET /api/agents`, e.g. if it currently does `apicall('/api/agents')`, change to:

```js
apicall('/api/agents' + (activeAgentGroupId !== null ? '?groupId=' + activeAgentGroupId : ''))
```

(Match this exactly to `loadAgents()`'s real current structure from Step 2 — this is a sketch of the one-line change, not a full function replacement.)

Find wherever the Agents tab is first shown/initialized (likely inside `showTab('agents')` handling, or wherever `loadAgents()` is first called on app load) and add a call to `loadAgentGroupTree()` alongside it, so the tree panel populates whenever the Agents page is opened.

- [ ] **Step 6: Update the "Group" column and row action menu**

In `renderAgentRows()`, replace the Group column cell (currently `'<td><span class="tag">' + x(a.envLabel || '—') + '</span></td>' +`) with:

```js
      '<td><span class="tag">' + x(a.groupName || 'Ungrouped') + '</span></td>' +
```

In the same function's row-menu-panel block (built around `toggleRowMenu`), add one new item alongside the existing ones (e.g. "Detail"/"Run simulation"/"Safe Scan"/"Report"/"Download audit pack"):

```js
          '<button class="row-menu-item" onclick="closeAllRowMenus();moveAgentToGroupPrompt(\'' + x(a.agentId) + '\')">&#128193; Move to group…</button>' +
```

- [ ] **Step 7: Verify the syntax is still valid**

Run:

```bash
node -e "
  const fs = require('fs');
  const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
  const m = html.match(/<script>([\s\S]*)<\/script>/);
  new Function(m[1]);
  console.log('script block parses OK');
"
```

Expected: `script block parses OK`.

- [ ] **Step 8: Manual browser verification**

No automated frontend test framework exists for this file. **Known risk, carried over from earlier plans this session:** live browser verification against this codebase's Postgres has repeatedly been blocked this session by local credential access issues — treat this step as something that may need to be deferred/reported-as-unverified rather than assumed to work smoothly, exactly as happened for the Technique Selector, search-operators-hint, and sidebar-icon-redesign plans earlier today. If blocked, stop and ask rather than guessing at credentials again.

If the app is reachable:

1. Open the Agents page. Confirm the tree panel appears on the left with an "All" node and (initially) nothing else.
2. Create a root group "Finance," then a subgroup "Servers" under it, via the `+`/menu prompts.
3. Move an existing agent into "Servers" via its row's new "Move to group..." action. Confirm the Agents table's Group column updates.
4. Click "Finance" in the tree — confirm the table filters to show that agent (proving the recursive descendant-group filter works, since the agent is directly in "Servers," a child of "Finance," not in "Finance" itself).
5. Click "All" — confirm the table shows every agent again.
6. Try deleting "Finance" while it still contains "Servers" and the agent — confirm it's blocked with a message naming what's still inside.
7. Move the agent back to Ungrouped, delete "Servers," then delete "Finance" — confirm both succeed once empty.
8. Try moving "Finance" under "Servers" while "Servers" is still a child of "Finance" (before deleting it) — confirm the circular move is rejected with a clear error, not silently applied.

If any of these fail, stop and report — do not proceed to commit with a known-broken hierarchy.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
feat(agents): add hierarchical group tree panel to Agents page

Left-hand tree panel (create/rename/move/delete groups, minimal
prompt()-based pickers at this MVP stage) embedded in the existing
Agents page, matching the brainstormed design's "embedded sidebar"
choice. Selecting a node filters the agent table via the new groupId
param, including descendant subgroups. The Agents table's "Group"
column now shows the real assigned group (or "Ungrouped") instead of
the old EnvLabel-based placeholder; EnvLabel itself is untouched
everywhere else (its own separate Environment filter, the Agent
Detail drawer). Each row's action menu gains "Move to group...".
EOF
)"
git push
```

---

## Self-Review Notes

- **Spec coverage:** Data model (§1) → Task 1. Backend API, circular-check, delete-blocking, recursive `groupId` filter (§2) → Task 2. Frontend tree panel, embedded-sidebar placement, Group column swap, row-menu integration (§3) → Task 3. All brainstormed decisions (EnvLabel replaced not duplicated, Ungrouped implicit bucket, no tenant scoping, real tree widget, embedded sidebar, delete-blocked-not-cascading) are each implemented in a specific, named step above. Non-goals (dynamic groups, policies, drag-and-drop, bulk multi-select, copy/merge/archive) are not implemented anywhere in this plan.
- **Placeholder scan:** caught and removed a stray placeholder function (`isDescendant`, dead code with a hardcoded `false` body) that had been left in an earlier draft of Task 2 Step 7 — `UpdateAgentGroup`'s own inline upward-walk loop is the real, complete circular-check, so no separate helper was ever needed. One remaining item flagged explicitly rather than silently assumed: Task 2 Step 5's test file references test-harness helpers (`newTestEnv`, `env.adminContext`, `env.seedAgent`) by a plausible but unconfirmed name, since this plan didn't trace the exact existing `internal/api/*_test.go` fixture shape — the step explicitly instructs grepping the real helper names before finalizing rather than assuming the sketch is correct as-is; this is a "verify against reality first" instruction for the implementer, not a placeholder in the No-Placeholders sense (all the actual test logic/assertions are fully written out).
- **Type consistency:** `AgentGroupNode` (Go, Task 2) fields (`id`, `name`, `parentId`, `directAgentCount`, `totalAgentCount`, `children`) match exactly what Task 3's `renderAgentGroupNode()` reads (`node.id`, `.name`, `.children`, `.totalAgentCount`). `models.Agent`'s new `GroupID`/`GroupName` (Task 2 Step 1) match the JSON keys (`groupId`/`groupName`) Task 3 reads in `renderAgentRows()` and the row-menu action. The `PATCH /api/agents/{agentId}/group` body shape (`{groupId: number|null}`) is identical between Task 2's `SetAgentGroup` handler and Task 3's `moveAgentToGroupPrompt()`.
