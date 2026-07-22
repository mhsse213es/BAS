# Remote Agent Stop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** give an Admin operator a "Stop" action in the Agents table that durably stops a connected BAS agent on its endpoint (the process stops, and does not come back on its own — not on a service-recovery restart, not on the endpoint's next reboot).

**Architecture:** Server dispatches a new WebSocket command (`command_stop_agent`) to the target agent over the existing per-agent command channel (`hub.SendToAgent`), the same mechanism scenario dispatch already uses. The agent finalizes any in-flight run, sends a final heartbeat, then durably disables its own platform service (Windows SCM / systemd / launchd) *before* exiting, because each platform has a different auto-restart guard that a naive process exit would trip. The Agents table gets a new Admin-only "Stop" button and confirmation modal; the agent Detail view shows who stopped it and why.

**Tech Stack:** Go (orchestrator backend + agent, existing conventions), vanilla JS (existing `wwwroot/index.html`), PostgreSQL (idempotent `ALTER TABLE`).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-22-agent-remote-stop-design.md` — read it first; this plan implements it exactly.
- Admin-only everywhere: new permission `CanStopAgent`, matching `CanExecuteResponseAction`'s precedent as the strictest tier in this codebase.
- Reason is mandatory both server-side (400 if empty) and client-side (submit disabled until non-empty) — same double-enforcement pattern as EPP Response Actions.
- No remote restart capability exists or is being built — once stopped, physical/console access to the endpoint is required. This is intentional, not a gap to fill.
- Every edit to `orchestrator/wwwroot/index.html` must be applied identically to `orchestrator/cmd/server/wwwroot/index.html` (OS-level hardlinks, two separate git paths) — verify with `diff` before every commit, `git add` both paths together.
- `stopped_by` stores the acting user's ID (matches `audit_logs.actor_id`'s convention), never a display name — display names are resolved read-time via a `LEFT JOIN users`.

---

### Task 1: Server — stop dispatch, persistence, permission

**Files:**
- Modify: `orchestrator/internal/models/schema.go` (new WS message constant, new `models.Agent` fields)
- Modify: `orchestrator/internal/db/postgres.go:79-88` (new idempotent `ALTER TABLE` migrations)
- Modify: `orchestrator/internal/auth/permissions.go` (new `CanStopAgent` permission, added to `RoleAdmin` map and `Permissions()` ordered list)
- Modify: `orchestrator/internal/auth/permissions_test.go` (add `CanStopAgent` to `TestHasPermission_MatrixIsComplete` and `TestPermissions_Ordering` fixtures)
- Modify: `orchestrator/internal/api/handlers.go` (new `StopAgent` handler; extend `GetAgents` SELECT + `EnrollAgent` upsert)
- Modify: `orchestrator/internal/api/routes.go:343` (wire the new route)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (add the new route's `routeMatrix` entry)
- Test: `orchestrator/internal/api/agent_lifecycle_test.go` (new `TestStopAgent_*` tests)

**Interfaces:**
- Consumes: `hub.SendToAgent(agentID string, msg models.WSMessage) bool` (`internal/ws/hub.go:109`), `h.auditLog(r, action, resource string, detail map[string]any, outcome string)` (`internal/api/audit.go:44`), `auth.ClaimsFrom(r.Context())`.
- Produces: `POST /api/agents/{agentId}/stop`, `models.MsgCommandStopAgent = "command_stop_agent"`, `auth.CanStopAgent` — all consumed by Task 3 (UI).

- [ ] **Step 1: Add the WS message constant and `models.Agent` fields**

In `orchestrator/internal/models/schema.go`, find:
```go
	// MsgRevalidationStarted is broadcast when the auto-revalidation loop
	// dispatches a targeted re-run after an ITSM ticket is resolved.
	MsgRevalidationStarted = "revalidation_started"
)
```
Replace with:
```go
	// MsgRevalidationStarted is broadcast when the auto-revalidation loop
	// dispatches a targeted re-run after an ITSM ticket is resolved.
	MsgRevalidationStarted = "revalidation_started"
	// MsgCommandStopAgent tells a connected agent to durably stop itself —
	// finalize any in-flight run, disable its platform service so it does not
	// restart on its own, then exit. Payload: {"reason": string}.
	MsgCommandStopAgent = "command_stop_agent"
)
```

Find the `Agent` struct:
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
}
```
Replace with:
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

- [ ] **Step 2: Add the DB migration**

In `orchestrator/internal/db/postgres.go`, find:
```go
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS security_products jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS posture_catalog jsonb NOT NULL DEFAULT '{}'`,
```
Replace with:
```go
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS security_products jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS posture_catalog jsonb NOT NULL DEFAULT '{}'`,
		// Remote stop (see docs/superpowers/specs/2026-07-22-agent-remote-stop-design.md).
		// stopped_by stores the acting user's ID, not a display name.
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS stopped_by  text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS stopped_at  timestamptz`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS stop_reason text`,
```

- [ ] **Step 3: Add the `CanStopAgent` permission**

In `orchestrator/internal/auth/permissions.go`, find:
```go
	// Admin-only: agent state, license, connection config.
	CanSetAgentState        Permission = "agents:set-state"
	CanViewLicense          Permission = "license:view"
	CanViewConnectionConfig Permission = "config:view-connection"
```
Replace with:
```go
	// Admin-only: agent state, license, connection config.
	CanSetAgentState        Permission = "agents:set-state"
	CanStopAgent            Permission = "agents:stop"
	CanViewLicense          Permission = "license:view"
	CanViewConnectionConfig Permission = "config:view-connection"
```

Find (in the `RoleAdmin` map):
```go
		CanSetAgentState: true, CanViewLicense: true, CanViewConnectionConfig: true,
```
Replace with:
```go
		CanSetAgentState: true, CanStopAgent: true, CanViewLicense: true, CanViewConnectionConfig: true,
```

Find (in the `Permissions()` ordered list):
```go
		CanSetAgentState, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
```
Replace with:
```go
		CanSetAgentState, CanStopAgent, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
```

- [ ] **Step 4: Update the permission-matrix fixture tests**

In `orchestrator/internal/auth/permissions_test.go`, find (in `TestHasPermission_MatrixIsComplete`'s Admin fixture):
```go
		CanSetAgentState: true, CanViewLicense: true, CanViewConnectionConfig: true,
```
Replace with:
```go
		CanSetAgentState: true, CanStopAgent: true, CanViewLicense: true, CanViewConnectionConfig: true,
```

In the same file, find (in `TestPermissions_Ordering`'s expected-order slice):
```go
		CanSetAgentState, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
```
Replace with:
```go
		CanSetAgentState, CanStopAgent, CanViewLicense, CanViewConnectionConfig, CanListUsers, CanCreateUser,
		CanUpdateUser, CanDeleteUser, CanResetUserPassword, CanViewCalderaStatus, CanViewConnectorStatus,
```

- [ ] **Step 5: Run the permission tests to confirm the matrix is consistent**

Run: `cd orchestrator && go test ./internal/auth/... -run TestHasPermission_MatrixIsComplete -run TestPermissions_Ordering -v`
Expected: both tests PASS.

- [ ] **Step 6: Write the failing test for `StopAgent`**

In `orchestrator/internal/api/agent_lifecycle_test.go`, add at the end of the file:
```go
func TestStopAgent_RequiresReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		body, _ := json.Marshal(map[string]string{"reason": ""})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/agent-x/stop", bytes.NewReader(body)), "agentId", "agent-x")
		rec := httptest.NewRecorder()
		h.StopAgent(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("empty reason: status = %d, want 400", rec.Code)
		}
	})
}

func TestStopAgent_NotConnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-stop-notconn"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))

		body, _ := json.Marshal(map[string]string{"reason": "decommissioning"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/stop", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.StopAgent(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("agent not connected: status = %d, want 503", rec.Code)
		}
	})
}

func TestStopAgent_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		hub := ws.NewHub()
		h := New(pool, hub, nil, "")
		agentID := "agent-stop-ok"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))

		fake := startFakeAgent(t, hub, agentID)

		body, _ := json.Marshal(map[string]string{"reason": "decommissioning host"})
		req := authedRequest(t, http.MethodPost, "/api/agents/"+agentID+"/stop", bytes.NewReader(body), auth.RoleAdmin, "admin-1")
		req = withURLParam(req, "agentId", agentID)
		rec := callAuthed(h.StopAgent, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("stop dispatch: status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandStopAgent {
			t.Fatalf("WS message type = %q, want %q", env.Type, models.MsgCommandStopAgent)
		}
		var payload struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(env.Data, &payload); err != nil || payload.Reason != "decommissioning host" {
			t.Fatalf("WS payload = %+v, err = %v, want reason=decommissioning host", payload, err)
		}

		var stoppedBy, stopReason string
		if err := pool.QueryRow(context.Background(),
			`SELECT stopped_by, stop_reason FROM agents WHERE agent_id=$1`, agentID,
		).Scan(&stoppedBy, &stopReason); err != nil {
			t.Fatalf("read stop columns: %v", err)
		}
		if stoppedBy != "admin-1" || stopReason != "decommissioning host" {
			t.Fatalf("stopped_by=%q stop_reason=%q, want admin-1/decommissioning host", stoppedBy, stopReason)
		}
	})
}
```
`agent_lifecycle_test.go` already imports `"time"` (line 12); it does not yet import `auth`. In its import block, find:
```go
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
```
Replace with:
```go
	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
```

- [ ] **Step 7: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestStopAgent -v`
Expected: FAIL — `h.StopAgent undefined (type *Handler has no field or method StopAgent)`.

- [ ] **Step 8: Implement `StopAgent`, extend `GetAgents` and `EnrollAgent`**

In `orchestrator/internal/api/handlers.go`, find the end of `SetAgentState` (right after its closing `}` and before the `agentFiles` comment):
```go
	h.auditLog(r, "agent.state", agentID, map[string]any{"state": body.State}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "state": body.State})
}

// agentFiles is the explicit allowlist of downloadable agent artifacts.
```
Replace with:
```go
	h.auditLog(r, "agent.state", agentID, map[string]any{"state": body.State}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "state": body.State})
}

// POST /api/agents/{agentId}/stop — durably stops a connected agent: the
// agent finalizes any in-flight run, disables its platform service so it
// does not restart on its own (not on crash-recovery, not on next boot),
// then exits. There is no remote way to start it again — see
// docs/superpowers/specs/2026-07-22-agent-remote-stop-design.md.
// Admin-only; the route group enforces the permission check.
func (h *Handler) StopAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Reason) == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandStopAgent,
		AgentID: agentID,
		Data:    map[string]string{"reason": body.Reason},
	})
	if !sent {
		jsonError(w, "agent not connected", http.StatusServiceUnavailable)
		return
	}

	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	_, err := h.db.Exec(r.Context(),
		`UPDATE agents SET stopped_by = $1, stopped_at = NOW(), stop_reason = $2 WHERE agent_id = $3`,
		actorID, body.Reason, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "agent.stop", agentID, map[string]any{"reason": body.Reason}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "status": "stop_dispatched"})
}

// agentFiles is the explicit allowlist of downloadable agent artifacts.
```

`handlers.go` already imports both `"strings"` (line 15) and `"github.com/audspect/bas/internal/auth"` (line 24) — no import changes needed for this step.

Now extend `GetAgents`. Find:
```go
func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT a.agent_id, a.hostname, a.ip_address, a.os_version, a.username, a.status, a.env_label,
		        a.has_report, a.binary_hash, a.binary_trusted, a.last_update,
		        COALESCE(a.state, 'active'), COALESCE(a.policy_json::text, '{}'), a.enrolled_at,
		        (SELECT COUNT(*) FROM scenario_runs sr WHERE sr.agent_id = a.agent_id) AS sims
		 FROM agents a ORDER BY a.last_update DESC`)
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
			&stateStr, &policyRaw, &a.EnrolledAt, &a.Sims); err != nil {
			continue
		}
```
Replace with:
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
```

Now clear the stop fields on re-enroll. Find (in `EnrollAgent`):
```go
			state          = CASE
			                   WHEN agents.state IN ('quarantined','retired') THEN agents.state
			                   ELSE 'active'
			                 END,
			policy_json    = EXCLUDED.policy_json,
			posture_catalog = EXCLUDED.posture_catalog,
			enrolled_at    = COALESCE(agents.enrolled_at, NOW()),
			last_update    = NOW()`,
```
Replace with:
```go
			state          = CASE
			                   WHEN agents.state IN ('quarantined','retired') THEN agents.state
			                   ELSE 'active'
			                 END,
			policy_json    = EXCLUDED.policy_json,
			posture_catalog = EXCLUDED.posture_catalog,
			enrolled_at    = COALESCE(agents.enrolled_at, NOW()),
			-- A fresh enrollment is itself evidence someone restarted the agent —
			-- clear any prior remote-stop record unconditionally.
			stopped_by     = NULL,
			stopped_at     = NULL,
			stop_reason    = NULL,
			last_update    = NOW()`,
```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestStopAgent -v`
Expected: all three PASS.

- [ ] **Step 10: Wire the route**

In `orchestrator/internal/api/routes.go`, find:
```go
		r.With(auth.RequirePermission(auth.CanSetAgentState)).Put("/api/agents/{agentId}/state", h.SetAgentState)
```
Replace with:
```go
		r.With(auth.RequirePermission(auth.CanSetAgentState)).Put("/api/agents/{agentId}/state", h.SetAgentState)
		r.With(auth.RequirePermission(auth.CanStopAgent)).Post("/api/agents/{agentId}/stop", h.StopAgent)
```

- [ ] **Step 11: Add the RBAC drift-detection fixture entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, find:
```go
	{http.MethodPut, "/api/agents/{agentId}/state", tierPermission, auth.CanSetAgentState},
```
Replace with:
```go
	{http.MethodPut, "/api/agents/{agentId}/state", tierPermission, auth.CanSetAgentState},
	{http.MethodPost, "/api/agents/{agentId}/stop", tierPermission, auth.CanStopAgent},
```

- [ ] **Step 12: Run the full API test suite**

Run: `cd orchestrator && go test ./internal/api/... ./internal/auth/... 2>&1 | tail -40`
Expected: `ok` for both packages, no failures (this is a real-Postgres testcontainer suite — ensure Docker Desktop is running first via `docker info`; if it's down, note the blocker rather than skip verification).

- [ ] **Step 13: Commit**

```bash
git add orchestrator/internal/models/schema.go orchestrator/internal/db/postgres.go \
        orchestrator/internal/auth/permissions.go orchestrator/internal/auth/permissions_test.go \
        orchestrator/internal/api/handlers.go orchestrator/internal/api/routes.go \
        orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/agent_lifecycle_test.go
git commit -m "feat(api): add durable remote agent stop dispatch"
git push
```

---

### Task 2: Agent — durable stop-and-disable (Windows / Linux / macOS)

**Files:**
- Modify: `agent/agent.go` (new WS message case; new `stopSelf` method; new package-level test-seam vars)
- Modify: `agent/service.go` (Windows: `stopRequested` channel, `Execute()` new case, `platformDisableAutoStart`, `platformExitAfterStop`)
- Modify: `agent/service_linux.go` (`platformDisableAutoStart`)
- Modify: `agent/service_darwin.go` (`platformDisableAutoStart`)
- Modify: `agent/platform_posix.go` (`platformExitAfterStop`)
- Test: `agent/stop_test.go` (new)

**Interfaces:**
- Consumes: `a.shutdownFinalize(grace time.Duration)`, `a.sendHeartbeat(status string)`, `a.logger.Op(level, category, message string)`, `platformRestoreOnShutdown()` — all pre-existing.
- Produces: `func (a *Agent) stopSelf(reason string)`, `platformDisableAutoStart() error`, `platformExitAfterStop()` — package-level, one implementation of the latter two per platform. Not consumed elsewhere in this plan (Task 1/3 don't touch agent code), but this is the agent-side counterpart Task 1's `command_stop_agent` message triggers.

- [ ] **Step 1: Write the failing test for `stopSelf`'s call sequence**

Create `agent/stop_test.go`:
```go
package main

import (
	"reflect"
	"testing"
)

func TestStopSelf_FinalizesHeartbeatsDisablesThenExits(t *testing.T) {
	var calls []string

	origDisable := platformDisableAutoStartFn
	origExit := platformExitAfterStopFn
	defer func() {
		platformDisableAutoStartFn = origDisable
		platformExitAfterStopFn = origExit
	}()
	platformDisableAutoStartFn = func() error { calls = append(calls, "disable"); return nil }
	platformExitAfterStopFn = func() { calls = append(calls, "exit") }

	a := newAgent(Config{ServerURL: "http://127.0.0.1:1"}, Identity{AgentID: "test-agent"})
	a.status = "idle" // shutdownFinalize is a no-op when idle — isolates this test to stopSelf's own sequencing

	a.stopSelf("decommissioning host")

	want := []string{"disable", "exit"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestStopSelf_DisableFailureStillExits(t *testing.T) {
	var calls []string

	origDisable := platformDisableAutoStartFn
	origExit := platformExitAfterStopFn
	defer func() {
		platformDisableAutoStartFn = origDisable
		platformExitAfterStopFn = origExit
	}()
	platformDisableAutoStartFn = func() error { calls = append(calls, "disable"); return errDisableFailedForTest }
	platformExitAfterStopFn = func() { calls = append(calls, "exit") }

	a := newAgent(Config{ServerURL: "http://127.0.0.1:1"}, Identity{AgentID: "test-agent"})
	a.status = "idle"

	a.stopSelf("decommissioning host")

	want := []string{"disable", "exit"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v (a disable failure must not prevent exit)", calls, want)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd agent && go test ./... -run TestStopSelf -v`
Expected: FAIL — `undefined: platformDisableAutoStartFn` (and related undefined symbols).

- [ ] **Step 3: Add `stopSelf` and the test-seam vars to `agent.go`**

In `agent/agent.go`, find the `shutdownFinalize` method (ends at line 317 per the codebase as it stands — anchor on its literal closing, not the line number, since other edits in this file may have shifted it):
```go
	select {
	case <-done:
		log.Println("[*] in-flight simulation finalized; partial result spooled for delivery")
	case <-time.After(grace):
		log.Printf("[!] simulation did not finalize within %s — partial may be incomplete", grace)
	}
}
```
Replace with:
```go
	select {
	case <-done:
		log.Println("[*] in-flight simulation finalized; partial result spooled for delivery")
	case <-time.After(grace):
		log.Printf("[!] simulation did not finalize within %s — partial may be incomplete", grace)
	}
}

// platformDisableAutoStartFn and platformExitAfterStopFn are indirections
// over the real platform-specific functions (defined per-OS in
// service.go/service_linux.go/service_darwin.go/platform_posix.go) so tests
// can substitute no-op stand-ins instead of actually disabling a service or
// exiting the test process.
var (
	platformDisableAutoStartFn = platformDisableAutoStart
	platformExitAfterStopFn    = platformExitAfterStop
)

// stopSelf performs a durable, operator-requested shutdown: finalize any
// in-flight run, send a final heartbeat, disable the platform service so it
// does not come back (not on crash-recovery, not on next boot), then exit.
// See docs/superpowers/specs/2026-07-22-agent-remote-stop-design.md for why
// the disable step must run before exit, and why it differs per platform.
func (a *Agent) stopSelf(reason string) {
	log.Printf("[*] Stop requested by operator: %s", reason)
	a.logger.Op("warn", "lifecycle", "agent stopped by operator request: "+reason)
	a.shutdownFinalize(shutdownGrace)
	a.sendHeartbeat("offline")
	platformRestoreOnShutdown()
	if err := platformDisableAutoStartFn(); err != nil {
		log.Printf("[!] disable auto-start: %v — agent may restart at next boot", err)
	}
	platformExitAfterStopFn()
}
```

Find the WS message switch's `command_cancel` case:
```go
			case "command_cancel":
				if a.cancelCurrentScenario() {
					log.Printf("[*] scenario cancelled by operator")
					a.logger.Op("warn", "lifecycle", "scenario stopped by operator request")
				} else {
					log.Printf("[~] command_cancel received but no scenario is running")
				}

			default:
```
Replace with:
```go
			case "command_cancel":
				if a.cancelCurrentScenario() {
					log.Printf("[*] scenario cancelled by operator")
					a.logger.Op("warn", "lifecycle", "scenario stopped by operator request")
				} else {
					log.Printf("[~] command_cancel received but no scenario is running")
				}

			case "command_stop_agent":
				var body struct {
					Reason string `json:"reason"`
				}
				if err := json.Unmarshal(msg.Data, &body); err != nil {
					log.Printf("[!] WS: bad stop command: %v", err)
					continue
				}
				go a.stopSelf(body.Reason)

			default:
```

- [ ] **Step 4: Add the cross-platform test-error sentinel**

`agent/agent.go` does not currently import `"errors"`. In its import block, find:
```go
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
```
Replace with:
```go
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
```

Then, still in `agent/agent.go`, find:
```go
func newAgent(cfg Config, id Identity) *Agent {
```
Replace with:
```go
var errDisableFailedForTest = errors.New("disable failed (test)")

func newAgent(cfg Config, id Identity) *Agent {
```

- [ ] **Step 5: Add the Windows platform functions**

In `agent/service.go`, find:
```go
const (
	svcName        = "BASAgent"
	svcDisplayName = "BAS Platform Agent (Audspect)"
	svcDescription = "Next-Gen Breach & Attack Simulation endpoint agent. Runs security posture checks and reports results to the BAS orchestrator."
)
```
Replace with:
```go
const (
	svcName        = "BASAgent"
	svcDisplayName = "BAS Platform Agent (Audspect)"
	svcDescription = "Next-Gen Breach & Attack Simulation endpoint agent. Runs security posture checks and reports results to the BAS orchestrator."
)

// stopRequested signals agentSvc.Execute()'s own select loop from the
// WS-command goroutine (agent.go's stopSelf), so a remote stop while
// running as a Windows service goes through the same clean SERVICE_STOPPED
// handshake as a normal svc.Stop — calling os.Exit() directly from a
// different goroutine would skip that handshake and could look like a
// crash to SCM, triggering ApplyServiceRecovery's auto-restart. stopSelf
// already ran finalize/heartbeat/disable before signaling, so no payload
// is needed here — an empty struct is enough.
var stopRequested = make(chan struct{}, 1)
```

Find:
```go
	for {
		select {
		case <-ticker.C:
			agent.sendHeartbeat(agent.getStatus())
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				// Tell the SCM how long we may take so it doesn't kill us before an
				// in-flight run finalizes its Partial to the spool.
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32((shutdownGrace + 5*time.Second) / time.Millisecond)}
				agent.shutdownFinalize(shutdownGrace)
				agent.sendHeartbeat("offline")
				RestoreSystemDialogs()
				return false, 0
```
Replace with (note the new `case <-stopRequested:` is a sibling of `case c := <-r:` in the *outer* select — it cannot go inside `switch c.Cmd { ... }`, since that switch compares `c.Cmd` values and a channel-receive case is a different kind of expression entirely; mixing them is a compile error):
```go
	for {
		select {
		case <-ticker.C:
			agent.sendHeartbeat(agent.getStatus())
		case <-stopRequested:
			// stopSelf (agent.go) already ran finalize/heartbeat/disable before
			// signaling here — this just performs the clean SCM handshake.
			status <- svc.Status{State: svc.StopPending, WaitHint: uint32((shutdownGrace + 5*time.Second) / time.Millisecond)}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				// Tell the SCM how long we may take so it doesn't kill us before an
				// in-flight run finalizes its Partial to the spool.
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32((shutdownGrace + 5*time.Second) / time.Millisecond)}
				agent.shutdownFinalize(shutdownGrace)
				agent.sendHeartbeat("offline")
				RestoreSystemDialogs()
				return false, 0
```

Add at the end of `agent/service.go` (after the last existing function):
```go
// platformDisableAutoStart sets the service's start type to Disabled so it
// does not start at the endpoint's next boot. Safe to call on a running
// service — only affects future start attempts, not this one.
func platformDisableAutoStart() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("query service config: %w", err)
	}
	cfg.StartType = mgr.StartDisabled
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("update service config: %w", err)
	}
	log.Printf("[svc] service start type set to Disabled — will not start at next boot")
	return nil
}

// platformExitAfterStop ends this process. When running as a Windows
// service, it hands off to agentSvc.Execute()'s own select loop (via
// stopRequested) instead of exiting directly, so SCM sees a clean stop
// rather than a crash. In console mode there is no SCM handshake to honor,
// so it exits directly.
func platformExitAfterStop() {
	if isWindowsService() {
		select {
		case stopRequested <- struct{}{}:
		default:
		}
		return
	}
	os.Exit(0)
}
```

- [ ] **Step 6: Add the Linux platform function**

In `agent/service_linux.go`, add at the end of the file (after `readServiceParams`):
```go
// platformDisableAutoStart removes bas-agent.service's boot-time enablement
// so it does not start at the endpoint's next boot. Best-effort: a failure
// here is logged by the caller (stopSelf) but does not block the stop
// itself — the process still exits now; it just isn't guaranteed to stay
// stopped across a reboot.
func platformDisableAutoStart() error {
	return exec.Command("systemctl", "disable", "bas-agent.service").Run()
}

// platformExitAfterStop ends this process. The systemd unit's
// Restart=on-failure policy does not fire on a clean exit (code 0), so no
// SCM-style handshake is needed here unlike Windows.
func platformExitAfterStop() {
	os.Exit(0)
}
```

- [ ] **Step 7: Add the macOS platform function**

In `agent/service_darwin.go`, add at the end of the file (after `readServiceParams`):
```go
// platformDisableAutoStart unloads the launchd job with the persistent
// "-w" (disabled) flag, so it does not start at the endpoint's next boot.
// Unlike Linux/Windows, this must run BEFORE the process exits, not after:
// the launchd plist's KeepAlive=true restarts the job unconditionally on
// ANY exit (clean or not), so exiting first would just be relaunched before
// this had a chance to disable it. Note this call itself typically
// terminates the process as a side effect of unloading — that's expected;
// platformExitAfterStop below becomes a no-op in that case.
func platformDisableAutoStart() error {
	return exec.Command("launchctl", "unload", "-w", darwinPlistPath).Run()
}

// platformExitAfterStop ends this process. On macOS the disable step above
// usually already ended it — this is a fallback for the case where it did
// not (e.g. an older launchd that doesn't synchronously kill on unload).
func platformExitAfterStop() {
	os.Exit(0)
}
```

- [ ] **Step 8: Add the POSIX console-mode fallback**

In `agent/platform_posix.go`, find:
```go
// platformRestoreOnShutdown is a no-op on non-Windows.
func platformRestoreOnShutdown() {}
```
Replace with:
```go
// platformRestoreOnShutdown is a no-op on non-Windows.
func platformRestoreOnShutdown() {}
```
This file is unchanged — `platformExitAfterStop`/`platformDisableAutoStart` for Linux and macOS are defined directly in `service_linux.go`/`service_darwin.go` (Step 6/7 above), not in the shared `platform_posix.go` stub, since their implementations genuinely differ per OS (systemd vs launchd) and `platform_posix.go` only holds functions that are identical no-ops across both. No edit needed here — this step exists to document why, not to change code.

- [ ] **Step 9: Run the agent tests to verify they pass**

Run: `cd agent && go test ./... -run TestStopSelf -v`
Expected: both PASS.

- [ ] **Step 10: Cross-compile for all three platforms to catch build breaks**

Run:
```bash
cd agent
GOOS=windows GOARCH=amd64 go build -o /tmp/bas_agent_win_verify.exe . && echo WINDOWS_OK
GOOS=linux GOARCH=amd64 go build -o /tmp/bas_agent_linux_verify . && echo LINUX_OK
GOOS=darwin GOARCH=amd64 go build -o /tmp/bas_agent_darwin_verify . && echo DARWIN_OK
rm -f /tmp/bas_agent_win_verify.exe /tmp/bas_agent_linux_verify /tmp/bas_agent_darwin_verify
```
Expected: `WINDOWS_OK`, `LINUX_OK`, `DARWIN_OK` all printed, no compile errors.

- [ ] **Step 11: Run the full agent test suite**

Run: `cd agent && go test ./... 2>&1 | tail -30`
Expected: `ok` for `audspect/agent` and `audspect/agent/sched`, no failures.

- [ ] **Step 12: Commit**

```bash
git add agent/agent.go agent/service.go agent/service_linux.go agent/service_darwin.go agent/stop_test.go
git commit -m "feat(agent): durably stop and disable auto-restart on remote stop command"
git push
```

---

### Task 3: UI — Stop button, confirmation modal, Detail banner

**Files:**
- Modify: `orchestrator/wwwroot/index.html:5555-5585` (`renderAgentRows` — new Stop button)
- Modify: `orchestrator/wwwroot/index.html` (new `#stop-agent-overlay` modal HTML, placed after `#respond-overlay`'s closing `</div>`)
- Modify: `orchestrator/wwwroot/index.html:12487-12560` (`openAgentDetail` — new stopped banner)
- Modify: `orchestrator/wwwroot/index.html` (new JS functions, appended after the Respond modal's functions)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (same edits, hardlinked twin)

**Interfaces:**
- Consumes: `apicall`, `showToast`, `x` (HTML-escape helper), `agents` (global array, already loaded by `loadAgents()`), `ROLE` (global admin-check string), `loadAgents()`.
- Produces: `openStopAgentModal(agentId, hostname)`, `closeStopAgentModal()`, `submitStopAgent()` — not consumed by any other task.

- [ ] **Step 1: Add the Stop button to the Agents table**

In `orchestrator/wwwroot/index.html`, find:
```js
      '<td>' +
        '<div style="display:flex;flex-wrap:wrap;gap:3px">' +
        '<button class="btn btn-outline btn-sm" onclick="openAgentDetail(\'' + x(a.agentId) + '\')" title="View detail">&#128269; Detail</button>' +
        '<button class="btn btn-outline-green btn-sm" onclick="openModal(null,\'' + x(a.agentId) + '\')" title="Run simulation">&#9654; Run</button>' +
        '<button class="btn btn-outline btn-sm" onclick="safeScan(\'' + x(a.agentId) + '\')" title="Read-only simulation">&#128737; Safe Scan</button>' +
        '<button class="btn btn-outline btn-sm" onclick="openFullReport(\'' + x(a.agentId) + '\')" title="Open HTML report">&#128196; Report</button>' +
        '<button class="btn btn-outline btn-sm" onclick="downloadAuditPack(\'' + x(a.agentId) + '\')" title="Download audit pack">&#8659; Pack</button>' +
        '</div>' +
      '</td></tr>';
```
Replace with:
```js
      '<td>' +
        '<div style="display:flex;flex-wrap:wrap;gap:3px">' +
        '<button class="btn btn-outline btn-sm" onclick="openAgentDetail(\'' + x(a.agentId) + '\')" title="View detail">&#128269; Detail</button>' +
        '<button class="btn btn-outline-green btn-sm" onclick="openModal(null,\'' + x(a.agentId) + '\')" title="Run simulation">&#9654; Run</button>' +
        '<button class="btn btn-outline btn-sm" onclick="safeScan(\'' + x(a.agentId) + '\')" title="Read-only simulation">&#128737; Safe Scan</button>' +
        '<button class="btn btn-outline btn-sm" onclick="openFullReport(\'' + x(a.agentId) + '\')" title="Open HTML report">&#128196; Report</button>' +
        '<button class="btn btn-outline btn-sm" onclick="downloadAuditPack(\'' + x(a.agentId) + '\')" title="Download audit pack">&#8659; Pack</button>' +
        (ROLE === 'admin' && a.status !== 'offline' ?
          '<button class="btn btn-sm" style="color:var(--danger);background:rgba(218,54,51,0.08);border:1px solid rgba(218,54,51,0.25)" onclick="openStopAgentModal(\'' + x(a.agentId) + '\',\'' + x(a.hostname || a.agentId) + '\')" title="Stop agent permanently">&#9209; Stop</button>' : '') +
        '</div>' +
      '</td></tr>';
```

- [ ] **Step 2: Add the confirmation modal markup**

Find:
```html
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeRespondModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="respond-submit-btn" class="btn btn-outline-green btn-sm" onclick="submitRespondAction()">&#9654; Execute</button>
    </div>
  </div>
</div>

<!-- Technique / Ability Picker -->
```
Replace with:
```html
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeRespondModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="respond-submit-btn" class="btn btn-outline-green btn-sm" onclick="submitRespondAction()">&#9654; Execute</button>
    </div>
  </div>
</div>

<!-- Stop Agent Modal -->
<div id="stop-agent-overlay" class="overlay">
  <div class="modal" style="width:440px">
    <h3>Stop Agent</h3>
    <p class="sub2" id="stop-agent-target-sub"></p>

    <div style="background:rgba(218,54,51,.1);border:1px solid var(--danger-border, var(--danger));border-radius:var(--radius);padding:0.65rem 0.8rem;font-size:0.78rem;color:var(--danger);margin:0.6rem 0">
      &#9888; This stops the agent and disables it from restarting automatically — including after a reboot of this endpoint. There is no remote way to start it again; someone will need physical or console access to the machine.
    </div>

    <label class="modal-lbl">Reason <span class="tiny muted">(required)</span></label>
    <input type="text" id="stop-agent-reason" placeholder="e.g. decommissioning this host"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeStopAgentModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="stop-agent-submit-btn" class="btn btn-sm" style="color:#fff;background:var(--danger)" onclick="submitStopAgent()">&#9209; Stop Agent</button>
    </div>
  </div>
</div>

<!-- Technique / Ability Picker -->
```

- [ ] **Step 3: Add the Detail-view stopped banner**

Find:
```js
      (a.state === 'quarantined' ? '<div style="background:rgba(218,54,51,.12);border:1px solid var(--danger);border-radius:4px;padding:0.6rem 0.85rem;color:var(--danger);font-size:0.78rem;margin-bottom:0.75rem">&#9888; Agent is QUARANTINED — binary hash mismatch detected. Scenario dispatch is blocked. Restore to Active once the issue is resolved.</div>' : '') +
      (a.state === 'restricted'  ? '<div style="background:rgba(210,153,34,.12);border:1px solid var(--warning);border-radius:4px;padding:0.6rem 0.85rem;color:var(--warning);font-size:0.78rem;margin-bottom:0.75rem">&#9888; Agent is RESTRICTED — scenario dispatch is blocked by policy. Restore to Active to re-enable.</div>' : '') +
      (a.state === 'retired'     ? '<div style="background:rgba(100,116,139,.12);border:1px solid rgba(100,116,139,.4);border-radius:4px;padding:0.6rem 0.85rem;color:#94a3b8;font-size:0.78rem;margin-bottom:0.75rem">&#128683; Agent is RETIRED — decommissioned and blocked from running scenarios. Restore to Active to re-enable.</div>' : '') +
```
Replace with:
```js
      (a.state === 'quarantined' ? '<div style="background:rgba(218,54,51,.12);border:1px solid var(--danger);border-radius:4px;padding:0.6rem 0.85rem;color:var(--danger);font-size:0.78rem;margin-bottom:0.75rem">&#9888; Agent is QUARANTINED — binary hash mismatch detected. Scenario dispatch is blocked. Restore to Active once the issue is resolved.</div>' : '') +
      (a.state === 'restricted'  ? '<div style="background:rgba(210,153,34,.12);border:1px solid var(--warning);border-radius:4px;padding:0.6rem 0.85rem;color:var(--warning);font-size:0.78rem;margin-bottom:0.75rem">&#9888; Agent is RESTRICTED — scenario dispatch is blocked by policy. Restore to Active to re-enable.</div>' : '') +
      (a.state === 'retired'     ? '<div style="background:rgba(100,116,139,.12);border:1px solid rgba(100,116,139,.4);border-radius:4px;padding:0.6rem 0.85rem;color:#94a3b8;font-size:0.78rem;margin-bottom:0.75rem">&#128683; Agent is RETIRED — decommissioned and blocked from running scenarios. Restore to Active to re-enable.</div>' : '') +
      (a.stoppedBy ? '<div style="background:rgba(218,54,51,.12);border:1px solid var(--danger);border-radius:4px;padding:0.6rem 0.85rem;color:var(--danger);font-size:0.78rem;margin-bottom:0.75rem">&#9209; Agent was stopped by ' + x(a.stoppedByName || a.stoppedBy) + ' on ' + x(new Date(a.stoppedAt).toLocaleString()) + ': ' + x(a.stopReason || '') + '. It will not restart automatically. Physical/console access to the endpoint is required to bring it back.</div>' : '') +
```

- [ ] **Step 4: Add the JS functions**

Find (the end of `submitRespondAction`, right before `function triggerTicketingSync() {` — this is now further down the file than in Plan 5 of EPP Response Actions since that plan's own edits shifted subsequent line numbers; locate by the literal code below, not a line number):
```js
  }).then(function(res) {
    btn.disabled = false;
    if (res && res.status === 'completed') {
      showToast('Dispatched — ' + label, 'ok');
      closeRespondModal();
    } else {
      showToast('Failed: ' + (res && res.error ? res.error : 'unknown error'), 'err');
    }
  }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
}

function triggerTicketingSync() {
```
Replace with:
```js
  }).then(function(res) {
    btn.disabled = false;
    if (res && res.status === 'completed') {
      showToast('Dispatched — ' + label, 'ok');
      closeRespondModal();
    } else {
      showToast('Failed: ' + (res && res.error ? res.error : 'unknown error'), 'err');
    }
  }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
}

// ── Stop Agent ───────────────────────────────────────────────────────────────
var _stopAgentTargetId = null;

function openStopAgentModal(agentId, hostname) {
  _stopAgentTargetId = agentId;
  document.getElementById('stop-agent-target-sub').textContent = 'Target: ' + hostname;
  document.getElementById('stop-agent-reason').value = '';
  document.getElementById('stop-agent-overlay').classList.add('open');
}

function closeStopAgentModal() {
  document.getElementById('stop-agent-overlay').classList.remove('open');
}

function submitStopAgent() {
  if (!_stopAgentTargetId) return;
  var reason = document.getElementById('stop-agent-reason').value.trim();
  if (!reason) { showToast('Reason is required', 'err'); return; }
  if (!confirm('Stop agent permanently?\n\nReason: ' + reason + '\n\nThis cannot be undone remotely. Proceed?')) return;

  var btn = document.getElementById('stop-agent-submit-btn');
  btn.disabled = true;
  apicall('/api/agents/' + encodeURIComponent(_stopAgentTargetId) + '/stop', {
    method: 'POST',
    body: JSON.stringify({ reason: reason })
  }).then(function() {
    btn.disabled = false;
    showToast('Stop dispatched', 'ok');
    closeStopAgentModal();
    loadAgents();
  }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
}

function triggerTicketingSync() {
```

- [ ] **Step 5: Verify the hardlink twin is in sync**

```bash
diff orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
```
Expected: no output.

- [ ] **Step 6: Structural verification**

```bash
grep -n "stop-agent-overlay\|openStopAgentModal\|submitStopAgent\|stoppedByName" orchestrator/wwwroot/index.html
```
Expected: matches for the new markup ID and all new function/field names.

- [ ] **Step 7: Live-server smoke test**

```bash
docker run -d --name masd-stop-verify -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=bas -p 55460:5432 postgres:16-alpine
```
Wait for it to accept connections (`docker exec masd-stop-verify pg_isready -U postgres`), then in `orchestrator/`:
```bash
DATABASE_URL="postgres://postgres:postgres@localhost:55460/bas?sslmode=disable" JWT_SECRET=dev-secret BAS_LICENSE_PATH="C:/Users/Administrator/Downloads/Audspect_Cloud/audspect-dev.lic" HTTP_PORT=8201 go run ./cmd/server
```
In a second shell:
```bash
curl -s http://localhost:8201/ | grep -o "stop-agent-overlay\|Stop Agent\|openStopAgentModal"
```
Expected: all three strings present.

Then clean up:
```bash
powershell -Command "Get-NetTCPConnection -LocalPort 8201 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }"
docker rm -f masd-stop-verify
```

- [ ] **Step 8: Record the manual browser checklist**

Before this branch is merged, a human must verify in an actual browser, logged in as Admin, with a real connected agent:
1. Agents table — confirm a red "Stop" button appears only for currently-connected (non-offline) agents, and only when logged in as Admin.
2. Click Stop — confirm the modal shows the target hostname and the warning text about no remote restart.
3. Click "Stop Agent" with an empty Reason — confirm it's rejected client-side, no `confirm()` shown.
4. Fill in Reason, click "Stop Agent" — confirm the native `confirm()` dialog shows the reason; cancelling leaves the modal open, nothing dispatched.
5. Accept — confirm a toast reports success, the modal closes, and the agent's status transitions to offline within one missed heartbeat interval.
6. Open that agent's Detail view — confirm the red "stopped by X on Y: reason" banner appears.
7. Confirm the actual agent process/service on the test endpoint has stopped, and (Windows) `sc qc BASAgent` shows `START_TYPE: DISABLED`, or (Linux) `systemctl is-enabled bas-agent` reports `disabled`, or (macOS) `launchctl list | grep bas-agent` shows nothing.
8. Reboot the test endpoint — confirm the agent does NOT come back on its own.
9. Manually restart it (`sc config BASAgent start=auto && sc start BASAgent` / `systemctl enable --now bas-agent` / `launchctl load -w <plist>`) and let it re-enroll — confirm the stopped banner disappears from the Detail view.
10. Log in as a non-admin — confirm no "Stop" button appears anywhere on the Agents page.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(ui): add Stop action to Agents table with confirmation modal"
git push
```

---

## Self-Review Notes

**Spec coverage:** Task 1 covers the spec's "Delivery: server → agent" and "Data model"/"Permission" sections in full. Task 2 covers "Agent-side: receiving and executing the stop" including all three platforms' distinct auto-restart guards. Task 3 covers the full "UI" section (button, modal, Detail banner) plus the manual checklist mirroring the spec's disclosed no-browser-automation limitation. The spec's "Error handling / edge cases" section is covered: not-connected (Task 1 test), disable-failure-still-exits (Task 2 test), double-stop idempotency (implicit — `shutdownFinalize`/`sendHeartbeat`/disable are all naturally idempotent, no extra guard code needed, matches the spec's own reasoning). "Out of scope" items are correctly not built.

**Placeholder scan:** none — every step has complete code or an exact command with expected output.

**Type consistency:** `models.MsgCommandStopAgent` (Task 1) matches the literal `"command_stop_agent"` string used in Task 2's agent-side `case` (Go string constants and literals compare equal regardless of which side names them — the agent package doesn't import `orchestrator/internal/models`, so it necessarily uses the literal, same pattern as the pre-existing `"command_cancel"` case). `StopAgent`'s request body field `Reason` (Task 1) matches Task 3's `{reason: reason}` JS body. `models.Agent`'s `StoppedBy`/`StoppedByName`/`StoppedAt`/`StopReason` (Task 1) match the JS field names `a.stoppedBy`/`a.stoppedByName`/`a.stoppedAt`/`a.stopReason`/`a.stopReason` used in Task 3 (JSON tags are camelCase, matching every other field on this struct). `platformDisableAutoStart`/`platformExitAfterStop` are defined exactly once per platform (Windows in `service.go`, Linux in `service_linux.go`, macOS in `service_darwin.go`) with matching signatures (`func() error` / `func()`) across all three, satisfying the single call site in `agent.go`'s `stopSelf` via the `platformDisableAutoStartFn`/`platformExitAfterStopFn` indirection.
