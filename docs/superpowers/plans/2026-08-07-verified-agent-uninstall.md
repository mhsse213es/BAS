# Verified Agent Uninstall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace today's DB-only "Remove Agent" with two distinct operations — a verified Uninstall Agent that dispatches a real command and waits for the endpoint to confirm before updating the record, and a Force Remove escape hatch that keeps today's exact behavior for permanently unavailable devices.

**Architecture:** New `agents` columns + two `AgentState` values track a dispatched uninstall through to its confirmed result. A new WS command (`command_uninstall_agent`) triggers a per-platform, in-process self-uninstall routine on the agent that reports its outcome via a new agent-token-authenticated endpoint before exiting — deliberately never invoking the OS service manager's "stop myself" call in a way that could race its own exit before the result is reported. Force Remove is `POST /api/agents/{agentId}/remove`, entirely unchanged.

**Tech Stack:** Go (`pgx/v5`, `chi`, `golang.org/x/sys/windows/svc` for the agent's Windows service), vanilla JS in `orchestrator/wwwroot/index.html`, PostgreSQL.

## Global Constraints

- No hard DB-level FK constraint on the new `agents` columns — matches this codebase's existing convention (confirmed again via the just-completed Agent Group Hierarchy feature).
- Reuse the existing `CanRemoveAgent` permission for the new dispatch endpoint — no new permission. The result-confirmation endpoint is agent-token authenticated (`validateAgentAuth`), not JWT/permission-gated, matching `UnenrollAgent`.
- Force Remove's backend (`POST /api/agents/{agentId}/remove`, `RemoveAgent` handler) is **not modified** — confirmed by the user, kept exactly as-is; only its frontend label/copy changes.
- Applying an uninstall result is idempotent / at-least-once (no status guard blocking a late result) — matches this codebase's existing run-result reconciliation convention.
- The self-uninstall routine must never call the OS service manager's stop/unload against the service the calling process itself belongs to in a way that could terminate the process before it reports its result — see Task 3 for the exact per-platform ordering that avoids this.
- Per the user's explicit decision: this feature is not production-ready until each platform (Windows/Linux/macOS) has been manually validated on a real machine — Task 6 makes this an explicit, required gate, not an optional nice-to-have.

---

### Task 1: Backend data model

**Files:**
- Create: `orchestrator/internal/db/agent_uninstall_schema.go`
- Test: `orchestrator/internal/db/agent_uninstall_schema_test.go`
- Modify: `orchestrator/cmd/server/main.go:103-106`
- Modify: `orchestrator/internal/testutil/testdb.go` (register the new schema function in the shared Docker-backed test harness — **do not skip this**; the Agent Group Hierarchy feature earlier this session hit "relation X does not exist" in every handler test because this step was initially missed)
- Modify: `orchestrator/internal/models/schema.go` (new `AgentState` values, `Agent` struct fields, `MsgCommandUninstallAgent` WS const, `UninstallResultTimeout` const, `EffectiveUninstallError` function)

**Interfaces:**
- Produces: `db.EnsureAgentUninstallSchema(ctx, pool) error`; `models.AgentStateUninstalling`, `models.AgentStateUninstalled` (`AgentState`); `models.MsgCommandUninstallAgent` (string, `"command_uninstall_agent"`); `models.UninstallResultTimeout` (`time.Duration`); `models.EffectiveUninstallError(state models.AgentState, storedError *string, requestedAt *time.Time, now time.Time) *string`; `Agent.UninstallError *string` / `Agent.UninstallErrorAt *time.Time` (JSON `uninstallError`/`uninstallErrorAt`, `omitempty`). Task 2's handlers write/read the new DB columns directly via SQL and call `EffectiveUninstallError` from `GetAgents`. Task 5's frontend reads `a.state === 'uninstalling'`/`'uninstalled'` and `a.uninstallError`.

- [ ] **Step 1: Write the failing schema test**

Create `orchestrator/internal/db/agent_uninstall_schema_test.go`:

```go
package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

// EnsureAgentUninstallSchema must be safe to call repeatedly (startup runs
// it every boot) and must leave every new column in place.
func TestEnsureAgentUninstallSchema_Idempotent(t *testing.T) {
	ctx := context.Background()
	if err := db.EnsureAgentUninstallSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("first EnsureAgentUninstallSchema: %v", err)
	}
	if err := db.EnsureAgentUninstallSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("second EnsureAgentUninstallSchema (idempotency): %v", err)
	}

	cols := []string{
		"uninstall_requested_by", "uninstall_requested_at", "uninstall_reason",
		"uninstall_prior_state", "uninstall_error", "uninstall_error_at",
	}
	for _, col := range cols {
		var exists bool
		err := sharedDB.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agents' AND column_name = $1)`,
			col,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("checking agents.%s: %v", col, err)
		}
		if !exists {
			t.Errorf("agents.%s was not added", col)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureAgentUninstallSchema_Idempotent -v`
Expected: `FAIL` — `db.EnsureAgentUninstallSchema` is undefined (compile error).

- [ ] **Step 3: Implement `EnsureAgentUninstallSchema`**

Create `orchestrator/internal/db/agent_uninstall_schema.go`:

```go
package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureAgentUninstallSchema adds the columns needed to track a dispatched
// Uninstall Agent command through to its confirmed result. Idempotent --
// safe to call on every startup. Must run after EnsureSchema (the agents
// table must already exist).
//
// uninstall_prior_state records the agent's state immediately before
// dispatch, so a failed or timed-out attempt can restore it exactly
// instead of guessing. uninstall_error/uninstall_error_at are cleared on
// a successful attempt and set on a failed one; GetAgents additionally
// computes a live timeout message when neither is set but the agent has
// been stuck in 'uninstalling' too long (see models.EffectiveUninstallError)
// -- that computation never writes to these columns.
func EnsureAgentUninstallSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_requested_by text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_requested_at timestamptz`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_reason text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_prior_state text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_error text`,
		`ALTER TABLE agents ADD COLUMN IF NOT EXISTS uninstall_error_at timestamptz`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("agent uninstall schema: %w", err)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/db/... -run TestEnsureAgentUninstallSchema_Idempotent -v`
Expected: `PASS`.

- [ ] **Step 5: Wire the call into `main.go`**

In `orchestrator/cmd/server/main.go`, replace (currently lines 103-106):

```go
	if err := db.EnsureAgentGroupSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] agent group schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")
```

with:

```go
	if err := db.EnsureAgentGroupSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] agent group schema bootstrap: %v", err)
	}
	if err := db.EnsureAgentUninstallSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] agent uninstall schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")
```

- [ ] **Step 6: Register the schema in the shared test-DB harness**

In `orchestrator/internal/testutil/testdb.go`, find the `EnsureAgentGroupSchema` call added for the previous feature (near the end of `newTestDB`, right before `return &TestDB{`) and add immediately after it:

```go
	if err := db.EnsureAgentUninstallSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureAgentUninstallSchema: %w", err)
	}
```

- [ ] **Step 7: Add the `AgentState` values, WS const, timeout const, and `EffectiveUninstallError`**

In `orchestrator/internal/models/schema.go`, replace (currently lines 235-241):

```go
const (
	AgentStateEnrolling   AgentState = "enrolling"
	AgentStateActive      AgentState = "active"
	AgentStateRestricted  AgentState = "restricted"
	AgentStateQuarantined AgentState = "quarantined"
	AgentStateRetired     AgentState = "retired"
)
```

with:

```go
const (
	AgentStateEnrolling   AgentState = "enrolling"
	AgentStateActive      AgentState = "active"
	AgentStateRestricted  AgentState = "restricted"
	AgentStateQuarantined AgentState = "quarantined"
	AgentStateRetired     AgentState = "retired"
	// AgentStateUninstalling means an Uninstall Agent command has been
	// dispatched and the endpoint hasn't reported a result yet. Unlike
	// Retired/Uninstalled, this state stays in the default agent list (not
	// filtered out) so the admin can see it in progress.
	AgentStateUninstalling AgentState = "uninstalling"
	// AgentStateUninstalled means the endpoint confirmed a successful
	// uninstall. Distinct from Retired on purpose: Retired means "an admin
	// marked this gone without proof" (Force Remove); Uninstalled means "the
	// endpoint proved it removed itself."
	AgentStateUninstalled AgentState = "uninstalled"
)

// UninstallResultTimeout is how long GetAgents waits for an uninstall
// result before displaying an agent stuck in AgentStateUninstalling as
// timed out (see EffectiveUninstallError). Comfortably longer than the
// agent's own internal service-stop timeout (15s on Windows) plus normal
// network latency.
const UninstallResultTimeout = 2 * time.Minute

// EffectiveUninstallError overrides a nil stored error with a timeout
// message when an agent has been stuck in AgentStateUninstalling longer
// than UninstallResultTimeout with no result received. Computed on read,
// same pattern as EffectiveAgentStatus -- nothing is written to the
// database, and a result arriving late is still applied normally by
// whatever wrote it.
func EffectiveUninstallError(state AgentState, storedError *string, requestedAt *time.Time, now time.Time) *string {
	if state != AgentStateUninstalling || storedError != nil || requestedAt == nil {
		return storedError
	}
	if now.Sub(*requestedAt) > UninstallResultTimeout {
		msg := "No response from the endpoint — it may have gone offline mid-uninstall. Retry or use Force Remove."
		return &msg
	}
	return storedError
}
```

- [ ] **Step 8: Add the `Agent` struct fields**

In `orchestrator/internal/models/schema.go`, replace (currently lines 299-304):

```go
	// GroupID/GroupName are the agent's hierarchical group assignment (nil =
	// Ungrouped). GroupName is resolved read-time via a join, same pattern
	// as StoppedByName above.
	GroupID   *int64  `json:"groupId,omitempty"`
	GroupName *string `json:"groupName,omitempty"`
}
```

with:

```go
	// GroupID/GroupName are the agent's hierarchical group assignment (nil =
	// Ungrouped). GroupName is resolved read-time via a join, same pattern
	// as StoppedByName above.
	GroupID   *int64  `json:"groupId,omitempty"`
	GroupName *string `json:"groupName,omitempty"`
	// UninstallError/UninstallErrorAt are set by the agent's own
	// uninstall-result report on failure, or computed live as a timeout
	// message if the agent never reports back (see EffectiveUninstallError).
	// Cleared on a successful uninstall.
	UninstallError   *string    `json:"uninstallError,omitempty"`
	UninstallErrorAt *time.Time `json:"uninstallErrorAt,omitempty"`
}
```

- [ ] **Step 9: Add the `MsgCommandUninstallAgent` WS constant**

In `orchestrator/internal/models/schema.go`, replace (currently lines 385-389):

```go
	// MsgCommandStopAgent tells a connected agent to durably stop itself —
	// finalize any in-flight run, disable its platform service so it does not
	// restart on its own, then exit. Payload: {"reason": string}.
	MsgCommandStopAgent = "command_stop_agent"
)
```

with:

```go
	// MsgCommandStopAgent tells a connected agent to durably stop itself —
	// finalize any in-flight run, disable its platform service so it does not
	// restart on its own, then exit. Payload: {"reason": string}.
	MsgCommandStopAgent = "command_stop_agent"
	// MsgCommandUninstallAgent tells a connected agent to fully uninstall
	// itself (not just stop) -- remove its service/unit/daemon registration
	// and autostart artifacts, report the real outcome to the server, then
	// exit. Payload: {"reason": string}.
	MsgCommandUninstallAgent = "command_uninstall_agent"
)
```

- [ ] **Step 10: Build and run the full db package test suite**

Run: `cd orchestrator && go build ./... && go test ./internal/db/... ./internal/models/... -v`
Expected: build succeeds, all tests pass (including the new one and everything pre-existing).

- [ ] **Step 11: Commit**

```bash
git add internal/db/agent_uninstall_schema.go internal/db/agent_uninstall_schema_test.go \
        cmd/server/main.go internal/testutil/testdb.go internal/models/schema.go
git commit -m "$(cat <<'EOF'
feat(db): add agent uninstall tracking columns and states

New EnsureAgentUninstallSchema (idempotent, follows the
EnsureAgentGroupSchema pattern), wired into main.go's startup sequence
and the shared Docker-backed test harness. Adds AgentStateUninstalling/
AgentStateUninstalled, a MsgCommandUninstallAgent WS command constant,
and EffectiveUninstallError -- a read-time timeout computation matching
EffectiveAgentStatus's existing pattern, so an agent stuck mid-uninstall
surfaces a clear message without a background poller.
EOF
)"
git push
```

---

### Task 2: Backend API — dispatch, result, and GetAgents

**Files:**
- Create: `orchestrator/internal/api/agent_uninstall_handlers.go`
- Create: `orchestrator/internal/api/agent_uninstall_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Modify: `orchestrator/internal/api/handlers.go:567-630` (`GetAgents`)

**Interfaces:**
- Consumes: `models.AgentStateUninstalling`/`AgentStateUninstalled`, `models.MsgCommandUninstallAgent`, `models.EffectiveUninstallError`, `Agent.UninstallError`/`UninstallErrorAt` from Task 1.
- Produces: `POST /api/agents/{agentId}/uninstall` (admin, `CanRemoveAgent`), `POST /api/agents/{agentId}/uninstall-result` (agent-token) — both consumed by Task 3's agent-side code and Task 5's frontend.

- [ ] **Step 1: Write the failing handler tests**

Create `orchestrator/internal/api/agent_uninstall_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestUninstallAgent_RequiresReason(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		body, _ := json.Marshal(map[string]string{"reason": ""})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/agent-x/uninstall", bytes.NewReader(body)), "agentId", "agent-x")
		rec := httptest.NewRecorder()
		h.UninstallAgent(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("empty reason: status = %d, want 400", rec.Code)
		}
	})
}

// Uninstall Agent must never silently claim success for an unreachable
// endpoint -- unlike Force Remove, it requires a live connection.
func TestUninstallAgent_NotConnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-uninstall-notconn"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))

		body, _ := json.Marshal(map[string]string{"reason": "decommissioning"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/uninstall", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.UninstallAgent(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("agent not connected: status = %d, want 503", rec.Code)
		}

		var state string
		if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, agentID).Scan(&state); err != nil {
			t.Fatalf("read state: %v", err)
		}
		if state == string(models.AgentStateUninstalling) {
			t.Fatalf("state = %q, must not become uninstalling when dispatch failed", state)
		}
	})
}

// A connected agent gets marked uninstalling and keeps its prior state on
// record so a failed/timed-out attempt can restore it.
func TestUninstallAgent_Connected_MarksUninstalling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		hub := ws.NewHub()
		h := New(pool, hub, nil, "")
		agentID := "agent-uninstall-connected"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		fake := startFakeAgent(t, hub, agentID)

		body, _ := json.Marshal(map[string]string{"reason": "decommissioning"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/uninstall", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.UninstallAgent(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("dispatch: status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandUninstallAgent {
			t.Fatalf("WS message type = %q, want %q", env.Type, models.MsgCommandUninstallAgent)
		}

		var state, priorState string
		if err := pool.QueryRow(context.Background(),
			`SELECT state, uninstall_prior_state FROM agents WHERE agent_id=$1`, agentID,
		).Scan(&state, &priorState); err != nil {
			t.Fatalf("read: %v", err)
		}
		if state != string(models.AgentStateUninstalling) {
			t.Fatalf("state = %q, want uninstalling", state)
		}
		if priorState != "active" {
			t.Fatalf("uninstall_prior_state = %q, want active", priorState)
		}
	})
}

// A successful result must move the agent to 'uninstalled' and clear any
// prior error.
func TestUninstallAgentResult_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-uninstall-result-ok"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET state='uninstalling', uninstall_prior_state='active', uninstall_error='stale' WHERE agent_id=$1`, agentID); err != nil {
			t.Fatalf("seed uninstalling state: %v", err)
		}

		body, _ := json.Marshal(map[string]any{"success": true})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/uninstall-result", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.UninstallAgentResult(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var state string
		var uninstallError *string
		if err := pool.QueryRow(context.Background(),
			`SELECT state, uninstall_error FROM agents WHERE agent_id=$1`, agentID,
		).Scan(&state, &uninstallError); err != nil {
			t.Fatalf("read: %v", err)
		}
		if state != string(models.AgentStateUninstalled) {
			t.Fatalf("state = %q, want uninstalled", state)
		}
		if uninstallError != nil {
			t.Fatalf("uninstall_error = %q, want cleared", *uninstallError)
		}
	})
}

// A failed result must restore the prior state and record the error, not
// leave the agent stuck in 'uninstalling' or silently marked gone.
func TestUninstallAgentResult_Failure_RestoresPriorState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-uninstall-result-fail"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET state='uninstalling', uninstall_prior_state='restricted' WHERE agent_id=$1`, agentID); err != nil {
			t.Fatalf("seed uninstalling state: %v", err)
		}

		body, _ := json.Marshal(map[string]any{"success": false, "error": "service delete failed: access denied"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/uninstall-result", bytes.NewReader(body)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.UninstallAgentResult(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var state, uninstallError string
		if err := pool.QueryRow(context.Background(),
			`SELECT state, uninstall_error FROM agents WHERE agent_id=$1`, agentID,
		).Scan(&state, &uninstallError); err != nil {
			t.Fatalf("read: %v", err)
		}
		if state != "restricted" {
			t.Fatalf("state = %q, want restored to restricted", state)
		}
		if uninstallError != "service delete failed: access denied" {
			t.Fatalf("uninstall_error = %q, want the reported message", uninstallError)
		}
	})
}

// GetAgents must surface a live timeout message for an agent stuck in
// 'uninstalling' past the timeout window, without writing anything to the DB.
func TestGetAgents_UninstallTimeoutDisplayedLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-uninstall-timeout"
		h.EnrollAgent(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		staleRequestedAt := time.Now().Add(-5 * time.Minute)
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET state='uninstalling', uninstall_requested_at=$1 WHERE agent_id=$2`, staleRequestedAt, agentID); err != nil {
			t.Fatalf("seed stale uninstalling state: %v", err)
		}

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		var agents []models.Agent
		if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var found *models.Agent
		for i := range agents {
			if agents[i].AgentID == agentID {
				found = &agents[i]
			}
		}
		if found == nil {
			t.Fatal("agent missing from GetAgents")
		}
		if found.UninstallError == nil || *found.UninstallError == "" {
			t.Fatal("expected a live timeout message, got none")
		}

		var storedError *string
		if err := pool.QueryRow(context.Background(), `SELECT uninstall_error FROM agents WHERE agent_id=$1`, agentID).Scan(&storedError); err != nil {
			t.Fatalf("read stored error: %v", err)
		}
		if storedError != nil {
			t.Fatalf("stored uninstall_error = %q, want nil -- timeout display must not write to the DB", *storedError)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestUninstallAgent|TestGetAgents_UninstallTimeout" -v`
Expected: `FAIL` — compile errors (`h.UninstallAgent`/`h.UninstallAgentResult` undefined).

- [ ] **Step 3: Implement the handlers**

Create `orchestrator/internal/api/agent_uninstall_handlers.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
)

// POST /api/agents/{agentId}/uninstall — dispatches a real uninstall order
// to a connected agent and marks the record 'uninstalling' until the
// endpoint confirms success or failure via UninstallAgentResult below.
// Unlike RemoveAgent (Force Remove), this requires a live connection and
// never silently claims the endpoint is gone. Admin-only; the route group
// enforces the permission check.
func (h *Handler) UninstallAgent(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Reason) == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}

	var priorState string
	if err := h.db.QueryRow(r.Context(),
		`SELECT COALESCE(state, 'active') FROM agents WHERE agent_id = $1`, agentID,
	).Scan(&priorState); err != nil {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}

	sent := h.hub.SendToAgent(agentID, models.WSMessage{
		Type:    models.MsgCommandUninstallAgent,
		AgentID: agentID,
		Data:    map[string]string{"reason": body.Reason},
	})
	if !sent {
		jsonError(w, "agent not connected — cannot verify uninstall. Retry once it reconnects, or use Force Remove for a permanently unavailable device.", http.StatusServiceUnavailable)
		return
	}

	actorID := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		actorID = claims.UserID
	}
	_, err := h.db.Exec(r.Context(),
		`UPDATE agents SET state = 'uninstalling', uninstall_requested_by = $1, uninstall_requested_at = NOW(),
		        uninstall_reason = $2, uninstall_prior_state = $3, uninstall_error = NULL, uninstall_error_at = NULL
		 WHERE agent_id = $4`,
		actorID, body.Reason, priorState, agentID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "agent.uninstall", agentID, map[string]any{"reason": body.Reason}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "status": "uninstall_dispatched"})
}

// POST /api/agents/{agentId}/uninstall-result — the agent's own report of
// whether command_uninstall_agent actually succeeded on the endpoint.
// Agent-token authenticated (same as UnenrollAgent), not a user JWT -- there
// is no admin session at this point. Applied whenever it arrives, no matter
// how long dispatch was ago (idempotent, at-least-once delivery -- matches
// UnenrollAgent's own convention).
func (h *Handler) UninstallAgentResult(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	agentID := chi.URLParam(r, "agentId")
	var body struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	var err error
	if body.Success {
		_, err = h.db.Exec(r.Context(),
			`UPDATE agents SET state = 'uninstalled', uninstall_error = NULL, uninstall_error_at = NULL WHERE agent_id = $1`,
			agentID)
	} else {
		_, err = h.db.Exec(r.Context(),
			`UPDATE agents SET state = COALESCE(uninstall_prior_state, 'active'), uninstall_error = $1, uninstall_error_at = NOW()
			 WHERE agent_id = $2`,
			body.Error, agentID)
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLogAs(r, "agent:"+agentID, "agent.uninstall_result", agentID,
		map[string]any{"success": body.Success, "error": body.Error}, "ok")
	h.hub.BroadcastBrowsers(models.WSMessage{Type: models.MsgAgentUpdate, AgentID: agentID})
	respond(w, map[string]any{"agentId": agentID, "success": body.Success})
}
```

The file's import block is exactly `encoding/json`, `net/http`, `strings`, `github.com/go-chi/chi/v5`, `github.com/audspect/bas/internal/auth`, `github.com/audspect/bas/internal/models` — no `time` import, since neither handler references it.

- [ ] **Step 4: Add the `uninstall_error`/`uninstall_error_at`/`uninstall_requested_at` columns to `GetAgents` and compute the live timeout**

In `orchestrator/internal/api/handlers.go`, replace (currently lines 567-630):

```go
func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	query := `SELECT a.agent_id, a.hostname, a.ip_address, a.os_version, a.username, a.status, a.env_label,
	        a.has_report, a.binary_hash, a.binary_trusted, a.last_update,
	        COALESCE(a.state, 'active'), COALESCE(a.policy_json::text, '{}'), a.enrolled_at,
	        (SELECT COUNT(*) FROM scenario_runs sr WHERE sr.agent_id = a.agent_id) AS sims,
	        a.stopped_by, COALESCE(u.username, a.stopped_by), a.stopped_at, a.stop_reason,
	        a.group_id, g.name
	 FROM agents a LEFT JOIN users u ON u.id = a.stopped_by LEFT JOIN agent_groups g ON g.id = a.group_id`
	var args []any
	if groupIDParam := r.URL.Query().Get("groupId"); groupIDParam != "" {
		groupID, err := strconv.ParseInt(groupIDParam, 10, 64)
		if err != nil {
			jsonError(w, "invalid groupId", http.StatusBadRequest)
			return
		}
		args = append(args, groupID)
		// Recursive CTE: the target group plus every descendant group, so
		// selecting "Finance" also surfaces agents in "Servers"/"Workstations".
		query += ` WHERE a.group_id IN (
			WITH RECURSIVE descendants(id) AS (
				SELECT id FROM agent_groups WHERE id = $` + strconv.Itoa(len(args)) + `
				UNION ALL
				SELECT gr.id FROM agent_groups gr JOIN descendants d ON gr.parent_id = d.id
			)
			SELECT id FROM descendants
		)`
	}
	query += ` ORDER BY a.last_update DESC`

	rows, err := h.db.Query(r.Context(), query, args...)
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

with:

```go
func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	query := `SELECT a.agent_id, a.hostname, a.ip_address, a.os_version, a.username, a.status, a.env_label,
	        a.has_report, a.binary_hash, a.binary_trusted, a.last_update,
	        COALESCE(a.state, 'active'), COALESCE(a.policy_json::text, '{}'), a.enrolled_at,
	        (SELECT COUNT(*) FROM scenario_runs sr WHERE sr.agent_id = a.agent_id) AS sims,
	        a.stopped_by, COALESCE(u.username, a.stopped_by), a.stopped_at, a.stop_reason,
	        a.group_id, g.name, a.uninstall_error, a.uninstall_error_at, a.uninstall_requested_at
	 FROM agents a LEFT JOIN users u ON u.id = a.stopped_by LEFT JOIN agent_groups g ON g.id = a.group_id`
	var args []any
	if groupIDParam := r.URL.Query().Get("groupId"); groupIDParam != "" {
		groupID, err := strconv.ParseInt(groupIDParam, 10, 64)
		if err != nil {
			jsonError(w, "invalid groupId", http.StatusBadRequest)
			return
		}
		args = append(args, groupID)
		// Recursive CTE: the target group plus every descendant group, so
		// selecting "Finance" also surfaces agents in "Servers"/"Workstations".
		query += ` WHERE a.group_id IN (
			WITH RECURSIVE descendants(id) AS (
				SELECT id FROM agent_groups WHERE id = $` + strconv.Itoa(len(args)) + `
				UNION ALL
				SELECT gr.id FROM agent_groups gr JOIN descendants d ON gr.parent_id = d.id
			)
			SELECT id FROM descendants
		)`
	}
	query += ` ORDER BY a.last_update DESC`

	rows, err := h.db.Query(r.Context(), query, args...)
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
		var uninstallRequestedAt *time.Time
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSVersion,
			&a.Username, &a.Status, &a.EnvLabel, &a.HasReport,
			&a.BinaryHash, &a.BinaryTrusted, &a.LastUpdate,
			&stateStr, &policyRaw, &a.EnrolledAt, &a.Sims,
			&a.StoppedBy, &a.StoppedByName, &a.StoppedAt, &a.StopReason,
			&a.GroupID, &a.GroupName, &a.UninstallError, &a.UninstallErrorAt, &uninstallRequestedAt); err != nil {
			continue
		}
		// Connectivity is heartbeat-driven: a dead/rebooted agent stops updating
		// last_update, so surface it as offline rather than its frozen last status.
		a.Status = models.EffectiveAgentStatus(a.Status, a.LastUpdate, now)
		a.State = models.AgentState(stateStr)
		a.UninstallError = models.EffectiveUninstallError(a.State, a.UninstallError, uninstallRequestedAt, now)
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

- [ ] **Step 5: Register the 2 routes**

In `orchestrator/internal/api/routes.go`, find the agent-token-authenticated route group (near line 47, `r.Post("/api/agents/unenroll", h.UnenrollAgent)`) and add immediately after it:

```go
	r.Post("/api/agents/{agentId}/uninstall-result", h.UninstallAgentResult)
```

Then find the admin-permission-gated agent routes (near line 422, `r.With(auth.RequirePermission(auth.CanRemoveAgent)).Post("/api/agents/{agentId}/remove", h.RemoveAgent)`) and add immediately after it:

```go
	r.With(auth.RequirePermission(auth.CanRemoveAgent)).Post("/api/agents/{agentId}/uninstall", h.UninstallAgent)
```

- [ ] **Step 6: Add the RBAC matrix entries**

In `orchestrator/internal/api/rbac_matrix_test.go`, find the `CanRemoveAgent` entry in `routeMatrix` (currently line 214) and add immediately after it:

```go
	{http.MethodPost, "/api/agents/{agentId}/uninstall", tierPermission, auth.CanRemoveAgent},
```

Then find the `publicRoutes` exemption map's `"POST /api/agents/unenroll": true,` entry (currently line 352) and add immediately after it:

```go
	"POST /api/agents/{agentId}/uninstall-result":  true,
```

(This second map is what `TestRBACMatrix_NoDrift` checks against for every route mounted outside the JWT-gated group — `uninstall-result` is agent-token authenticated, same tier as `unenroll`, not a `routeMatrix`/`tierPermission` entry.)

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run "TestUninstallAgent|TestGetAgents_UninstallTimeout|TestRBACMatrix" -v`
Expected: build succeeds, all matched tests `PASS`.

- [ ] **Step 8: Commit**

```bash
git add internal/api/agent_uninstall_handlers.go internal/api/agent_uninstall_handlers_test.go \
        internal/api/routes.go internal/api/rbac_matrix_test.go internal/api/handlers.go
git commit -m "$(cat <<'EOF'
feat(api): verified agent uninstall dispatch + result endpoints

POST /api/agents/{agentId}/uninstall (admin, CanRemoveAgent) requires
a live connection -- unlike Force Remove, it never silently claims an
unreachable endpoint is gone. Records the agent's prior state before
marking it 'uninstalling' so a failed/timed-out attempt can restore it
exactly. POST /api/agents/{agentId}/uninstall-result (agent-token,
same auth tier as the existing unenroll endpoint) applies the agent's
real outcome whenever it arrives -- 'uninstalled' on success, restored
prior state + recorded error on failure. GetAgents now also computes a
live timeout message (EffectiveUninstallError) for an agent stuck in
'uninstalling' too long, without writing anything to the database.
EOF
)"
git push
```

---

### Task 3: Agent-side self-uninstall (Windows, Linux, macOS)

**Files:**
- Modify: `agent/agent.go` (new `command_uninstall_agent` WS case, new `uninstallSelf` method, new `platformSelfUninstallFn` indirection)
- Create: `agent/uninstall_result.go` (`reportUninstallResult`)
- Modify: `agent/service.go` (new `platformSelfUninstall()` for Windows)
- Modify: `agent/service_linux.go` (new `platformSelfUninstall()` for Linux)
- Modify: `agent/service_darwin.go` (new `platformSelfUninstall()` for macOS, and a change to the existing `platformDisableAutoStart()` — see Step 5's rationale)
- Test: `agent/uninstall_self_test.go`

**Interfaces:**
- Consumes: `POST /api/agents/{agentId}/uninstall-result` from Task 2.
- Produces: nothing consumed by later tasks in this plan — this is the agent-side half of the round trip Task 2 already assumes.

**Design note carried from the spec/investigation (read before writing any code in this task):** the existing local `agent.exe -uninstall` path (`svcUninstall()` in `service.go`/`service_linux.go`/`service_darwin.go`) always runs as a *separate, short-lived process* stopping/removing an *independently running* service — so it can safely call `Control(svc.Stop)` / `systemctl stop` / `launchctl unload` against that other process without racing its own exit. The new WS-triggered path is different: the command arrives *inside the already-running service process itself*. Calling the OS service manager's "stop me" primitive from within that same process risks the process being torn down (SIGTERM on Linux, or a documented side-effect kill on macOS — see Step 5) before it can report its result over HTTP. The design below avoids this by never calling those self-referential stop primitives directly from the new code; it only ever removes the *persistent registration* (so the agent won't come back), reports the result, and then reuses the exact same, already-tested `platformDisableAutoStartFn`/`platformExitAfterStopFn` pair that `stopSelf()` (Stop Agent) already relies on for the actual stop/exit.

- [ ] **Step 1: Write the failing agent-side test**

Create `agent/uninstall_self_test.go`:

```go
package main

import (
	"errors"
	"reflect"
	"testing"
)

var errSelfUninstallFailedForTest = errors.New("self-uninstall failed for test")

func TestUninstallSelf_SuccessReportsThenDisablesThenExits(t *testing.T) {
	var calls []string

	origSelfUninstall := platformSelfUninstallFn
	origDisable := platformDisableAutoStartFn
	origExit := platformExitAfterStopFn
	origReport := reportUninstallResultFn
	defer func() {
		platformSelfUninstallFn = origSelfUninstall
		platformDisableAutoStartFn = origDisable
		platformExitAfterStopFn = origExit
		reportUninstallResultFn = origReport
	}()
	platformSelfUninstallFn = func() error { calls = append(calls, "selfUninstall"); return nil }
	platformDisableAutoStartFn = func() error { calls = append(calls, "disable"); return nil }
	platformExitAfterStopFn = func() { calls = append(calls, "exit") }
	reportUninstallResultFn = func(a *Agent, err error) {
		calls = append(calls, "report:"+boolToOutcome(err == nil))
	}

	a := newAgent(Config{ServerURL: "http://127.0.0.1:1"}, Identity{AgentID: "test-agent"})
	a.status = "idle" // shutdownFinalize is a no-op when idle -- isolates this test to uninstallSelf's own sequencing

	a.uninstallSelf("decommissioning host")

	want := []string{"selfUninstall", "report:success", "disable", "exit"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestUninstallSelf_CleanupFailureStillReportsThenDisablesThenExits(t *testing.T) {
	var calls []string

	origSelfUninstall := platformSelfUninstallFn
	origDisable := platformDisableAutoStartFn
	origExit := platformExitAfterStopFn
	origReport := reportUninstallResultFn
	defer func() {
		platformSelfUninstallFn = origSelfUninstall
		platformDisableAutoStartFn = origDisable
		platformExitAfterStopFn = origExit
		reportUninstallResultFn = origReport
	}()
	platformSelfUninstallFn = func() error { calls = append(calls, "selfUninstall"); return errSelfUninstallFailedForTest }
	platformDisableAutoStartFn = func() error { calls = append(calls, "disable"); return nil }
	platformExitAfterStopFn = func() { calls = append(calls, "exit") }
	reportUninstallResultFn = func(a *Agent, err error) {
		calls = append(calls, "report:"+boolToOutcome(err == nil))
	}

	a := newAgent(Config{ServerURL: "http://127.0.0.1:1"}, Identity{AgentID: "test-agent"})
	a.status = "idle"

	a.uninstallSelf("decommissioning host")

	want := []string{"selfUninstall", "report:failure", "disable", "exit"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v (a cleanup failure must still be reported, then still disable+exit)", calls, want)
	}
}

func boolToOutcome(ok bool) string {
	if ok {
		return "success"
	}
	return "failure"
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd agent && go test ./... -run TestUninstallSelf -v`
Expected: `FAIL` — `platformSelfUninstallFn`, `reportUninstallResultFn`, `a.uninstallSelf` all undefined (compile error).

- [ ] **Step 3: Implement `reportUninstallResult` and its test indirection**

Create `agent/uninstall_result.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// reportUninstallResult tells the server whether this agent's self-uninstall
// (triggered by command_uninstall_agent) succeeded, using the in-memory
// cfg/id this already-running process was started with -- unlike
// notifyServerUnenroll (called from the separate-process CLI --uninstall
// path), there is no need to re-read serverURL/secret from disk here.
func reportUninstallResult(a *Agent, uninstallErr error) {
	body := map[string]any{"success": uninstallErr == nil}
	if uninstallErr != nil {
		body["error"] = uninstallErr.Error()
	}
	data, err := json.Marshal(body)
	if err != nil {
		log.Printf("[!] marshal uninstall result: %v", err)
		return
	}
	url := a.cfg.ServerURL + "/api/agents/" + a.id.AgentID + "/uninstall-result"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		log.Printf("[!] build uninstall-result request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.AgentSecret != "" {
		req.Header.Set("X-Agent-Token", a.cfg.AgentSecret)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[!] POST uninstall-result: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("[!] uninstall-result: server returned %d", resp.StatusCode)
	}
}

// reportUninstallResultFn is an indirection over reportUninstallResult so
// tests can substitute a no-op stand-in instead of making a real HTTP call.
var reportUninstallResultFn = reportUninstallResult
```

- [ ] **Step 4: Add `uninstallSelf` and the `platformSelfUninstallFn` indirection to `agent.go`**

In `agent/agent.go`, replace (currently lines 322-330):

```go
// platformDisableAutoStartFn and platformExitAfterStopFn are indirections
// over the real platform-specific functions (defined per-OS in
// service.go/service_linux.go/service_darwin.go) so tests can substitute
// no-op stand-ins instead of actually disabling a service or exiting the
// test process.
var (
	platformDisableAutoStartFn = platformDisableAutoStart
	platformExitAfterStopFn    = platformExitAfterStop
)
```

with:

```go
// platformDisableAutoStartFn, platformExitAfterStopFn, and
// platformSelfUninstallFn are indirections over the real platform-specific
// functions (defined per-OS in service.go/service_linux.go/service_darwin.go)
// so tests can substitute no-op stand-ins instead of actually touching
// service state or exiting the test process.
var (
	platformDisableAutoStartFn = platformDisableAutoStart
	platformExitAfterStopFn    = platformExitAfterStop
	platformSelfUninstallFn    = platformSelfUninstall
)
```

Then, immediately after `stopSelf` (currently ending at line 347 with the closing `}`), add:

```go

// uninstallSelf performs a durable, operator-requested full uninstall:
// finalize any in-flight run, remove the artifacts that make the agent come
// back (service/unit/daemon registration, tray autostart -- see
// platformSelfUninstall per platform), report the real outcome to the
// server BEFORE the process might exit, then disable+exit exactly like
// stopSelf does. Reporting before disable/exit matters because on some
// platforms disabling has the documented side effect of ending this very
// process (see platformDisableAutoStart's macOS implementation) -- if the
// report happened after, a failure could go unreported. See
// docs/superpowers/specs/2026-08-07-verified-agent-uninstall-design.md for
// why this never asks the OS service manager to stop the process from
// within itself.
func (a *Agent) uninstallSelf(reason string) {
	log.Printf("[*] Uninstall requested by operator: %s", reason)
	a.logger.Op("warn", "lifecycle", "agent uninstall requested by operator: "+reason)
	a.shutdownFinalize(shutdownGrace)
	a.sendHeartbeat("offline")
	platformRestoreOnShutdown()

	uninstallErr := platformSelfUninstallFn()
	if uninstallErr != nil {
		log.Printf("[!] self-uninstall cleanup failed: %v", uninstallErr)
	}
	reportUninstallResultFn(a, uninstallErr)

	if err := platformDisableAutoStartFn(); err != nil {
		log.Printf("[!] disable auto-start: %v — agent may restart at next boot", err)
	}
	platformExitAfterStopFn()
}
```

Then, in the WS message-handling switch (find `case "command_stop_agent":`, currently lines 961-969), add immediately after its closing (before `default:`):

```go

		case "command_uninstall_agent":
			var body struct {
				Reason string `json:"reason"`
			}
			if err := json.Unmarshal(msg.Data, &body); err != nil {
				log.Printf("[!] WS: bad uninstall command: %v", err)
				continue
			}
			go a.uninstallSelf(body.Reason)
```

- [ ] **Step 5: Implement `platformSelfUninstall()` for Windows**

In `agent/service.go`, add (immediately after `platformDisableAutoStart`, currently ending at line 383):

```go

// platformSelfUninstall performs the parts of an uninstall that are safe to
// run from within the live, running service process itself: cleaning up
// tray/registry artifacts, scheduling the binary for delete-on-reboot, and
// marking the service registration for deletion via Delete() -- a legal,
// non-blocking call while running. Windows completes the actual removal
// once the service later reaches the Stopped state, which
// platformDisableAutoStartFn/platformExitAfterStopFn (called by
// uninstallSelf right after this returns) already bring about via the same
// stopRequested-channel signaling used by Stop Agent. This deliberately
// does NOT call Control(svc.Stop) or wait for Stopped itself -- doing so
// from within the very process being stopped would race this function's
// own return and the HTTP result report that follows it.
func platformSelfUninstall() error {
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

	var binaryPath string
	if cfg, cfgErr := s.Config(); cfgErr == nil {
		binaryPath = cfg.BinaryPathName
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("mark service for deletion: %w", err)
	}
	_ = eventlog.Remove(svcName)

	// Everything below is best-effort cleanup, matching svcUninstall's own
	// philosophy: a missing key/window/file is already the desired end
	// state, not an error worth failing the whole uninstall over.
	if binaryPath != "" {
		if err := scheduleBinaryDeleteOnReboot(binaryPath); err != nil {
			log.Printf("[~] Could not schedule binary for delayed deletion: %v", err)
		}
	}
	if err := removeTrayRunKey(); err != nil {
		log.Printf("[~] Could not remove tray autostart entry: %v", err)
	}
	closeTrayWindow()
	if err := removeTrayShortcut(); err != nil {
		log.Printf("[~] Could not remove tray shortcut: %v", err)
	}
	return nil
}
```

- [ ] **Step 6: Implement `platformSelfUninstall()` for Linux**

In `agent/service_linux.go`, add (immediately after `platformDisableAutoStart`, currently ending at line 145):

```go

// platformSelfUninstall removes the systemd unit's boot-time enablement and
// deletes its unit file, then reloads systemd's unit cache. It deliberately
// does NOT call `systemctl stop` on the unit the calling process belongs to
// -- that would send SIGTERM to this very process before it can report the
// result and exit cleanly. The process's own exit (via
// platformExitAfterStopFn -- os.Exit(0) on Linux, called right after this
// by uninstallSelf) is what actually stops it; Restart=on-failure does not
// fire on a clean exit. Matches svcUninstall's existing choice to leave the
// binary/config in place -- only the unit definition is removed here.
func platformSelfUninstall() error {
	if err := exec.Command("systemctl", "disable", "bas-agent.service").Run(); err != nil {
		fmt.Printf("[~] systemctl disable: %v\n", err)
	}
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Printf("[~] systemctl daemon-reload: %v\n", err)
	}
	return nil
}
```

- [ ] **Step 7: Implement `platformSelfUninstall()` for macOS, and fix `platformDisableAutoStart` to unload by label**

In `agent/service_darwin.go`, replace (currently lines 119-129):

```go
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
```

with:

```go
// darwinLaunchdLabel matches the <key>Label</key> written into the plist by
// svcInstall above.
const darwinLaunchdLabel = "com.audspect.bas-agent"

// platformDisableAutoStart unloads the launchd job so it does not start at
// the endpoint's next boot. Unlike Linux/Windows, this must run BEFORE the
// process exits, not after: the launchd plist's
// KeepAlive=true restarts the job unconditionally on ANY exit (clean or
// not), so exiting first would just be relaunched before this had a chance
// to disable it. Note this call itself typically terminates the process as
// a side effect of unloading — that's expected; platformExitAfterStop below
// becomes a no-op in that case.
//
// Unloads by label (via `bootout`) rather than by plist path (the legacy
// `unload <path>` form) so this still works when the plist file has
// already been removed -- the case for the remote self-uninstall flow,
// where platformSelfUninstall (below) deletes the plist before this runs.
func platformDisableAutoStart() error {
	return exec.Command("launchctl", "bootout", "system/"+darwinLaunchdLabel).Run()
}

// platformSelfUninstall removes the plist so the daemon does not reload at
// the endpoint's next boot. Safe to call while running -- deleting the file
// has no effect on the currently-loaded job; platformDisableAutoStartFn
// (called by uninstallSelf right after this returns, and after the result
// is reported) is what actually unloads the running job, and now does so by
// label so it no longer depends on this file still existing at that point.
func platformSelfUninstall() error {
	if err := os.Remove(darwinPlistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}
	return nil
}
```

- [ ] **Step 8: Run the agent test suite and cross-compile all three platforms**

Run:
```bash
cd agent
go test ./... -v
GOOS=windows GOARCH=amd64 go build ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=amd64 go build ./...
```
Expected: all tests `PASS` (this repo's own Windows-only tests, like `uninstall_windows_test.go`, only run natively on Windows — confirm via `go test ./... -v` on this Windows machine that they still pass unaffected); all three `GOOS` cross-compiles succeed with no errors. Linux/macOS-specific runtime behavior (whether `systemctl`/`launchctl` actually behave as designed) cannot be verified by cross-compilation alone — that is Task 6's job.

- [ ] **Step 9: Commit**

```bash
git add agent/agent.go agent/uninstall_result.go agent/uninstall_self_test.go \
        agent/service.go agent/service_linux.go agent/service_darwin.go
git commit -m "$(cat <<'EOF'
feat(agent): remote-triggered self-uninstall (Windows/Linux/macOS)

New command_uninstall_agent WS handler + uninstallSelf, parallel to
the existing stopSelf/command_stop_agent (Stop Agent) pattern. Adds a
new platformSelfUninstall() per platform that removes only the
persistent "will come back" registration (service/unit/plist, tray
autostart) -- never the OS service manager's self-referential stop
call, which on Linux would SIGTERM the calling process and on macOS
already has a documented side effect of ending it (see
platformDisableAutoStart). Reuses the existing, already-tested
platformDisableAutoStartFn/platformExitAfterStopFn pair (used by Stop
Agent today) for the actual stop/exit, called only after the result
has been reported to the server. Also fixes platformDisableAutoStart
on macOS to unload by launchd label instead of by plist path, so it
still works once platformSelfUninstall has already removed the file.
EOF
)"
git push
```

---

### Task 4: Fix the existing local-uninstall notify-timing bug

**Files:**
- Modify: `agent/service.go` (`svcUninstall`, Windows)
- Modify: `agent/service_linux.go` (`svcUninstall`, Linux)
- Modify: `agent/service_darwin.go` (`svcUninstall`, macOS)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing consumed by later tasks — this is an isolated bug fix found during investigation (see the spec), unrelated to the new remote-uninstall flow but touching the same functions.

- [ ] **Step 1: Fix the Windows ordering**

In `agent/service.go`, replace (currently lines 254-274, the start of `svcUninstall`):

```go
func svcUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not found", svcName)
	}
	defer s.Close()

	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline". Read while the service (and its registry Parameters) still
	// exist -- must happen before Delete below.
	serverURL, _ := readServiceParams()
	if err := notifyServerUnenroll(serverURL, ReadEncryptedSecret(), collectIdentity().AgentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}

	// Capture the installed binary path before Delete() removes the service
	// registration -- needed below to schedule the exe for delayed deletion.
	var binaryPath string
	if cfg, cfgErr := s.Config(); cfgErr == nil {
		binaryPath = cfg.BinaryPathName
	}
```

with:

```go
func svcUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not found", svcName)
	}
	defer s.Close()

	// serverURL/secret must be read while the service (and its registry
	// Parameters) still exist -- capture them now, but notify only after
	// the stop/delete below actually succeeds, so the server never learns
	// "uninstalled" before it's true (a partial failure below used to leave
	// the server thinking the endpoint was gone while the service was still
	// registered).
	serverURL, _ := readServiceParams()
	secret := ReadEncryptedSecret()
	agentID := collectIdentity().AgentID

	// Capture the installed binary path before Delete() removes the service
	// registration -- needed below to schedule the exe for delayed deletion.
	var binaryPath string
	if cfg, cfgErr := s.Config(); cfgErr == nil {
		binaryPath = cfg.BinaryPathName
	}
```

Then, replace (currently lines 291-316, the rest of the function):

```go
	if err := s.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(svcName)

	// Everything below is best-effort cleanup: a running process cannot
	// delete its own executing binary, and the tray autostart entry/window/
	// shortcut are all independently idempotent -- a missing key, window, or
	// file is already the desired end state. Only the service stop/delete
	// above can fail the uninstall.
	if binaryPath != "" {
		if err := scheduleBinaryDeleteOnReboot(binaryPath); err != nil {
			fmt.Printf("[~] Could not schedule binary for delayed deletion: %v\n", err)
		}
	}
	if err := removeTrayRunKey(); err != nil {
		fmt.Printf("[~] Could not remove tray autostart entry: %v\n", err)
	}
	closeTrayWindow()
	if err := removeTrayShortcut(); err != nil {
		fmt.Printf("[~] Could not remove tray shortcut: %v\n", err)
	}

	fmt.Printf("[+] Service %q uninstalled\n", svcName)
	return nil
}
```

with:

```go
	if err := s.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(svcName)

	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline" -- now sent only after Delete above actually succeeded.
	if err := notifyServerUnenroll(serverURL, secret, agentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}

	// Everything below is best-effort cleanup: a running process cannot
	// delete its own executing binary, and the tray autostart entry/window/
	// shortcut are all independently idempotent -- a missing key, window, or
	// file is already the desired end state. Only the service stop/delete
	// above can fail the uninstall.
	if binaryPath != "" {
		if err := scheduleBinaryDeleteOnReboot(binaryPath); err != nil {
			fmt.Printf("[~] Could not schedule binary for delayed deletion: %v\n", err)
		}
	}
	if err := removeTrayRunKey(); err != nil {
		fmt.Printf("[~] Could not remove tray autostart entry: %v\n", err)
	}
	closeTrayWindow()
	if err := removeTrayShortcut(); err != nil {
		fmt.Printf("[~] Could not remove tray shortcut: %v\n", err)
	}

	fmt.Printf("[+] Service %q uninstalled\n", svcName)
	return nil
}
```

- [ ] **Step 2: Fix the Linux ordering**

In `agent/service_linux.go`, replace (currently lines 86-102, all of `svcUninstall`):

```go
func svcUninstall() error {
	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline". Must happen before the config file removal below.
	serverURL, _ := readServiceParams()
	if err := notifyServerUnenroll(serverURL, readAgentSecret(), collectIdentity().AgentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}

	_ = exec.Command("systemctl", "stop", "bas-agent.service").Run()
	_ = exec.Command("systemctl", "disable", "bas-agent.service").Run()
	_ = os.Remove(unitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("[+] bas-agent.service removed.")
	fmt.Printf("[!] Binary and config (%s) left in place — remove manually if no longer needed.\n", configDir)
	return nil
}
```

with:

```go
func svcUninstall() error {
	// serverURL/secret must be read while the config file still exists --
	// capture them now, but notify only after the unit is actually removed
	// below, so the server never learns "uninstalled" before it's true.
	serverURL, _ := readServiceParams()
	secret := readAgentSecret()
	agentID := collectIdentity().AgentID

	_ = exec.Command("systemctl", "stop", "bas-agent.service").Run()
	_ = exec.Command("systemctl", "disable", "bas-agent.service").Run()
	_ = os.Remove(unitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("[+] bas-agent.service removed.")
	fmt.Printf("[!] Binary and config (%s) left in place — remove manually if no longer needed.\n", configDir)

	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline" -- now sent only after the unit is actually removed above.
	if err := notifyServerUnenroll(serverURL, secret, agentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}
	return nil
}
```

- [ ] **Step 3: Fix the macOS ordering**

In `agent/service_darwin.go`, replace (currently lines 70-82, all of `svcUninstall`):

```go
func svcUninstall() error {
	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline". Must happen before the plist unload/removal below.
	serverURL, _ := readServiceParams()
	if err := notifyServerUnenroll(serverURL, readAgentSecret(), collectIdentity().AgentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}

	_ = exec.Command("launchctl", "unload", darwinPlistPath).Run()
	_ = os.Remove(darwinPlistPath)
	fmt.Println("[+] bas-agent launchd daemon removed.")
	return nil
}
```

with:

```go
func svcUninstall() error {
	// serverURL/secret must be read while the config file still exists --
	// capture them now, but notify only after the plist is actually
	// unloaded/removed below, so the server never learns "uninstalled"
	// before it's true.
	serverURL, _ := readServiceParams()
	secret := readAgentSecret()
	agentID := collectIdentity().AgentID

	_ = exec.Command("launchctl", "unload", darwinPlistPath).Run()
	_ = os.Remove(darwinPlistPath)
	fmt.Println("[+] bas-agent launchd daemon removed.")

	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline" -- now sent only after the plist is actually removed above.
	if err := notifyServerUnenroll(serverURL, secret, agentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}
	return nil
}
```

- [ ] **Step 4: Run the agent test suite and cross-compile all three platforms**

Run:
```bash
cd agent
go test ./... -v
GOOS=windows GOARCH=amd64 go build ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=amd64 go build ./...
```
Expected: all pass, all three cross-compiles succeed. Pay particular attention to `uninstall_windows_test.go` (Windows-native, runs directly here) still passing — this task did not touch `uninstall_windows.go` itself, only `service.go`'s `svcUninstall`, so no existing test should need updating, but confirm.

- [ ] **Step 5: Commit**

```bash
git add agent/service.go agent/service_linux.go agent/service_darwin.go
git commit -m "$(cat <<'EOF'
fix(agent): notify server after uninstall succeeds, not before

svcUninstall (the local `agent.exe -uninstall` CLI path, all 3
platforms) previously told the server the endpoint was uninstalled
BEFORE attempting the actual service/unit/daemon removal -- found
during investigation for the new verified-uninstall feature. If the
removal step then failed, the server had already marked the agent
gone while the service was still registered on the endpoint. The
notify call now fires only after removal actually succeeds.
EOF
)"
git push
```

---

### Task 5: Frontend — Uninstall Agent / Force Remove split

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `POST /api/agents/{agentId}/uninstall` from Task 2; `a.state` values `'uninstalling'`/`'uninstalled'` and `a.uninstallError`/`a.uninstallErrorAt` (JSON fields already on every `GET /api/agents` row) from Task 1/2.
- Produces: nothing consumed elsewhere — terminal UI layer.

- [ ] **Step 1: Re-verify current line numbers**

Run:
```bash
grep -n 'function agentBucket\|stateColor = {\|remove-agent-overlay\|openRemoveAgentModal\|function submitRemoveAgent\|Remove agent</button>' orchestrator/wwwroot/index.html
```
Confirm line numbers roughly match what's cited below (last verified in this same session).

- [ ] **Step 2: Update `agentBucket` so `uninstalled` behaves like `retired`**

In `orchestrator/wwwroot/index.html`, replace (currently line 6372):

```js
  if (a.state === 'retired') return 'retired';
```

with:

```js
  if (a.state === 'retired' || a.state === 'uninstalled') return 'retired';
```

- [ ] **Step 3: Relabel the existing Remove Agent modal to Force Remove**

Replace (currently lines 3808-3828):

```html
<!-- Remove Agent Modal -->
<div id="remove-agent-overlay" class="overlay">
  <div class="modal" style="width:440px">
    <h3>Remove Agent</h3>
    <p class="sub2" id="remove-agent-target-sub"></p>

    <div style="background:rgba(218,54,51,.1);border:1px solid var(--danger-border, var(--danger));border-radius:var(--radius);padding:0.65rem 0.8rem;font-size:0.78rem;color:var(--danger);margin:0.6rem 0">
      &#9888; This removes the agent from the dashboard — it moves to the Retired filter and drops out of the default list. It does <strong>not</strong> touch the endpoint: the agent software keeps running there until someone uninstalls it locally or you separately push a Stop.
    </div>

    <label class="modal-lbl">Reason <span class="tiny muted">(required)</span></label>
    <input type="text" id="remove-agent-reason" placeholder="e.g. duplicate enrollment"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeRemoveAgentModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="remove-agent-submit-btn" class="btn btn-sm" style="color:#fff;background:var(--danger)" onclick="submitRemoveAgent()">&#128465; Remove Agent</button>
    </div>
  </div>
</div>
```

with:

```html
<!-- Uninstall Agent Modal -->
<div id="uninstall-agent-overlay" class="overlay">
  <div class="modal" style="width:440px">
    <h3>Uninstall Agent</h3>
    <p class="sub2" id="uninstall-agent-target-sub"></p>

    <div style="background:rgba(218,54,51,.1);border:1px solid var(--danger-border, var(--danger));border-radius:var(--radius);padding:0.65rem 0.8rem;font-size:0.78rem;color:var(--danger);margin:0.6rem 0">
      &#9888; This sends a real uninstall order to the endpoint. The agent stays visible as "Uninstalling…" until it confirms — it is only removed once the endpoint proves the uninstall succeeded. Requires the agent to be online right now.
    </div>

    <label class="modal-lbl">Reason <span class="tiny muted">(required)</span></label>
    <input type="text" id="uninstall-agent-reason" placeholder="e.g. decommissioning this host"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeUninstallAgentModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="uninstall-agent-submit-btn" class="btn btn-sm" style="color:#fff;background:var(--danger)" onclick="submitUninstallAgent()">&#128465; Uninstall Agent</button>
    </div>
  </div>
</div>

<!-- Force Remove Agent Modal -->
<div id="remove-agent-overlay" class="overlay">
  <div class="modal" style="width:440px">
    <h3>Force Remove Agent</h3>
    <p class="sub2" id="remove-agent-target-sub"></p>

    <div style="background:rgba(218,54,51,.1);border:1px solid var(--danger-border, var(--danger));border-radius:var(--radius);padding:0.65rem 0.8rem;font-size:0.78rem;color:var(--danger);margin:0.6rem 0">
      &#9888; This removes the agent record from Audspect. The endpoint will <strong>not</strong> receive an uninstall command. The agent software may still be installed on the device if it ever reconnects. This action should only be used for permanently unavailable or decommissioned devices.
    </div>

    <label class="modal-lbl">Reason <span class="tiny muted">(required)</span></label>
    <input type="text" id="remove-agent-reason" placeholder="e.g. device destroyed / permanently offline"
           style="width:100%;padding:0.5rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit">

    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="closeRemoveAgentModal()">Cancel</button>
      <span style="flex:1"></span>
      <button id="remove-agent-submit-btn" class="btn btn-sm" style="color:#fff;background:var(--danger)" onclick="submitRemoveAgent()">&#128465; Force Remove</button>
    </div>
  </div>
</div>
```

- [ ] **Step 4: Add the Uninstall Agent modal JS functions**

In `orchestrator/wwwroot/index.html`, find `submitRemoveAgent` (the JS function, not the modal markup just edited) and add the new functions immediately before it (right after `closeStopAgentModal`'s block and before the `// ── Remove Agent` comment, i.e. right where the `_removeAgentTargetId` section currently begins):

```js
// ── Uninstall Agent ──────────────────────────────────────────────────────
// Verified uninstall: requires a live connection, waits for the endpoint to
// confirm before the record changes -- unlike Force Remove below, this
// never silently claims an unreachable endpoint is gone.
var _uninstallAgentTargetId = null;

function openUninstallAgentModal(agentId, hostname) {
  _uninstallAgentTargetId = agentId;
  document.getElementById('uninstall-agent-target-sub').textContent = 'Target: ' + hostname;
  document.getElementById('uninstall-agent-reason').value = '';
  document.getElementById('uninstall-agent-overlay').classList.add('open');
}

function closeUninstallAgentModal() {
  document.getElementById('uninstall-agent-overlay').classList.remove('open');
}

function submitUninstallAgent() {
  if (!_uninstallAgentTargetId) return;
  var reason = document.getElementById('uninstall-agent-reason').value.trim();
  if (!reason) { showToast('Reason is required', 'err'); return; }
  if (!confirm('Uninstall this agent from the endpoint?\n\nReason: ' + reason + '\n\nThe agent must be online to confirm. Proceed?')) return;

  var btn = document.getElementById('uninstall-agent-submit-btn');
  btn.disabled = true;
  apicall('/api/agents/' + encodeURIComponent(_uninstallAgentTargetId) + '/uninstall', {
    method: 'POST',
    body: JSON.stringify({ reason: reason })
  }).then(function(res) {
    btn.disabled = false;
    if (res && res.error) { showToast(res.error, 'err'); return; }
    showToast('Uninstall dispatched', 'ok');
    closeUninstallAgentModal();
    loadAgents();
  }).catch(function(e) { btn.disabled = false; showToast(e.message, 'err'); });
}

```

- [ ] **Step 5: Update the row action menu**

In `orchestrator/wwwroot/index.html`, find the "Remove agent" menu item (currently line 6541):

```js
          (ROLE === 'admin' ?
            '<button class="row-menu-item row-menu-item-danger" onclick="closeAllRowMenus();openRemoveAgentModal(\'' + x(a.agentId) + '\',\'' + x(a.hostname || a.agentId) + '\')">&#128465; Remove agent</button>' : '') +
```

with:

```js
          (ROLE === 'admin' ?
            '<button class="row-menu-item row-menu-item-danger" onclick="closeAllRowMenus();openUninstallAgentModal(\'' + x(a.agentId) + '\',\'' + x(a.hostname || a.agentId) + '\')">&#128465; Uninstall Agent</button>' : '') +
          (ROLE === 'admin' ?
            '<button class="row-menu-item row-menu-item-danger" onclick="closeAllRowMenus();openRemoveAgentModal(\'' + x(a.agentId) + '\',\'' + x(a.hostname || a.agentId) + '\')">&#9888; Force Remove…</button>' : '') +
```

- [ ] **Step 6: Add the "Uninstalling…" status badge**

In `orchestrator/wwwroot/index.html`, find the Status column cell in `renderAgentRows()` (currently lines 6519-6523):

```js
      '<td>' +
        '<span class="sbadge s-' + x(a.status || 'idle') + '">' + x(a.status || 'idle') + '</span>' +
        (a.state && a.state !== 'active' ? ' <span class="sbadge s-' + x(a.state) + '" title="Lifecycle state">' + x(a.state) + '</span>' : '') +
        (apActiveJobs[a.agentId] ? ' <span class="sbadge s-running" title="Attack-path collection: ' + x(apActiveJobs[a.agentId].status) + '">&#128202; AP</span>' : '') +
      '</td>' +
```

Leave this exactly as-is — it already renders `a.state` as a badge whenever it's not `'active'`, so `'uninstalling'`/`'uninstalled'` automatically show up via the existing `s-<state>` CSS class convention. Add the two missing badge color rules alongside the other `.sbadge.s-*` rules (find `.sbadge.s-retired` near line 663 and add immediately after it):

```css
.sbadge.s-uninstalling { background:rgba(47,129,247,.12); color:var(--accent); border-color:rgba(47,129,247,.3); }
.sbadge.s-uninstalled  { background:rgba(100,116,139,.12); color:#94a3b8; border-color:rgba(100,116,139,.25); }
```

- [ ] **Step 7: Add the error banner and state color to the Agent Detail drawer**

In `orchestrator/wwwroot/index.html`, replace (currently line 14684):

```js
    var stateColor = {active:'var(--success)',enrolling:'var(--accent)',restricted:'var(--warning)',quarantined:'var(--danger)',retired:'var(--muted)'}[a.state] || 'var(--muted)';
```

with:

```js
    var stateColor = {active:'var(--success)',enrolling:'var(--accent)',restricted:'var(--warning)',quarantined:'var(--danger)',retired:'var(--muted)',uninstalling:'var(--accent)',uninstalled:'var(--muted)'}[a.state] || 'var(--muted)';
```

Then, find the RETIRED banner clause (currently line 14699):

```js
      (a.state === 'retired'     ? '<div style="background:rgba(100,116,139,.12);border:1px solid rgba(100,116,139,.4);border-radius:4px;padding:0.6rem 0.85rem;color:#94a3b8;font-size:0.78rem;margin-bottom:0.75rem">&#128683; Agent is RETIRED — decommissioned and blocked from running scenarios. Restore to Active to re-enable.</div>' : '') +
```

and add immediately after it:

```js
      (a.state === 'uninstalling' ? '<div style="background:rgba(47,129,247,.12);border:1px solid rgba(47,129,247,.4);border-radius:4px;padding:0.6rem 0.85rem;color:var(--accent);font-size:0.78rem;margin-bottom:0.75rem">&#8987; Uninstall in progress — waiting for the endpoint to confirm.</div>' : '') +
      (a.state === 'uninstalled'  ? '<div style="background:rgba(100,116,139,.12);border:1px solid rgba(100,116,139,.4);border-radius:4px;padding:0.6rem 0.85rem;color:#94a3b8;font-size:0.78rem;margin-bottom:0.75rem">&#10003; Agent confirmed it uninstalled itself.</div>' : '') +
      (a.uninstallError ? '<div style="background:rgba(218,54,51,.12);border:1px solid var(--danger);border-radius:4px;padding:0.6rem 0.85rem;color:var(--danger);font-size:0.78rem;margin-bottom:0.75rem">&#9888; Uninstall failed: ' + x(a.uninstallError) + (a.uninstallErrorAt ? ' (' + x(new Date(a.uninstallErrorAt).toLocaleString()) + ')' : '') + '</div>' : '') +
```

- [ ] **Step 8: Verify the syntax is still valid**

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

- [ ] **Step 9: Manual browser verification**

Same known constraint as this session's other frontend work: `wwwroot` is baked into the Docker image at build time, so a real click-through requires a full rebuild+redeploy. Defer to the same backlog as the Agent Group tree panel unless a rebuild is already planned, in which case verify:

1. Click "Uninstall Agent" on an online agent — confirm the modal, dispatch, "Uninstalling…" badge, and (once you POST a manual `uninstall-result` via curl/Postman with `{"success":true}` and the configured `X-Agent-Token`) the row settling into the Retired filter as `uninstalled`.
2. Click "Uninstall Agent" on an offline agent — confirm the 503 error surfaces clearly and nothing changes.
3. Click "Force Remove…" — confirm the new copy/title, and that it still works exactly as before (unchanged backend).
4. POST a manual `uninstall-result` with `{"success":false,"error":"test failure"}` against an agent mid-`uninstalling` — confirm the state reverts to its prior value and the red error banner appears in the Agent Detail drawer.

If any of these fail, stop and report — do not proceed to commit with a known-broken flow.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
feat(agents): split Remove Agent into Uninstall Agent + Force Remove

Uninstall Agent is now the primary row action -- dispatches a real
uninstall order and waits for the endpoint to confirm before the
record changes, with an "Uninstalling…" badge while in flight and a
red error banner in the Agent Detail drawer if it fails or times out.
Force Remove is the existing removal behavior, unchanged on the
backend, relabeled with the agreed explicit warning copy and moved to
a secondary action. agentBucket now treats the new 'uninstalled'
terminal state the same as 'retired' for list filtering.

Manual browser QA deferred -- same wwwroot-baked-into-image constraint
noted for the Agent Group tree panel earlier this session.
EOF
)"
git push
```

---

### Task 6: Per-OS manual validation (required acceptance gate)

This task has no code changes. Per the user's explicit decision, the feature is **not considered production-ready** until each platform has been validated on a real machine — this cannot be proven by `go test` or cross-compilation alone, since it depends on real Windows SCM / systemd / launchd behavior.

- [ ] **Step 1: Windows validation**

On a real (or VM) Windows install running the agent as a service:
1. Trigger Uninstall Agent from the console. Confirm: the service registration disappears from `services.msc`/`sc query bas-agent` once fully stopped, the tray icon/autostart entry is gone, the binary is scheduled for delete-on-reboot (`sc query` shows it gone, or check via `MoveFileEx` pending-operations if you have tooling for it), and the console shows `uninstalled` shortly after.
2. Confirm the eventlog source is removed.
3. Confirm a subsequent fresh `--install` on the same machine works cleanly (no "already installed" collision).

- [ ] **Step 2: Linux validation**

On a real (or VM) Linux install running the agent as a systemd service:
1. Trigger Uninstall Agent. Confirm: `systemctl status bas-agent.service` reports the unit no longer found, `/etc/systemd/system/bas-agent.service` is gone, `systemctl daemon-reload` ran (no stale unit in `systemctl list-unit-files`), and the process actually exited (not just disconnected) — check `ps`/`pgrep bas-agent`.
2. Confirm the console shows `uninstalled` shortly after.
3. Confirm the binary/config at `/usr/local/bin/bas-agent`/`/etc/bas-agent` are left in place (matches today's local-uninstall behavior — intentionally not removed).

- [ ] **Step 3: macOS validation**

On a real (or VM) macOS install running the agent as a LaunchDaemon:
1. Trigger Uninstall Agent. Confirm: `/Library/LaunchDaemons/com.audspect.bas-agent.plist` is gone, `launchctl list | grep bas-agent` shows nothing, and the process actually exited.
2. **Specifically watch for a respawn** in the few seconds around uninstall — this is the step flagged as highest-risk during design (plist removed before `bootout` is guaranteed to have unloaded the job). If the process does briefly respawn and then get killed by the subsequent `bootout`, note it, but confirm the end state is still clean (no process, no plist, console shows `uninstalled`).
3. Confirm the console shows `uninstalled` shortly after (or a reported failure if step 2 revealed a real problem — in which case, stop and report back before considering this task done).

- [ ] **Step 4: Record the outcome**

Report back per-OS pass/fail. Only once all three pass should this feature be considered complete — no commit needed for this task, it is a verification gate on the work already committed in Tasks 1-5.

---

## Self-Review Notes

- **Spec coverage:** Data model (§Data model) → Task 1. Backend API, offline-503, prior-state capture, idempotent result application, live timeout display → Task 2. Agent-side self-uninstall across all 3 platforms, the self-referential-stop risk and its resolution → Task 3. The notify-timing bug fix on the existing local path → Task 4 (kept separate from Task 3 since it's an isolated fix to *different* code paths that happen to live in the same files — a reviewer could accept Task 3's new remote flow while still questioning Task 4's fix to the old CLI flow, or vice versa). Frontend two-button split, badges, error banner, exact confirmation copy → Task 5. The user's explicit "gate release on real-machine verification" requirement → Task 6, made a first-class required task rather than a step buried inside Task 3.
- **Placeholder scan:** caught and removed a stray `var _ = time.Now` workaround from an early draft of Task 2 Step 3 — neither handler in `agent_uninstall_handlers.go` actually references `time`, so it was unnecessary. Every step now contains complete, real code with no TBD/TODO markers or add-then-delete instructions.
- **Type consistency:** `models.EffectiveUninstallError`'s signature (`state AgentState, storedError *string, requestedAt *time.Time, now time.Time`) matches exactly how Task 2's `GetAgents` calls it. `Agent.UninstallError`/`UninstallErrorAt` (Task 1) match the JSON keys (`uninstallError`/`uninstallErrorAt`) Task 5 reads. `platformSelfUninstallFn`/`reportUninstallResultFn`/`platformDisableAutoStartFn`/`platformExitAfterStopFn` (Task 3) are the same four names across the test (Step 1), the `agent.go` wiring (Step 4), and the per-platform implementations (Steps 5-7). `POST .../uninstall-result`'s body shape (`{success, error}`) is identical between Task 2's `UninstallAgentResult` handler and Task 3's `reportUninstallResult`.
