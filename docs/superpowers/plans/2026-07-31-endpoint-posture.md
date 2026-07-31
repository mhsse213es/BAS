# Endpoint Posture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fleet-wide endpoint posture summary (agent connectivity/lifecycle/binary-trust health, plus derived EPP isolation state) that doesn't exist today, and surface it on the Operational dashboard as a new widget next to the existing Threat Intelligence widget.

**Architecture:** Relocate the fleet's only existing "is this agent online" definition (`AgentOfflineAfter`/`effectiveAgentStatus`, currently unexported in `internal/api`) to `internal/models`, so `internal/analytics` can use the same definition without an import cycle. `internal/analytics.EndpointPosture` then computes fleet-health tallies from `agents` plus a derived "currently isolated" count from `action_requests` (no stored isolation flag exists — it's the latest completed isolate/release row per hostname). A thin handler exposes it at `GET /api/analytics/endpoint-posture`. The frontend adds a new `#dash-endpoint-section` widget, structurally identical to the existing `#dash-ti-section`.

**Tech Stack:** Go (`internal/models`, `internal/analytics`, `internal/api`), `*pgxpool.Pool`, vanilla JS/HTML (`orchestrator/wwwroot/index.html`).

## Global Constraints

- No new database tables, columns, or migrations — every field comes from `agents`/`action_requests` as they exist today.
- No behavior change to `GetAgents`, the Agents tab, or `internal/actions`/`action_handlers.go` — this is a read-only fleet-wide aggregation layered on top.
- The `AgentOfflineAfter`/`effectiveAgentStatus` relocation must be byte-identical behavior — same 90-second constant, same logic, only the package changes. Verified by keeping the existing `TestEffectiveAgentStatus`/`TestRunIsStale` coverage green throughout (moved, not deleted).
- New route registered `tierAny` (Viewer+), matching every other read-only analytics endpoint — and the plan explicitly adds the `rbac_matrix_test.go` entry in the same task as the route, not left to be caught by drift detection later (a real gap from Sub-project D's Task 4).
- Frontend verification: a Node syntax check that every inline `<script>` block still parses, plus DOM id-uniqueness checks — no automated test harness exists for `index.html`.
- Every task ends with a commit + `git push`.

---

### Task 1: Relocate `AgentOfflineAfter`/`EffectiveAgentStatus` to `internal/models`

**Files:**
- Modify: `orchestrator/internal/models/schema.go:222` (insert after the `AgentState` const block, before `PolicyBundle`)
- Create: `orchestrator/internal/models/agent_status_test.go`
- Modify: `orchestrator/internal/api/liveness.go` (delete the moved const/func, delegate `runIsStale` to the new location)
- Modify: `orchestrator/internal/api/liveness_test.go` (remove `TestEffectiveAgentStatus` — now lives in `internal/models`)
- Modify: `orchestrator/internal/api/handlers.go:474` (call site)

**Interfaces:**
- Consumes: nothing new.
- Produces: `const models.AgentOfflineAfter = 90 * time.Second`, `func models.EffectiveAgentStatus(stored string, lastUpdate, now time.Time) string`. Task 2 calls `models.EffectiveAgentStatus` directly.

- [x] **Step 1: Write the failing test**

Create `orchestrator/internal/models/agent_status_test.go`:

```go
package models

import (
	"testing"
	"time"
)

func TestEffectiveAgentStatus(t *testing.T) {
	now := time.Now()

	// Fresh heartbeat → keep the stored connectivity status.
	if got := EffectiveAgentStatus("scanning", now.Add(-10*time.Second), now); got != "scanning" {
		t.Errorf("fresh scanning: got %q, want scanning", got)
	}
	if got := EffectiveAgentStatus("idle", now.Add(-30*time.Second), now); got != "idle" {
		t.Errorf("fresh idle: got %q, want idle", got)
	}

	// Stale heartbeat → offline regardless of the stored status.
	if got := EffectiveAgentStatus("scanning", now.Add(-5*time.Minute), now); got != "offline" {
		t.Errorf("stale scanning: got %q, want offline", got)
	}
	if got := EffectiveAgentStatus("offline", now.Add(-5*time.Minute), now); got != "offline" {
		t.Errorf("stale offline: got %q, want offline", got)
	}
}
```

This is the exact same test body as `internal/api/liveness_test.go`'s existing `TestEffectiveAgentStatus` (`liveness_test.go:8-26`), just targeting the new exported name — proves the relocation preserves behavior exactly.

- [x] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/models/... -run TestEffectiveAgentStatus -v`
Expected: FAIL — `undefined: EffectiveAgentStatus` (compile error).

- [x] **Step 3: Add the relocated code to `internal/models/schema.go`**

In `orchestrator/internal/models/schema.go`, find:

```go
const (
	AgentStateEnrolling   AgentState = "enrolling"
	AgentStateActive      AgentState = "active"
	AgentStateRestricted  AgentState = "restricted"
	AgentStateQuarantined AgentState = "quarantined"
	AgentStateRetired     AgentState = "retired"
)
```

Immediately after it (before the `PolicyBundle` type), insert:

```go
// AgentOfflineAfter is how long after its last heartbeat an agent is considered
// offline. A dead/rebooted endpoint stops heartbeating; once last_update is older
// than this the agent shows "offline" and any run it was executing is reaped.
// Single source of truth: internal/api's read paths and background staleness
// monitor, and internal/analytics's fleet-health tallies, all use this value.
// Comfortably exceeds the heartbeat interval to avoid flapping on one missed beat.
const AgentOfflineAfter = 90 * time.Second

// EffectiveAgentStatus overrides the stored connectivity status with "offline"
// when the agent's last heartbeat is older than AgentOfflineAfter. Stored status
// only changes on heartbeat, so without this a dead agent shows its last-known
// status until the background monitor next runs. Computing it on read makes any
// consumer correct immediately and stays right even if the monitor is delayed.
// Independent of the security AgentState (active/quarantined/…).
func EffectiveAgentStatus(stored string, lastUpdate, now time.Time) string {
	if now.Sub(lastUpdate) > AgentOfflineAfter {
		return "offline"
	}
	return stored
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/models/... -run TestEffectiveAgentStatus -v`
Expected: build succeeds; test PASSES.

- [x] **Step 5: Delete the old code and delegate `internal/api` to the new location**

In `orchestrator/internal/api/liveness.go`, replace the entire file with:

```go
package api

import (
	"time"

	"github.com/audspect/bas/internal/models"
)

// runIsStale reports whether a 'running' scenario_run should be reaped: either its
// agent has gone offline (heartbeat older than models.AgentOfflineAfter — the agent died
// mid-run) or the run has exceeded the hard staleRunGuard ceiling (a wedged run on
// a still-live agent). The offline check frees a dead-agent run at dispatch time
// instead of waiting the full staleRunGuard.
func runIsStale(runStarted, agentLastUpdate, now time.Time) bool {
	if now.Sub(agentLastUpdate) > models.AgentOfflineAfter {
		return true
	}
	return now.Sub(runStarted) > staleRunGuard
}
```

In `orchestrator/internal/api/handlers.go`, find (line 474):

```go
		a.Status = effectiveAgentStatus(a.Status, a.LastUpdate, now)
```

Replace with:

```go
		a.Status = models.EffectiveAgentStatus(a.Status, a.LastUpdate, now)
```

(`internal/api/handlers.go` already imports `github.com/audspect/bas/internal/models` for `models.Agent`/`models.AgentState` — no new import needed.)

- [x] **Step 6: Remove the now-duplicate test from `internal/api`**

In `orchestrator/internal/api/liveness_test.go`, delete the `TestEffectiveAgentStatus` function (lines 8-26), keeping only `TestRunIsStale`. The file should read:

```go
package api

import (
	"testing"
	"time"
)

func TestRunIsStale(t *testing.T) {
	now := time.Now()
	recentStart := now.Add(-1 * time.Minute)

	// Agent alive (fresh heartbeat) + recent run → not stale.
	if runIsStale(recentStart, now.Add(-10*time.Second), now) {
		t.Error("alive agent + recent run must not be stale")
	}
	// Agent offline (stale heartbeat) → stale immediately, even though run is recent.
	if !runIsStale(recentStart, now.Add(-5*time.Minute), now) {
		t.Error("offline agent must make its run stale immediately")
	}
	// Agent alive but run exceeds the hard ceiling → stale (backstop).
	if !runIsStale(now.Add(-3*time.Hour), now.Add(-5*time.Second), now) {
		t.Error("run beyond staleRunGuard ceiling must be stale")
	}
}
```

- [x] **Step 7: Run the full affected-package tests to verify nothing broke**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/models/... ./internal/api/... -run "TestEffectiveAgentStatus|TestRunIsStale|TestGetAgents" -v`
Expected: build/vet clean; all listed tests PASS (this exercises the relocated function, the delegating `runIsStale`, and `GetAgents`'s call site together).

- [x] **Step 8: Commit**

```bash
git add orchestrator/internal/models/schema.go orchestrator/internal/models/agent_status_test.go orchestrator/internal/api/liveness.go orchestrator/internal/api/liveness_test.go orchestrator/internal/api/handlers.go
git commit -m "refactor(models): relocate AgentOfflineAfter/EffectiveAgentStatus from internal/api

internal/analytics needs the fleet's one definition of \"is this agent
online\" for the new EndpointPosture summary, but can't import
internal/api (would cycle -- internal/api already imports
internal/analytics). Moves the constant and function to internal/models,
already imported by both. Pure relocation: same 90s value, same logic,
same test assertions, just re-homed. internal/api's runIsStale and
GetAgents now delegate to the moved version."
git push
```

---

### Task 2: `internal/analytics.EndpointPosture`

**Files:**
- Create: `orchestrator/internal/analytics/endpoint.go`
- Test: `orchestrator/internal/analytics/endpoint_test.go`

**Interfaces:**
- Consumes: `models.EffectiveAgentStatus(stored string, lastUpdate, now time.Time) string` (Task 1).
- Produces: `type EndpointPosture struct { TotalAgents, OnlineAgents, OfflineAgents, ActiveAgents, RestrictedAgents, QuarantinedAgents, RetiredAgents, UntrustedBinaryCount, CurrentlyIsolated int }`, `func EndpointPosture(ctx context.Context, pool *pgxpool.Pool) (EndpointPosture, error)`. Task 3's handler calls this directly.

- [x] **Step 1: Write the failing tests**

Create `orchestrator/internal/analytics/endpoint_test.go`:

```go
package analytics

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func seedAgent(t *testing.T, pool *pgxpool.Pool, id, status, state string, binaryTrusted bool, lastUpdateAgo string) {
	t.Helper()
	mustExec(t, pool, `
		INSERT INTO agents (agent_id, hostname, status, state, binary_trusted, last_update)
		VALUES ($1, $2, $3, $4, $5, NOW() - $6::interval)`,
		id, id+"-host", status, state, binaryTrusted, lastUpdateAgo)
}

func TestEndpointPosture_TalliesConnectivityAndLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAgent(t, pool, "a1", "idle", "active", true, "10 seconds")
		seedAgent(t, pool, "a2", "scanning", "active", true, "5 minutes") // stale -> offline
		seedAgent(t, pool, "a3", "idle", "restricted", true, "0 seconds")
		seedAgent(t, pool, "a4", "idle", "quarantined", true, "0 seconds")
		seedAgent(t, pool, "a5", "idle", "retired", true, "0 seconds")

		got, err := EndpointPosture(context.Background(), pool)
		if err != nil {
			t.Fatalf("EndpointPosture: %v", err)
		}
		if got.TotalAgents != 5 {
			t.Errorf("TotalAgents = %d, want 5", got.TotalAgents)
		}
		if got.OnlineAgents != 4 {
			t.Errorf("OnlineAgents = %d, want 4 (a2 is stale)", got.OnlineAgents)
		}
		if got.OfflineAgents != 1 {
			t.Errorf("OfflineAgents = %d, want 1 (a2)", got.OfflineAgents)
		}
		if got.ActiveAgents != 2 {
			t.Errorf("ActiveAgents = %d, want 2 (a1, a2)", got.ActiveAgents)
		}
		if got.RestrictedAgents != 1 || got.QuarantinedAgents != 1 || got.RetiredAgents != 1 {
			t.Errorf("lifecycle tallies = restricted:%d quarantined:%d retired:%d, want 1/1/1",
				got.RestrictedAgents, got.QuarantinedAgents, got.RetiredAgents)
		}
	})
}

func TestEndpointPosture_UntrustedBinaryCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAgent(t, pool, "b1", "idle", "active", true, "0 seconds")
		seedAgent(t, pool, "b2", "idle", "active", false, "0 seconds")
		seedAgent(t, pool, "b3", "idle", "active", false, "0 seconds")

		got, err := EndpointPosture(context.Background(), pool)
		if err != nil {
			t.Fatalf("EndpointPosture: %v", err)
		}
		if got.UntrustedBinaryCount != 2 {
			t.Errorf("UntrustedBinaryCount = %d, want 2 (b2, b3)", got.UntrustedBinaryCount)
		}
	})
}

func TestEndpointPosture_CurrentlyIsolated_UsesLatestActionPerHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedAgent(t, pool, "c1", "idle", "active", true, "0 seconds")
		seedAgent(t, pool, "c2", "idle", "active", true, "0 seconds")
		seedAgent(t, pool, "c3", "idle", "active", true, "0 seconds")

		// c1: bare completed isolate -> currently isolated.
		mustExec(t, pool, `
			INSERT INTO action_requests (type, target_type, target_identifier, connector_id, status, requested_at)
			VALUES ('endpoint.isolate', 'hostname', 'c1-host', 'conn-1', 'completed', NOW() - interval '1 hour')`)

		// c2: isolate then a later completed release -> NOT currently isolated.
		mustExec(t, pool, `
			INSERT INTO action_requests (type, target_type, target_identifier, connector_id, status, requested_at)
			VALUES ('endpoint.isolate', 'hostname', 'c2-host', 'conn-1', 'completed', NOW() - interval '2 hours')`)
		mustExec(t, pool, `
			INSERT INTO action_requests (type, target_type, target_identifier, connector_id, status, requested_at)
			VALUES ('endpoint.release', 'hostname', 'c2-host', 'conn-1', 'completed', NOW() - interval '1 hour')`)

		// c3: isolate attempt FAILED -> NOT currently isolated.
		mustExec(t, pool, `
			INSERT INTO action_requests (type, target_type, target_identifier, connector_id, status, requested_at)
			VALUES ('endpoint.isolate', 'hostname', 'c3-host', 'conn-1', 'failed', NOW() - interval '1 hour')`)

		got, err := EndpointPosture(context.Background(), pool)
		if err != nil {
			t.Fatalf("EndpointPosture: %v", err)
		}
		if got.CurrentlyIsolated != 1 {
			t.Errorf("CurrentlyIsolated = %d, want 1 (only c1)", got.CurrentlyIsolated)
		}
	})
}

func TestEndpointPosture_NoAgents_ReturnsZeroSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := EndpointPosture(context.Background(), pool)
		if err != nil {
			t.Fatalf("EndpointPosture: %v", err)
		}
		if got.TotalAgents != 0 || got.CurrentlyIsolated != 0 {
			t.Errorf("got %+v, want all zero", got)
		}
	})
}
```

`sharedDB`/`mustExec` are already declared in `internal/analytics/risk_test.go` (Sub-project A) — shared across every test file in this package. `sharedDB.RunWithPool` truncates all tables between subtests (existing convention — confirmed by every prior sub-project's test files), so these tests don't interfere with each other.

- [x] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/analytics/... -run TestEndpointPosture -v`
Expected: FAIL — `undefined: EndpointPosture` (compile error).

- [x] **Step 3: Implement `EndpointPosture`**

Create `orchestrator/internal/analytics/endpoint.go`:

```go
package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
)

// EndpointPosture is the fleet-wide endpoint health summary: agent
// connectivity/lifecycle/binary-trust state plus derived EPP isolation
// state (there is no stored "currently isolated" flag -- it's computed
// from the latest completed isolate/release action_requests row per host).
type EndpointPosture struct {
	TotalAgents          int `json:"totalAgents"`
	OnlineAgents          int `json:"onlineAgents"`
	OfflineAgents         int `json:"offlineAgents"`
	ActiveAgents          int `json:"activeAgents"`
	RestrictedAgents      int `json:"restrictedAgents"`
	QuarantinedAgents     int `json:"quarantinedAgents"`
	RetiredAgents         int `json:"retiredAgents"`
	UntrustedBinaryCount  int `json:"untrustedBinaryCount"`
	CurrentlyIsolated     int `json:"currentlyIsolated"`
}

// EndpointPosture computes the fleet-wide endpoint posture summary.
func EndpointPosture(ctx context.Context, pool *pgxpool.Pool) (EndpointPosture, error) {
	rows, err := pool.Query(ctx, `SELECT status, state, binary_trusted, last_update FROM agents`)
	if err != nil {
		return EndpointPosture{}, err
	}
	defer rows.Close()

	var p EndpointPosture
	now := time.Now()
	for rows.Next() {
		var status, state string
		var binaryTrusted bool
		var lastUpdate time.Time
		if err := rows.Scan(&status, &state, &binaryTrusted, &lastUpdate); err != nil {
			return EndpointPosture{}, err
		}
		p.TotalAgents++
		if models.EffectiveAgentStatus(status, lastUpdate, now) == "offline" {
			p.OfflineAgents++
		} else {
			p.OnlineAgents++
		}
		switch models.AgentState(state) {
		case models.AgentStateActive:
			p.ActiveAgents++
		case models.AgentStateRestricted:
			p.RestrictedAgents++
		case models.AgentStateQuarantined:
			p.QuarantinedAgents++
		case models.AgentStateRetired:
			p.RetiredAgents++
		}
		if !binaryTrusted {
			p.UntrustedBinaryCount++
		}
	}
	if err := rows.Err(); err != nil {
		return EndpointPosture{}, err
	}

	err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
			SELECT DISTINCT ON (target_identifier) type
			FROM action_requests
			WHERE target_type = 'hostname'
			  AND type IN ('endpoint.isolate', 'endpoint.release')
			  AND status = 'completed'
			ORDER BY target_identifier, requested_at DESC
		) latest
		WHERE latest.type = 'endpoint.isolate'`,
	).Scan(&p.CurrentlyIsolated)
	if err != nil {
		return EndpointPosture{}, err
	}

	return p, nil
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/analytics/... -run TestEndpointPosture -v`
Expected: build succeeds; all 4 tests PASS.

- [x] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/endpoint.go orchestrator/internal/analytics/endpoint_test.go
git commit -m "feat(analytics): add EndpointPosture (fleet health + EPP isolation state)

Fills the last gap in the parent initiative's 7-category list -- no
fleet-wide agent-health or EPP-isolation summary has ever existed.
CurrentlyIsolated is derived (DISTINCT ON latest completed
isolate/release per hostname), not a stored flag -- action_requests is
an append-only event log with no persisted current-state column."
git push
```

---

### Task 3: `GET /api/analytics/endpoint-posture`

**Files:**
- Create: `orchestrator/internal/api/endpoint_posture_handlers.go`
- Modify: `orchestrator/internal/api/routes.go` (route registration)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (drift-detection entry — added proactively this time)
- Test: `orchestrator/internal/api/endpoint_posture_handler_test.go`

**Interfaces:**
- Consumes: `analytics.EndpointPosture(ctx, pool)` (Task 2), `h.db`.
- Produces: nothing new for later tasks — Task 4 calls this route directly from JS, not any Go symbol.

- [x] **Step 1: Write the failing test**

Create `orchestrator/internal/api/endpoint_posture_handler_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetEndpointPosture_EmptyFleet_ReturnsZeroSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetEndpointPosture(rec, httptest.NewRequest(http.MethodGet, "/api/analytics/endpoint-posture", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got struct {
			TotalAgents       int `json:"totalAgents"`
			CurrentlyIsolated int `json:"currentlyIsolated"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if got.TotalAgents != 0 || got.CurrentlyIsolated != 0 {
			t.Errorf("got %+v, want all zero on an empty fleet", got)
		}
	})
}
```

`sharedDB` is already declared in `internal/api`'s existing test suite (`testmain_test.go`).

- [x] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetEndpointPosture -v`
Expected: FAIL — `h.GetEndpointPosture undefined` (compile error).

- [x] **Step 3: Implement the handler**

Create `orchestrator/internal/api/endpoint_posture_handlers.go`:

```go
package api

import (
	"net/http"

	"github.com/audspect/bas/internal/analytics"
)

// GET /api/analytics/endpoint-posture — fleet-wide endpoint health: agent
// connectivity/lifecycle/binary-trust state plus current EPP isolation
// exposure. Viewer+.
func (h *Handler) GetEndpointPosture(w http.ResponseWriter, r *http.Request) {
	result, err := analytics.EndpointPosture(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
```

- [x] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/analytics/threat-intel-summary", h.GetThreatIntelSummary)
```

Replace with:

```go
		r.Get("/api/analytics/threat-intel-summary", h.GetThreatIntelSummary)

		// Endpoint Posture -- fleet-wide agent health + derived EPP isolation
		// state, for dashboard consumption. Last of the 7 analytics categories.
		r.Get("/api/analytics/endpoint-posture", h.GetEndpointPosture)
```

- [x] **Step 5: Add the RBAC matrix entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, find:

```go
	{http.MethodGet, "/api/analytics/threat-intel-summary", tierAny, ""},
```

Replace with:

```go
	{http.MethodGet, "/api/analytics/threat-intel-summary", tierAny, ""},
	{http.MethodGet, "/api/analytics/endpoint-posture", tierAny, ""},
```

This is the exact drift-detection failure Sub-project D's Task 4 caught after the fact (`TestRBACMatrix_NoDrift`) — added here up front instead.

- [x] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run "TestGetEndpointPosture|TestRBACMatrix_NoDrift" -v`
Expected: build and vet clean; both tests PASS.

- [x] **Step 7: Commit**

```bash
git add orchestrator/internal/api/endpoint_posture_handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/endpoint_posture_handler_test.go
git commit -m "feat(api): add GET /api/analytics/endpoint-posture"
git push
```

---

### Task 4: Wire the summary into a new dashboard widget

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (HTML: new `dash-endpoint-section`; JS: new `loadEndpointPostureWidget()`, call site)

**Interfaces:**
- Consumes: `GET /api/analytics/endpoint-posture` (Task 3), `apicall` (existing), `showTab` (existing, for click-through to the Agents tab), `x()` (existing HTML-escaping helper).
- Produces: `function loadEndpointPostureWidget()`, a new `#dash-endpoint-section`/`#dash-endpoint-tiles` pair.

- [x] **Step 1: Add the `#dash-endpoint-section` container**

Find (`index.html:1473-1481`):

```html
        <!-- Threat Intelligence — KEV exposure widget; hidden until data is loaded -->
        <div id="dash-ti-section" style="display:none">
          <div style="display:flex;align-items:center;justify-content:space-between;margin:1.25rem 0 0.55rem">
            <span style="font-size:0.72rem;font-weight:600;letter-spacing:0.06em;color:var(--muted);text-transform:uppercase">Threat Intelligence</span>
            <a class="tiny" style="color:var(--accent);cursor:pointer;font-weight:500" onclick="loadKEVPack()">&#9760; Create KEV Pack →</a>
          </div>
          <div class="kpi-row" id="dash-ti-tiles"></div>
          <div id="dash-ti-actors"></div>
        </div>
```

Replace with (adds a new sibling section immediately after):

```html
        <!-- Threat Intelligence — KEV exposure widget; hidden until data is loaded -->
        <div id="dash-ti-section" style="display:none">
          <div style="display:flex;align-items:center;justify-content:space-between;margin:1.25rem 0 0.55rem">
            <span style="font-size:0.72rem;font-weight:600;letter-spacing:0.06em;color:var(--muted);text-transform:uppercase">Threat Intelligence</span>
            <a class="tiny" style="color:var(--accent);cursor:pointer;font-weight:500" onclick="loadKEVPack()">&#9760; Create KEV Pack →</a>
          </div>
          <div class="kpi-row" id="dash-ti-tiles"></div>
          <div id="dash-ti-actors"></div>
        </div>

        <!-- Endpoint Posture — fleet health + EPP isolation state; hidden until data is loaded -->
        <div id="dash-endpoint-section" style="display:none">
          <div style="display:flex;align-items:center;justify-content:space-between;margin:1.25rem 0 0.55rem">
            <span style="font-size:0.72rem;font-weight:600;letter-spacing:0.06em;color:var(--muted);text-transform:uppercase">Endpoint Posture</span>
          </div>
          <div class="kpi-row" id="dash-endpoint-tiles"></div>
        </div>
```

- [x] **Step 2: Add `loadEndpointPostureWidget()`**

Find (`index.html:6887-6888`, immediately after `renderTIActors`'s closing brace):

```js
}

// loadReadinessTrends fetches and renders the per-actor readiness history table
```

Replace with:

```js
}

// loadEndpointPostureWidget fetches the fleet-wide endpoint posture summary
// and populates the dashboard's Endpoint Posture KPI tiles. Untrusted
// Binaries and Currently Isolated tiles only render when nonzero, matching
// loadKEVWidget's convention of hiding tiles that have nothing to report.
var _endpointPostureLoaded = false;
function loadEndpointPostureWidget() {
  if (_endpointPostureLoaded) return;
  apicall('/api/analytics/endpoint-posture').then(function(p) {
    if (!p || !p.totalAgents) return;
    _endpointPostureLoaded = true;
    document.getElementById('dash-endpoint-section').style.display = '';
    var tiles = document.getElementById('dash-endpoint-tiles');
    var html =
      '<div class="kpi-card stat-tile" style="cursor:pointer" onclick="showTab(\'agents\')" title="Agents currently reachable vs. past the 90s heartbeat window">' +
      '<div class="stat-top"><div><div class="kpi-label">Online / Offline</div><div class="kpi-value">' + p.onlineAgents + ' <span class="tiny muted">/ ' + p.offlineAgents + '</span></div></div>' +
      '<div class="stat-icon" style="background:rgba(35,134,54,0.10);color:var(--success)">&#9679;</div></div>' +
      '<div class="kpi-sub">' + p.totalAgents + ' total agents</div></div>' +
      '<div class="kpi-card stat-tile" style="cursor:pointer" onclick="showTab(\'agents\')" title="Agent lifecycle state breakdown">' +
      '<div class="stat-top"><div><div class="kpi-label">Lifecycle</div><div class="kpi-value">' + p.activeAgents + ' <span class="tiny muted">active</span></div></div></div>' +
      '<div class="kpi-sub">' + p.restrictedAgents + ' restricted · ' + p.quarantinedAgents + ' quarantined · ' + p.retiredAgents + ' retired</div></div>';
    if (p.untrustedBinaryCount > 0) {
      html +=
        '<div class="kpi-card stat-tile" style="cursor:pointer" onclick="showTab(\'agents\')" title="Agents whose binary hash failed trust verification">' +
        '<div class="stat-top"><div><div class="kpi-label">Untrusted Binaries</div><div class="kpi-value" style="color:var(--danger)">' + p.untrustedBinaryCount + '</div></div>' +
        '<div class="stat-icon" style="background:rgba(218,54,51,0.10);color:var(--danger)">&#9888;</div></div>' +
        '<div class="kpi-sub">binary hash failed trust verification</div></div>';
    }
    if (p.currentlyIsolated > 0) {
      html +=
        '<div class="kpi-card stat-tile" style="cursor:pointer" onclick="showTab(\'agents\')" title="Endpoints currently isolated via an EPP response action">' +
        '<div class="stat-top"><div><div class="kpi-label">Currently Isolated</div><div class="kpi-value" style="color:var(--warning)">' + p.currentlyIsolated + '</div></div>' +
        '<div class="stat-icon" style="background:rgba(210,153,34,0.10);color:var(--warning)">&#128274;</div></div>' +
        '<div class="kpi-sub">via EPP response action</div></div>';
    }
    tiles.innerHTML = html;
  }).catch(function() {});
}

// loadReadinessTrends fetches and renders the per-actor readiness history table
```

- [x] **Step 3: Call it from the dashboard load sequence**

Find (`index.html:12582-12587`):

```js
    loadRansomwareReadiness(runs);
    refreshDashboardCampaigns();
    loadComplianceScores();
    loadDashboardITSM();
    loadKEVWidget();
    loadReadinessTrends();
```

Replace with:

```js
    loadRansomwareReadiness(runs);
    refreshDashboardCampaigns();
    loadComplianceScores();
    loadDashboardITSM();
    loadKEVWidget();
    loadEndpointPostureWidget();
    loadReadinessTrends();
```

- [x] **Step 4: Verify — syntax check**

Run from the repo root:

```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
scripts.forEach((s, i) => { try { new Function(s); } catch (e) { console.error('Script block ' + i + ' failed:', e.message); process.exit(1); } });
console.log('All script blocks parse OK');
"
```

Expected: `All script blocks parse OK`.

- [x] **Step 5: Verify — id uniqueness**

Run:

```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
['dash-endpoint-section', 'dash-endpoint-tiles'].forEach(id => {
  const n = (html.match(new RegExp('id=\"' + id + '\"', 'g')) || []).length;
  console.log(id + ': ' + n);
});
"
```

Expected: `dash-endpoint-section: 1` and `dash-endpoint-tiles: 1`.

- [x] **Step 6: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): add Endpoint Posture widget

New #dash-endpoint-section, structurally identical to the existing
#dash-ti-section, fed by GET /api/analytics/endpoint-posture. Shows
online/offline and lifecycle-state counts always; Untrusted Binaries
and Currently Isolated tiles only render when nonzero. Every tile
click-throughs to the Agents tab, which already shows this data
per-agent -- no new detail view invented."
git push
```

---

### Task 5: Full regression

**Files:** none (verification only)

- [x] **Step 1: Confirm Docker is running**

Run: `docker info 2>&1 | grep -iE "server|error"`
Expected: a `Server:` block with no error. If down, start Docker Desktop and poll until ready:

```bash
timeout 180 bash -c 'until docker info >/dev/null 2>&1; do sleep 5; done' && echo "DOCKER_READY"
```

- [x] **Step 2: Run the full Go test suite**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -count=1`
Expected: `go build`/`go vet` clean, every package `ok`. If `internal/api` alone times out under full-suite load (a known artifact seen in every prior sub-project's Task 4/regression — Go's default 10-minute per-package timeout under Docker/DB resource contention, not a real failure), re-run it in isolation: `go test ./internal/api/... -count=1 -timeout 20m` and confirm it passes standalone before concluding the suite is clean.

- [x] **Step 3: Report completion**

Executes directly on `main`, no branch/worktree/PR decision needed. Confirm with the user that Sub-project E is complete — this closes out all 5 sub-projects of the Unified Analytics Layer initiative (A: Foundation, B: Dashboard Shell, C: Detection Reconciliation, D: Threat Intel Summary, E: Endpoint Posture).

---

## Execution Notes

All 5 tasks completed and pushed (`043433e`, `ceb9ee3`, `2edc5a1`, `b996a99`).

**A real bug the plan's own investigation missed:** the plan's grep for `AgentOfflineAfter`/`effectiveAgentStatus` only searched `internal/`, missing a third call site in `cmd/server/main.go`'s `runStalenessMonitor` (`api.AgentOfflineAfter`). Caught immediately by the compiler when Task 1's relocation removed the old symbol from `internal/api`. Fixed in the same commit — `cmd/server/main.go` already imported both `api` and `models`, so it was a one-line change.

**Same type/function name collision as Sub-project D:** Task 2's `EndpointPosture` (function) and its return type were both named `EndpointPosture`, the identical illegal-Go-construct mistake D made with `ThreatIntelSummary`. This is now a confirmed pattern, not a one-off — worth remembering during any future analytics-category design: **never name the summary function and its return struct the same identifier.** Fixed by renaming the type to `EndpointPostureSummary`.

**RBAC drift avoided this time:** Task 3 added the `rbac_matrix_test.go` entry proactively in the same step as the route registration (a lesson carried forward from D's Task 4, where this was only caught after the fact). `TestRBACMatrix_NoDrift` passed on the first run.

**Task 5 regression — one transient, non-systemic Docker blip:** the full suite showed `internal/pathcorrelation` failing with the "rootless Docker is not supported on Windows" container-startup error, but this time isolated to a single package rather than every DB-backed package (contrast with D's Task 4, where Docker was fully down). Re-ran `internal/pathcorrelation` alone immediately afterward — passed clean (`ok 8.654s`). Confirmed a one-off container-startup timing blip, not a systemic Docker-down state. Full suite is clean.

Sub-project E (Endpoint Posture) is complete. This closes out all 5 sub-projects of the Unified Analytics Layer initiative: A (Foundation), B (Dashboard Shell), C (Detection Reconciliation), D (Threat Intel Summary), E (Endpoint Posture).
