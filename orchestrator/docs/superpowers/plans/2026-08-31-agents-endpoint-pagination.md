# Agents Endpoint Pagination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add keyset pagination to `GET /api/agents` so the System Tree table stops shipping the entire fleet (measured at 1.08MB / ~1.74s transfer for 2,500 agents) on every load, while keeping the other 8 `/api/agents` call sites and the KPI tiles/toolbar counts working exactly as they do today.

**Architecture:** `GetAgents` grows a second, opt-in response shape — the existing bare-array response stays byte-for-byte unchanged when no `limit`/`cursor` param is passed; a new `{items, next_cursor, has_more, totals}` envelope is returned when either is present. Pagination uses a keyset (not offset) cursor on `(last_update, agent_id)` with a snapshot boundary, since `last_update` changes on every heartbeat. Only the System Tree table (`loadAgents()` and friends in `wwwroot/index.html`) is migrated to the new contract.

**Tech Stack:** Go (`pgx/v5`, `chi`), vanilla JS (no framework — this is a single large `wwwroot/index.html`), PostgreSQL.

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-31-agents-endpoint-pagination-design.md`

## Global Constraints

- The response for a call with **neither** `limit` nor `cursor` present must remain a bare JSON array, identical to today — this is what keeps the other 8 `/api/agents` consumers in `wwwroot/index.html` untouched.
- `limit` is clamped server-side to `[1, 500]`, defaulting to `100` when unset but pagination is triggered by `cursor` alone.
- Sort order is `last_update DESC, agent_id DESC` everywhere pagination applies — never introduce `OFFSET`.
- The bucket classification (`online`/`degraded`/`offline`/`retired`) must be expressed in exactly one place (`agentBucketCaseSQL`) and reused for both row filtering and totals — never duplicate the rule.
- A malformed `cursor` (bad base64 or JSON) returns `400` via the existing `jsonError` helper with `{"error": "invalid cursor"}`.
- Run `cd orchestrator && go build ./... && go vet ./... && go test ./... -p 1` before any task is considered done — `-p 1` per this session's established guidance (shared-testcontainer resource contention on this host at `-p 2`).
- This repo builds directly on `main`, no worktree — matches this session's established convention throughout.

---

### Task 1: Shared query helpers (pure refactor, no behavior change)

**Files:**
- Modify: `orchestrator/internal/api/handlers.go:677-748` (current `GetAgents`)
- Test: `orchestrator/internal/api/agent_lifecycle_test.go` (existing tests must still pass unchanged — no new test file needed for this task)

**Interfaces:**
- Produces: `agentSelectColumns` (string constant), `agentFromJoins` (string constant), `scanAgentRows(rows pgx.Rows, hub *ws.Hub, now time.Time) []models.Agent`, `groupRecursiveFilter(args []any, groupID int64) (string, []any)` — all package-level in `internal/api`, consumed by Task 3.

This task extracts the SELECT column list, the FROM/JOIN clause, the row-scanning loop, and the group recursive-CTE filter out of `GetAgents` into reusable pieces — with zero behavior change. Task 3 builds the paginated query path on top of these instead of duplicating ~35 lines of scan code and the column list a second time.

- [ ] **Step 1: Confirm the baseline passes before touching anything**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetAgents_' -v -timeout 5m`
Expected: `TestGetAgents_WSConnectedReflectsHubNotHeartbeat`, `TestGetAgents_SimsCountAggregation`, `TestGetAgents_EmptyOrderingAndNullableFields` all PASS. (Requires Docker Desktop running — these are testcontainer-backed.)

- [ ] **Step 2: Extract the shared constants and helpers**

In `orchestrator/internal/api/handlers.go`, immediately **before** the `func (h *Handler) GetAgents` line (currently line 677), add:

```go
// agentSelectColumns is the exact SELECT list shared by every GetAgents
// query path (unpaginated legacy, paginated, and nothing else needs it --
// the totals query below selects a different, narrower column set).
const agentSelectColumns = `a.agent_id, a.hostname, a.ip_address, a.os_version, a.username, a.status, a.env_label,
	        a.has_report, a.binary_hash, a.binary_trusted, a.last_update,
	        COALESCE(a.state, 'active'), COALESCE(a.policy_json::text, '{}'), a.enrolled_at,
	        COALESCE(sr.sims, 0) AS sims,
	        a.stopped_by, COALESCE(u.username, a.stopped_by), a.stopped_at, a.stop_reason,
	        a.group_id, g.name, a.uninstall_error, a.uninstall_error_at, a.uninstall_requested_at`

// agentFromJoins is the FROM/JOIN clause shared by every GetAgents query
// that selects agentSelectColumns above.
const agentFromJoins = `FROM agents a
	 LEFT JOIN users u ON u.id = a.stopped_by
	 LEFT JOIN agent_groups g ON g.id = a.group_id
	 LEFT JOIN (SELECT agent_id, COUNT(*) AS sims FROM scenario_runs GROUP BY agent_id) sr ON sr.agent_id = a.agent_id`

// scanAgentRows scans rows produced by a query selecting agentSelectColumns
// (in that exact order) into []models.Agent, applying the same
// derived-field logic GetAgents has always applied: effective (heartbeat-
// aware) status, live WSConnected from the hub, and effective uninstall
// error. Rows that fail to scan are skipped (matches prior GetAgents
// behavior). Does not close rows -- the caller owns that.
func scanAgentRows(rows pgx.Rows, hub *ws.Hub, now time.Time) []models.Agent {
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
		// The hub's live connection map is the ground truth for whether a
		// dispatch could actually reach this agent right now -- independent of
		// heartbeat freshness above. See models.Agent.WSConnected's doc comment.
		a.WSConnected = hub.IsAgentConnected(a.AgentID)
		a.UninstallError = models.EffectiveUninstallError(a.State, a.UninstallError, uninstallRequestedAt, now)
		var p models.PolicyBundle
		if err := json.Unmarshal([]byte(policyRaw), &p); err == nil {
			a.Policy = &p
		}
		agents = append(agents, a)
	}
	return agents
}

// groupRecursiveFilter returns the "a.group_id IN (...)" SQL fragment that
// selects groupID plus every descendant group (so filtering to a parent
// group like "Finance" also surfaces agents in child groups like
// "Servers"/"Workstations"), using the next available placeholder position
// in args, and returns args with groupID appended. Shared by every query
// that needs group scoping (the row-list query and the totals query in
// Task 3) so they can never drift out of sync with each other.
func groupRecursiveFilter(args []any, groupID int64) (string, []any) {
	args = append(args, groupID)
	frag := `a.group_id IN (
		WITH RECURSIVE descendants(id) AS (
			SELECT id FROM agent_groups WHERE id = $` + strconv.Itoa(len(args)) + `
			UNION ALL
			SELECT gr.id FROM agent_groups gr JOIN descendants d ON gr.parent_id = d.id
		)
		SELECT id FROM descendants
	)`
	return frag, args
}
```

- [ ] **Step 3: Rewrite `GetAgents` to use the extracted helpers**

Replace the full body of `GetAgents` (currently `orchestrator/internal/api/handlers.go:677-748`, from `func (h *Handler) GetAgents` through its closing `}`) with:

```go
func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	query := "SELECT " + agentSelectColumns + " " + agentFromJoins
	var args []any
	if groupIDParam := r.URL.Query().Get("groupId"); groupIDParam != "" {
		groupID, err := strconv.ParseInt(groupIDParam, 10, 64)
		if err != nil {
			jsonError(w, "invalid groupId", http.StatusBadRequest)
			return
		}
		var frag string
		frag, args = groupRecursiveFilter(args, groupID)
		query += " WHERE " + frag
	}
	query += " ORDER BY a.last_update DESC"

	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	agents := scanAgentRows(rows, h.hub, time.Now())
	if agents == nil {
		agents = []models.Agent{}
	}
	respond(w, agents)
}
```

- [ ] **Step 4: Verify the refactor changed nothing observable**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run 'TestGetAgents_' -v -timeout 5m`
Expected: same three tests from Step 1 PASS, unchanged. If any fails, the refactor introduced a behavior difference — fix it before proceeding; do not move to Task 2 with a red test here.

- [ ] **Step 5: Commit**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud"
git add orchestrator/internal/api/handlers.go
git commit -m "refactor: extract GetAgents' query/scan logic into shared helpers

Pure refactor, no behavior change -- pulls the SELECT column list,
FROM/JOIN clause, row-scan loop, and group recursive-CTE filter out of
GetAgents into package-level pieces (agentSelectColumns,
agentFromJoins, scanAgentRows, groupRecursiveFilter). Prerequisite for
adding a paginated query path without duplicating ~35 lines of scan
code and the column list a second time.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
git push
```

---

### Task 2: Cursor codec and bucket SQL constant

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (add near the Task 1 additions)
- Test: `orchestrator/internal/api/agents_pagination_test.go` (new file)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `type agentCursor struct { Snapshot time.Time; LastUpdate time.Time; AgentID string }` (JSON tags: `snapshot`, `last_update`, `agent_id`), `encodeAgentCursor(c agentCursor) string`, `decodeAgentCursor(s string) (agentCursor, error)`, `const agentBucketCaseSQL string` — all consumed by Task 3.

This is a pure-function task (no DB needed) — easy to TDD in isolation before wiring it into the handler.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/api/agents_pagination_test.go`:

```go
package api

import (
	"testing"
	"time"
)

func TestAgentCursor_EncodeDecodeRoundTrip(t *testing.T) {
	original := agentCursor{
		Snapshot:   time.Date(2026, 8, 31, 17, 0, 0, 123000000, time.UTC),
		LastUpdate: time.Date(2026, 8, 31, 16, 59, 58, 1000000, time.UTC),
		AgentID:    "loadgen-000042",
	}
	encoded := encodeAgentCursor(original)
	if encoded == "" {
		t.Fatal("encodeAgentCursor returned empty string")
	}
	decoded, err := decodeAgentCursor(encoded)
	if err != nil {
		t.Fatalf("decodeAgentCursor: %v", err)
	}
	if !decoded.Snapshot.Equal(original.Snapshot) {
		t.Errorf("Snapshot = %v, want %v", decoded.Snapshot, original.Snapshot)
	}
	if !decoded.LastUpdate.Equal(original.LastUpdate) {
		t.Errorf("LastUpdate = %v, want %v", decoded.LastUpdate, original.LastUpdate)
	}
	if decoded.AgentID != original.AgentID {
		t.Errorf("AgentID = %q, want %q", decoded.AgentID, original.AgentID)
	}
}

func TestDecodeAgentCursor_RejectsGarbage(t *testing.T) {
	if _, err := decodeAgentCursor("not-valid-base64!!!"); err == nil {
		t.Fatal("expected an error decoding garbage input, got nil")
	}
	// Valid base64, but not valid JSON underneath.
	if _, err := decodeAgentCursor("bm90LWpzb24="); err == nil {
		t.Fatal("expected an error decoding valid-base64-but-not-JSON input, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestAgentCursor_EncodeDecodeRoundTrip|TestDecodeAgentCursor_RejectsGarbage' -v`
Expected: FAIL — `agentCursor`/`encodeAgentCursor`/`decodeAgentCursor` are not defined.

- [ ] **Step 3: Implement the cursor codec and bucket constant**

In `orchestrator/internal/api/handlers.go`, add near the Task 1 additions (after `groupRecursiveFilter`):

```go
// agentCursor is the decoded form of the opaque "cursor" query param a
// paginated GetAgents response hands back in next_cursor. Snapshot is
// captured once, on the first page of a traversal, and carried forward
// unchanged on every subsequent page -- see the design spec's "Keyset
// pagination" section for why (last_update changes on every heartbeat, so
// a fixed snapshot boundary is what prevents skip/duplicate rows across
// pages of a single traversal).
type agentCursor struct {
	Snapshot   time.Time `json:"snapshot"`
	LastUpdate time.Time `json:"last_update"`
	AgentID    string    `json:"agent_id"`
}

func encodeAgentCursor(c agentCursor) string {
	b, _ := json.Marshal(c)
	return base64.URLEncoding.EncodeToString(b)
}

func decodeAgentCursor(s string) (agentCursor, error) {
	var c agentCursor
	raw, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	return c, nil
}

// agentBucketCaseSQL classifies an agent row into the same bucket
// wwwroot/index.html's agentBucket() computes client-side (retired /
// offline / degraded / online), reusing models.AgentOfflineAfter's 90s
// staleness threshold. Defined once and reused by both the paginated
// row-list query's optional bucket filter and the totals aggregate query
// (Task 3) so the two can never drift out of sync with each other or with
// the frontend's own agentBucket().
const agentBucketCaseSQL = `CASE
		WHEN COALESCE(a.state,'active') IN ('retired','uninstalled') THEN 'retired'
		WHEN (NOW() - a.last_update) > INTERVAL '90 seconds' THEN 'offline'
		WHEN COALESCE(a.state,'active') != 'active' THEN 'degraded'
		ELSE 'online'
	END`
```

Add `"encoding/base64"` to the import block at the top of `handlers.go` (alongside the existing `"encoding/json"`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestAgentCursor_EncodeDecodeRoundTrip|TestDecodeAgentCursor_RejectsGarbage' -v`
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud"
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/agents_pagination_test.go
git commit -m "feat: add agent cursor codec and bucket classification SQL

Pure-function prerequisites for GetAgents pagination (Task 3): an
opaque base64-JSON cursor carrying {snapshot, last_update, agent_id},
and a single reusable SQL CASE expression classifying an agent row
into online/degraded/offline/retired -- mirrors wwwroot/index.html's
agentBucket() and models.AgentOfflineAfter's 90s threshold, defined
once so the row-filter and totals-aggregate uses (both in Task 3)
can't drift apart.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
git push
```

---

### Task 3: Paginated query path in GetAgents

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`GetAgents`, as left by Task 1)
- Test: `orchestrator/internal/api/agents_pagination_test.go` (extends Task 2's file)

**Interfaces:**
- Consumes: `agentSelectColumns`, `agentFromJoins`, `scanAgentRows`, `groupRecursiveFilter` (Task 1); `agentCursor`, `encodeAgentCursor`, `decodeAgentCursor`, `agentBucketCaseSQL` (Task 2).
- Produces: `type AgentTotals struct { Online, Degraded, Offline, Retired int }` (JSON tags lowercase, matching the field names), `type AgentsPage struct { Items []models.Agent; NextCursor string \`json:"next_cursor,omitempty"\`; HasMore bool \`json:"has_more"\`; Totals AgentTotals }` — the response shape the frontend (Task 4) decodes.

This is the task that actually changes `GetAgents`' behavior. Write every test below **before** touching the handler — the snapshot-boundary test in particular is what proves the design decision (keyset + snapshot, not plain offset) was necessary, not just theoretically nice.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/agents_pagination_test.go`:

```go
func seedAgentWithLastUpdate(t *testing.T, pool *pgxpool.Pool, agentID string, lastUpdate time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, last_update) VALUES ($1, $2, $3)`,
		agentID, "h-"+agentID, lastUpdate); err != nil {
		t.Fatalf("seed agent %s: %v", agentID, err)
	}
}

func TestGetAgents_Unpaginated_StillReturnsBareArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		seedActiveAgent(t, pool, "agent-plain", "Windows")

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		// Must decode as a bare array -- decoding into a map/object would fail
		// if the handler ever started returning the paginated envelope here.
		var agents []models.Agent
		if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
			t.Fatalf("response is not a bare array (pagination leaked into the no-params path?): %v", err)
		}
		if len(agents) != 1 || agents[0].AgentID != "agent-plain" {
			t.Fatalf("got %+v, want exactly [agent-plain]", agents)
		}
	})
}

func TestGetAgents_Paginated_TraversesAllPagesWithoutSkipOrDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		base := time.Now().Add(-time.Hour)
		for i := 0; i < 5; i++ {
			seedAgentWithLastUpdate(t, pool, fmt.Sprintf("agent-%02d", i), base.Add(time.Duration(i)*time.Second))
		}

		seen := map[string]bool{}
		cursor := ""
		pages := 0
		for {
			url := "/api/agents?limit=2"
			if cursor != "" {
				url += "&cursor=" + cursor
			}
			rec := httptest.NewRecorder()
			h.GetAgents(rec, httptest.NewRequest(http.MethodGet, url, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("page %d: status = %d, body = %s", pages, rec.Code, rec.Body.String())
			}
			var page AgentsPage
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatalf("page %d: decode: %v", pages, err)
			}
			for _, a := range page.Items {
				if seen[a.AgentID] {
					t.Fatalf("agent %s returned on more than one page", a.AgentID)
				}
				seen[a.AgentID] = true
			}
			pages++
			if !page.HasMore {
				break
			}
			if page.NextCursor == "" {
				t.Fatal("has_more=true but next_cursor is empty")
			}
			cursor = page.NextCursor
			if pages > 10 {
				t.Fatal("pagination did not terminate after 10 pages")
			}
		}
		if len(seen) != 5 {
			t.Fatalf("saw %d distinct agents across all pages, want 5: %v", len(seen), seen)
		}
		if pages != 3 { // 2 + 2 + 1
			t.Fatalf("took %d pages to see all 5 agents at limit=2, want 3", pages)
		}
	})
}

func TestGetAgents_Paginated_SnapshotBoundaryHoldsUnderConcurrentHeartbeat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		base := time.Now().Add(-time.Hour)
		for i := 0; i < 4; i++ {
			seedAgentWithLastUpdate(t, pool, fmt.Sprintf("agent-%02d", i), base.Add(time.Duration(i)*time.Second))
		}

		// Page 1.
		rec1 := httptest.NewRecorder()
		h.GetAgents(rec1, httptest.NewRequest(http.MethodGet, "/api/agents?limit=2", nil))
		var page1 AgentsPage
		if err := json.Unmarshal(rec1.Body.Bytes(), &page1); err != nil {
			t.Fatalf("page 1 decode: %v", err)
		}
		if !page1.HasMore {
			t.Fatal("expected has_more=true on page 1")
		}

		// Simulate a heartbeat: agent-00 (which already appeared on page 1,
		// since the sort is last_update DESC and it had the OLDEST
		// last_update -- wait, it's actually agent-03 that sorts first
		// (newest). Bump agent-00's last_update to "now", which would move
		// it to the very front of the sort order under a naive re-query.
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET last_update = NOW() WHERE agent_id = 'agent-00'`); err != nil {
			t.Fatalf("simulate heartbeat: %v", err)
		}

		// Page 2, using page 1's cursor (which carries page 1's snapshot).
		rec2 := httptest.NewRecorder()
		h.GetAgents(rec2, httptest.NewRequest(http.MethodGet, "/api/agents?limit=2&cursor="+page1.NextCursor, nil))
		var page2 AgentsPage
		if err := json.Unmarshal(rec2.Body.Bytes(), &page2); err != nil {
			t.Fatalf("page 2 decode: %v", err)
		}

		seen := map[string]bool{}
		for _, a := range page1.Items {
			seen[a.AgentID] = true
		}
		for _, a := range page2.Items {
			if seen[a.AgentID] {
				t.Fatalf("agent %s appeared on both page 1 and page 2 -- the heartbeat during traversal caused a duplicate, snapshot boundary did not hold", a.AgentID)
			}
			seen[a.AgentID] = true
		}
		if len(seen) != 4 {
			t.Fatalf("saw %d distinct agents across 2 pages, want all 4 despite the mid-traversal heartbeat: %v", len(seen), seen)
		}
	})
}

func TestGetAgents_Paginated_TotalsMatchSeededBuckets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		now := time.Now()
		seedAgentWithLastUpdate(t, pool, "agent-online", now)
		seedAgentWithLastUpdate(t, pool, "agent-offline", now.Add(-5*time.Minute)) // >90s stale
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, last_update, state) VALUES ('agent-degraded','h', $1, 'quarantined')`, now); err != nil {
			t.Fatalf("seed degraded: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, last_update, state) VALUES ('agent-retired','h', $1, 'retired')`, now); err != nil {
			t.Fatalf("seed retired: %v", err)
		}

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents?limit=100", nil))
		var page AgentsPage
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode: %v", err)
		}
		want := AgentTotals{Online: 1, Degraded: 1, Offline: 1, Retired: 1}
		if page.Totals != want {
			t.Errorf("Totals = %+v, want %+v", page.Totals, want)
		}
	})
}

func TestGetAgents_Paginated_BucketFilterScopesRowList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		now := time.Now()
		seedAgentWithLastUpdate(t, pool, "agent-online", now)
		seedAgentWithLastUpdate(t, pool, "agent-offline", now.Add(-5*time.Minute))

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents?limit=100&bucket=offline", nil))
		var page AgentsPage
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(page.Items) != 1 || page.Items[0].AgentID != "agent-offline" {
			t.Fatalf("got %+v, want exactly [agent-offline]", page.Items)
		}
	})
}

func TestGetAgents_Paginated_SearchMatchesHostnameAgentIDAndGroupName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		seedActiveAgent(t, pool, "special-agent-id", "Windows")
		seedActiveAgent(t, pool, "other-agent", "Linux")
		seedAgentGroup(t, pool, "Finance-Group", "other-agent")

		cases := []struct {
			q    string
			want string
		}{
			{"special-agent", "special-agent-id"}, // matches agent_id
			{"Finance", "other-agent"},             // matches group name
		}
		for _, c := range cases {
			rec := httptest.NewRecorder()
			h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents?limit=100&q="+c.q, nil))
			var page AgentsPage
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatalf("q=%s: decode: %v", c.q, err)
			}
			if len(page.Items) != 1 || page.Items[0].AgentID != c.want {
				t.Errorf("q=%s: got %+v, want exactly [%s]", c.q, page.Items, c.want)
			}
		}
	})
}

func TestGetAgents_InvalidCursor_Returns400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents?cursor=not-a-valid-cursor!!!", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}
```

Add `"fmt"` to this test file's imports if not already present via the package (it's already imported in `handlers.go` but this is a separate file — check `agent_lifecycle_test.go`'s import block and add matching imports: `"context"`, `"encoding/json"`, `"fmt"`, `"net/http"`, `"net/http/httptest"`, `"testing"`, `"time"`, plus `"github.com/audspect/bas/internal/models"`, `"github.com/audspect/bas/internal/ws"`, `"github.com/jackc/pgx/v5/pgxpool"`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestGetAgents_(Unpaginated_StillReturnsBareArray|Paginated_|InvalidCursor_)' -v -timeout 5m`
Expected: FAIL to compile — `AgentsPage`/`AgentTotals` are not defined, and the paginated behavior doesn't exist yet.

- [ ] **Step 3: Implement the paginated path**

Add the response types near the Task 2 additions in `handlers.go`:

```go
// AgentTotals is the fleet-wide (or group-scoped) bucket count returned
// alongside a paginated GetAgents page -- independent of whichever page or
// filter is currently loaded client-side, so the KPI tiles stay accurate
// even though the row list itself is paginated.
type AgentTotals struct {
	Online   int `json:"online"`
	Degraded int `json:"degraded"`
	Offline  int `json:"offline"`
	Retired  int `json:"retired"`
}

// AgentsPage is GetAgents' response envelope when the caller triggers
// pagination (limit or cursor present). With neither present, GetAgents
// returns a bare []models.Agent instead -- see GetAgents' doc comment.
type AgentsPage struct {
	Items      []models.Agent `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
	HasMore    bool           `json:"has_more"`
	Totals     AgentTotals    `json:"totals"`
}
```

Replace `GetAgents` (as left by Task 1) with:

```go
// GetAgents lists agents. With neither "limit" nor "cursor" in the query
// string it returns the full fleet as a bare JSON array (the long-standing
// contract every other /api/agents caller in wwwroot/index.html depends
// on). With either present, it switches to keyset pagination and returns
// an AgentsPage envelope instead -- see
// docs/superpowers/specs/2026-08-31-agents-endpoint-pagination-design.md
// for why (last_update changes on every heartbeat, so plain OFFSET would
// skip/duplicate rows across pages of one traversal).
func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	limitParam := qs.Get("limit")
	cursorParam := qs.Get("cursor")
	if limitParam == "" && cursorParam == "" {
		h.getAgentsUnpaginated(w, r)
		return
	}
	h.getAgentsPaginated(w, r, limitParam, cursorParam)
}

func (h *Handler) getAgentsUnpaginated(w http.ResponseWriter, r *http.Request) {
	query := "SELECT " + agentSelectColumns + " " + agentFromJoins
	var args []any
	if groupIDParam := r.URL.Query().Get("groupId"); groupIDParam != "" {
		groupID, err := strconv.ParseInt(groupIDParam, 10, 64)
		if err != nil {
			jsonError(w, "invalid groupId", http.StatusBadRequest)
			return
		}
		var frag string
		frag, args = groupRecursiveFilter(args, groupID)
		query += " WHERE " + frag
	}
	query += " ORDER BY a.last_update DESC"

	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	agents := scanAgentRows(rows, h.hub, time.Now())
	if agents == nil {
		agents = []models.Agent{}
	}
	respond(w, agents)
}

func (h *Handler) getAgentsPaginated(w http.ResponseWriter, r *http.Request, limitParam, cursorParam string) {
	qs := r.URL.Query()

	limit := 100
	if limitParam != "" {
		n, err := strconv.Atoi(limitParam)
		if err != nil || n < 1 {
			jsonError(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = n
	}
	if limit > 500 {
		limit = 500
	}

	snapshot := time.Now()
	var cursor agentCursor
	if cursorParam != "" {
		c, err := decodeAgentCursor(cursorParam)
		if err != nil {
			jsonError(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		cursor = c
		snapshot = cursor.Snapshot
	}

	var hasGroup bool
	var groupID int64
	if groupIDParam := qs.Get("groupId"); groupIDParam != "" {
		id, err := strconv.ParseInt(groupIDParam, 10, 64)
		if err != nil {
			jsonError(w, "invalid groupId", http.StatusBadRequest)
			return
		}
		groupID, hasGroup = id, true
	}

	// Row-list query.
	var args []any
	args = append(args, snapshot)
	where := []string{"a.last_update <= $" + strconv.Itoa(len(args))}

	if hasGroup {
		var frag string
		frag, args = groupRecursiveFilter(args, groupID)
		where = append(where, frag)
	}
	if cursorParam != "" {
		args = append(args, cursor.LastUpdate, cursor.AgentID)
		where = append(where, fmt.Sprintf("(a.last_update, a.agent_id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	if qParam := qs.Get("q"); qParam != "" {
		args = append(args, "%"+qParam+"%")
		n := len(args)
		where = append(where, fmt.Sprintf(
			"(a.hostname ILIKE $%d OR a.agent_id ILIKE $%d OR a.ip_address ILIKE $%d OR g.name ILIKE $%d)",
			n, n, n, n))
	}
	if bucketParam := qs.Get("bucket"); bucketParam != "" && bucketParam != "all" {
		args = append(args, bucketParam)
		where = append(where, agentBucketCaseSQL+" = $"+strconv.Itoa(len(args)))
	}
	args = append(args, limit+1)

	query := "SELECT " + agentSelectColumns + " " + agentFromJoins +
		" WHERE " + strings.Join(where, " AND ") +
		" ORDER BY a.last_update DESC, a.agent_id DESC" +
		" LIMIT $" + strconv.Itoa(len(args))

	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	agents := scanAgentRows(rows, h.hub, time.Now())
	rows.Close()

	hasMore := len(agents) > limit
	if hasMore {
		agents = agents[:limit]
	}
	if agents == nil {
		agents = []models.Agent{}
	}

	var nextCursor string
	if hasMore {
		last := agents[len(agents)-1]
		nextCursor = encodeAgentCursor(agentCursor{
			Snapshot:   snapshot,
			LastUpdate: last.LastUpdate,
			AgentID:    last.AgentID,
		})
	}

	// Totals query -- narrower, group-scoped only (not q/bucket-scoped, so
	// the KPI tiles always reflect the true fleet/group-wide counts
	// regardless of whatever filter is currently narrowing the row list --
	// matches today's behavior, where the tiles have never been
	// search-scoped either).
	var totalsArgs []any
	totalsQuery := "SELECT " + agentBucketCaseSQL + " AS bucket, COUNT(*) FROM agents a"
	if hasGroup {
		var frag string
		frag, totalsArgs = groupRecursiveFilter(totalsArgs, groupID)
		totalsQuery += " WHERE " + frag
	}
	totalsQuery += " GROUP BY bucket"

	trows, err := h.db.Query(r.Context(), totalsQuery, totalsArgs...)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var totals AgentTotals
	for trows.Next() {
		var bucket string
		var count int
		if err := trows.Scan(&bucket, &count); err != nil {
			continue
		}
		switch bucket {
		case "online":
			totals.Online = count
		case "degraded":
			totals.Degraded = count
		case "offline":
			totals.Offline = count
		case "retired":
			totals.Retired = count
		}
	}
	trows.Close()

	respond(w, AgentsPage{
		Items:      agents,
		NextCursor: nextCursor,
		HasMore:    hasMore,
		Totals:     totals,
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./internal/api/... -run 'TestGetAgents_' -v -timeout 5m`
Expected: every `TestGetAgents_*` test PASSES, including all the ones from this task and the pre-existing ones from before this plan.

- [ ] **Step 5: Run the full backend suite**

Run: `cd orchestrator && go test ./... -p 1 -timeout 20m`
Expected: PASS across every package — confirms nothing outside `internal/api` broke (e.g. anything importing `models.Agent` or calling `GetAgents` indirectly).

- [ ] **Step 6: Commit**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud"
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/agents_pagination_test.go
git commit -m "feat: add keyset pagination to GetAgents

Opt-in via limit/cursor query params -- with neither present, returns
the same bare array as always (verified by regression test, keeps the
other 8 /api/agents call sites in wwwroot/index.html untouched).
Paginated path uses (last_update, agent_id) keyset ordering with a
snapshot boundary carried in the cursor, so a heartbeat mid-traversal
can't skip or duplicate rows across pages (proven by
TestGetAgents_Paginated_SnapshotBoundaryHoldsUnderConcurrentHeartbeat).
Adds q= (hostname/agent_id/ip/group substring search) and bucket=
(online/degraded/offline/retired) filters, both server-side now, plus
a totals field so KPI tiles stay fleet-wide-accurate under pagination.

This is the fix for the real remaining bottleneck found in today's
load testing: with the correlated-subquery fix (9a61a64) alone, a
2500-agent unpaginated response still cost ~1.08MB / ~1.74s transfer.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
git push
```

---

### Task 4: Frontend — migrate the System Tree table to paginated fetching

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (multiple functions: `loadAgents` at ~line 8123, `renderAgentTiles` at ~line 8130, `renderAgentToolbar` at ~line 8144, `setAgentFilter` at ~line 8154, `renderAgentRows` at ~line 8155, the `agent-search` input at ~line 1781, module-level `var agents`/`var AGENT_FILTER` near lines 5073/7932, and the table markup around lines 1796-1805 to add a "Load more" control)

**Interfaces:**
- Consumes: `GetAgents`' paginated envelope from Task 3 (`{items, next_cursor, has_more, totals}`), fields exactly as Task 3 defines them (`AgentsPage`/`AgentTotals` JSON tags).

This task only touches the System Tree view. Every other `/api/agents` call site in this file is untouched (verify with the grep in Step 6 below).

- [ ] **Step 1: Add new module-level state**

Near `var agents = [];` (currently `wwwroot/index.html:5073`), add immediately after it:

```javascript
var agents   = [];
var agentsNextCursor = '';
var agentsHasMore = false;
var agentTotals = { online: 0, degraded: 0, offline: 0, retired: 0 };
var agentSearchDebounceTimer = null;
```

- [ ] **Step 2: Rewrite `loadAgents()` and add `loadMoreAgents()`**

Replace `loadAgents()` (currently `wwwroot/index.html:8123-8129`):

```javascript
function loadAgents() {
  var url = '/api/agents?limit=100' + (activeAgentGroupId !== null ? '&groupId=' + activeAgentGroupId : '');
  var searchEl = document.getElementById('agent-search');
  var q = searchEl ? searchEl.value.trim() : '';
  if (q) url += '&q=' + encodeURIComponent(q);
  if (AGENT_FILTER !== 'all') url += '&bucket=' + encodeURIComponent(AGENT_FILTER);
  apicall(url).then(function(page) {
    agents = (page && page.items) || [];
    agentsNextCursor = (page && page.next_cursor) || '';
    agentsHasMore = !!(page && page.has_more);
    agentTotals = (page && page.totals) || { online: 0, degraded: 0, offline: 0, retired: 0 };
    document.getElementById('agent-cnt').textContent = agentTotals.online + agentTotals.degraded + agentTotals.offline;
    renderAgentTiles(); renderAgentToolbar(); renderAgentRows();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
function loadMoreAgents() {
  if (!agentsHasMore || !agentsNextCursor) return;
  var url = '/api/agents?limit=100&cursor=' + encodeURIComponent(agentsNextCursor) +
    (activeAgentGroupId !== null ? '&groupId=' + activeAgentGroupId : '');
  var searchEl = document.getElementById('agent-search');
  var q = searchEl ? searchEl.value.trim() : '';
  if (q) url += '&q=' + encodeURIComponent(q);
  if (AGENT_FILTER !== 'all') url += '&bucket=' + encodeURIComponent(AGENT_FILTER);
  apicall(url).then(function(page) {
    agents = agents.concat((page && page.items) || []);
    agentsNextCursor = (page && page.next_cursor) || '';
    agentsHasMore = !!(page && page.has_more);
    // totals intentionally NOT updated here -- they were already
    // fleet-wide-accurate from the first page's response, and appending
    // more rows to `agents` doesn't change the true totals.
    renderAgentRows();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
function onAgentSearchInput() {
  clearTimeout(agentSearchDebounceTimer);
  agentSearchDebounceTimer = setTimeout(loadAgents, 300);
}
```

- [ ] **Step 3: Rewrite `renderAgentTiles()` and the toolbar counts**

Replace `renderAgentTiles()` (currently `wwwroot/index.html:8130-8143`):

```javascript
function renderAgentTiles() {
  var b = agentTotals;
  var tile = function(lbl, val, col) {
    return '<div class="kpi-card stat-tile"><div class="stat-top"><div><div class="kpi-label">' + lbl +
      '</div><div class="kpi-value" style="color:' + col + '">' + val + '</div></div></div></div>';
  };
  var el = document.getElementById('agent-tiles');
  if (el) el.innerHTML =
    tile('Total agents', b.online + b.degraded + b.offline, 'var(--text)') +
    tile('Online', b.online, b.online ? 'var(--success)' : 'var(--muted)') +
    tile('Degraded', b.degraded, b.degraded ? 'var(--warning)' : 'var(--muted)') +
    tile('Offline', b.offline, b.offline ? 'var(--danger)' : 'var(--muted)');
}
```

In `renderAgentToolbar()` (currently `wwwroot/index.html:8144-8153`), replace the `c` count function:

```javascript
function renderAgentToolbar() {
  var c = function(k) {
    if (k === 'all') return agentTotals.online + agentTotals.degraded + agentTotals.offline;
    return agentTotals[k] || 0;
  };
  var el = document.getElementById('agent-toolbar');
  if (el) el.innerHTML = '<div class="cov-seg">' +
    [['all', 'All'], ['online', 'Online'], ['degraded', 'Degraded'], ['offline', 'Offline'], ['retired', 'Retired']]
      .map(function(o) { return '<button class="' + (AGENT_FILTER === o[0] ? 'on' : '') + '" onclick="setAgentFilter(\'' + o[0] + '\')">' + o[1] + ' <span style="opacity:.6">' + c(o[0]) + '</span></button>'; }).join('') + '</div>';
}
```

(Note: the button labels/order are unchanged — only the count source changed from `agents.filter(...)` to `agentTotals`.)

- [ ] **Step 4: Update `setAgentFilter` and simplify `renderAgentRows()`**

Replace `setAgentFilter` (currently `wwwroot/index.html:8154`):

```javascript
function setAgentFilter(v) { AGENT_FILTER = v; loadAgents(); }
```

Replace the filtering block at the top of `renderAgentRows()` (currently `wwwroot/index.html:8156-8170` — the `agentBucket`/search filtering, up to and including the line building `var tbody = document.getElementById('agents-body');`) with:

```javascript
function renderAgentRows() {
  var list = agents;
  var searchEl = document.getElementById('agent-search');
  var q = searchEl ? searchEl.value.trim() : '';
  var tbody = document.getElementById('agents-body');
```

The rest of `renderAgentRows()` (the empty-message branch and the `list.map(...)` row-building, currently starting at `wwwroot/index.html:8172`) is unchanged — it already reads `list`/`q`, both of which still exist with the same meaning (server-scoped now instead of client-filtered).

- [ ] **Step 5: Wire the search input and add the "Load more" control**

Change the `agent-search` input's `oninput` (currently `wwwroot/index.html:1781-1783`):

```html
<input type="search" id="agent-search" placeholder="Search hostname, agent ID, IP, group…"
       oninput="onAgentSearchInput()"
       style="padding:0.45rem 0.7rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.82rem;font-family:inherit;min-width:260px">
```

Add a "Load more" control after the closing `</div>` of `.tbl-wrap` (currently `wwwroot/index.html:1805`, right before the `</div>` that closes `.agent-tree-content`):

```html
        </div>
        <div id="agent-load-more-wrap" style="text-align:center;margin-top:0.75rem;display:none">
          <button class="btn btn-outline btn-sm" onclick="loadMoreAgents()">Load more</button>
        </div>
          </div>
```

(The first `</div>` shown is the existing `.tbl-wrap` close already in the file — insert the new `<div id="agent-load-more-wrap">` block between it and the existing `.agent-tree-content` close, don't duplicate the `.tbl-wrap` close itself.)

In `renderAgentRows()`, after building `tbody.innerHTML` (at the end of the function), add:

```javascript
  var loadMoreWrap = document.getElementById('agent-load-more-wrap');
  if (loadMoreWrap) loadMoreWrap.style.display = agentsHasMore ? '' : 'none';
```

- [ ] **Step 6: Confirm no other `/api/agents` call site was touched**

Run: `grep -n "apicall('/api/agents'\|fetch('/api/agents'" orchestrator/wwwroot/index.html`
Expected: the same 8 other call sites from the spec's Non-goals section (lines ~5111, 7463, 16982, 18503, 19267, 20174, 21022, 21078 — re-verify exact numbers, they may have shifted slightly from edits above) are present and **unmodified** — only `loadAgents()`'s own call (inside the function body you just rewrote) changed.

- [ ] **Step 7: Syntax-check the rewritten script**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud\orchestrator"
python3 -c "
import re
content = open('wwwroot/index.html', encoding='utf-8').read()
scripts = re.findall(r'<script>(.*?)</script>', content, re.DOTALL)
with open('../.tmp_agents_pagination_check.js', 'w', encoding='utf-8') as f:
    for s in scripts:
        f.write(s); f.write('\n;\n')
"
node --check ../.tmp_agents_pagination_check.js && echo "JS SYNTAX OK"
rm -f ../.tmp_agents_pagination_check.js
```
Expected: `JS SYNTAX OK`.

- [ ] **Step 8: Verify HTML tag balance in the Agents tab block**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud\orchestrator"
python3 -c "
import re
content = open('wwwroot/index.html', encoding='utf-8').read()
start = content.index('<!-- Agents -->')
end = content.index('<!-- Settings (admin only) -->')
block = content[start:end]
opens = len(re.findall(r'<div\b', block))
closes = len(re.findall(r'</div>', block))
print('opens:', opens, 'closes:', closes, 'balanced:', opens==closes)
"
```
Expected: `balanced: True`. If not, the "Load more" div insertion in Step 5 has a mismatched tag — find and fix it before proceeding.

- [ ] **Step 9: Attempt a real browser walkthrough, or say plainly it wasn't feasible**

This repo has no orchestrator running locally right now (Docker Desktop containers were checked earlier this session and none are up). If a dev environment can reasonably be spun up (e.g. via the `run` skill against this repo, or `docker compose up` against a local Postgres), do so and walk through: open the Agents tab (System Tree view loads by default), confirm the KPI tiles show real numbers, click "Load more" if more than 100 agents exist, type into the search box and confirm results narrow, click each status toolbar button. If it's not feasible in this session, say so explicitly in the final report rather than claiming this was verified — this matches this session's established practice (e.g. the Detection Validation tab work earlier).

- [ ] **Step 10: Commit**

```bash
cd "C:\Users\Administrator\Downloads\Audspect_Cloud"
git add orchestrator/wwwroot/index.html
git commit -m "feat: migrate System Tree table to paginated /api/agents

loadAgents() now requests limit=100 and reads the new
{items, next_cursor, has_more, totals} envelope; a 'Load more' button
appends subsequent pages. KPI tiles and toolbar counts now read the
server-computed totals field (fleet-wide-accurate under pagination)
instead of scanning the full agents array. Search and the
online/degraded/offline/retired toolbar buttons now trigger a
server-side re-fetch (q=/bucket= params) instead of client-side
filtering, so they scope the whole fleet, not just whatever page
happened to be loaded. The other 8 /api/agents call sites in this file
are untouched -- GetAgents (9a61a64, and this session's pagination
work) keeps returning a bare array for any call with neither limit nor
cursor set.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
git push
```

---

### Task 5: Full-suite verification and report (no commit)

**Files:** none — verification only.

- [ ] **Step 1: Full backend verification**

Run: `cd orchestrator && go build ./... && go vet ./... && go test ./... -p 1 -timeout 20m`
Expected: PASS across every package, including the new pagination tests and everything pre-existing.

- [ ] **Step 2: Confirm gofmt cleanliness (matches CI)**

Run: `cd orchestrator && gofmt -l .`
Expected: prints nothing.

- [ ] **Step 3: Report**

Summarize for the user:
- Confirmation both the backend suite and `gofmt` pass clean.
- Confirmation of Task 4 Step 6's grep result (the other 8 `/api/agents` call sites untouched) and Task 4 Step 9's outcome (real browser walkthrough done, or plainly not feasible in this session and why).
- A pointer to the two commits that matter most for review: the `GetAgents` pagination commit (Task 3) and the frontend migration commit (Task 4).
- A reminder of the next step **outside this plan's scope**: redeploying to the staging server (`windows-build.ps1` → transfer → `install.sh --upgrade`) and re-running the same `curl -w` timing check and `orchestrator/loadtest/runbook.sh` combined-stage tests used to find this problem, to get a real before/after number for `docs/load-testing-capacity-report.md` (Task 8 of `orchestrator/docs/superpowers/plans/2026-08-31-load-perf-scale-testing.md`). **Flag explicitly**: this session discovered `install.sh --upgrade` regenerates `JWT_SECRET`/`AGENT_SECRET` if they aren't already present in `setup.conf` — carry the current staging `.env`'s values into `setup.conf` before that upgrade, or expect to need fresh ones again afterward (same as happened earlier today).
