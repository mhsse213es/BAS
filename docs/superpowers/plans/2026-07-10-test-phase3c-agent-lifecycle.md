# Phase 3c: Agent Lifecycle Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a regression suite for the agent-facing trust boundary and lifecycle handlers in `internal/api` — `EnrollAgent`, `Heartbeat`, `SetAgentState`, `DownloadAgent`, `PingAgent`, `GetAgents`, and the shared `validateAgentAuth` gate.

**Architecture:** Four new test files, all calling `Handler` methods directly with `httptest` (same pattern as 3a), reusing the existing `internal/api` `testutil` harness (`sharedDB`, `TestMain`, `seedUser`, `authedRequest`, `callAuthed`, `withURLParam` — all already in `testmain_test.go`/`event_handlers_test.go`, no new harness task needed).

**Tech Stack:** Go 1.x, `internal/testutil` (testcontainers-go), `net/http/httptest`, `github.com/go-chi/chi/v5` (for `withURLParam`), `internal/integrity` (`LoadManifest`, read-only — no changes to that package).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-10-test-phase3c-agent-lifecycle-design.md` (commit `5c9337a`).
- All DB-backed tests use `sharedDB.RunWithPool` — the shared harness from 3a, not a new one.
- Every task ends green on: `go build ./...`, the package's own tests, `go test ./...` (full suite), `go vet ./...`, `staticcheck ./...`. Commit each task separately.
- Characterization testing: a test failure means the test's expectation is wrong, not the product code. Two known non-fixes from the spec: `policy_json` resets to the hardcoded default on every re-enroll (not a bug to fix — no client input path for policy exists); whitespace/very-long/unicode `agentId` values are accepted today (only `== ""` is validated).
- `-race` is CI-only on this Windows host (`CGO_ENABLED=0`, no gcc). Local verification substitutes `go test -count=10` for the concurrency test.
- Coverage target: every validation branch, every trust/quarantine state transition, and every auth-gate branch in the 6 handlers + `validateAgentAuth` exercised at least once — not chasing a package-wide percentage.

---

### Task 1: `internal/api/agent_auth_test.go`

**Files:**
- Create: `orchestrator/internal/api/agent_auth_test.go`

**Interfaces:**
- Consumes: `Handler.validateAgentAuth(r *http.Request) bool` (unexported method, same package), `Handler.PingAgent`, `Handler.EnrollAgent`, `Handler.Heartbeat`, `Handler.WithAgentSecret(s string) *Handler`, `New(pool, hub, engine, secret) *Handler` (all from `handlers.go`), `sharedDB`/`seedUser` from Task 1 of Phase 3a (`testmain_test.go`).

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidateAgentAuth_Precedence(t *testing.T) {
	h := &Handler{agentSecret: "shh"}

	newReq := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
	}

	cases := []struct {
		name        string
		header      string
		query       string
		wantAllowed bool
	}{
		{"header-only-correct", "shh", "", true},
		{"query-only-correct", "", "shh", true},
		{"both-correct", "shh", "shh", true},
		{"header-wrong-query-correct", "nope", "shh", false}, // header wins even though wrong; never falls back
		{"header-empty-query-correct", "", "shh", true},      // falls through when header is empty
		{"neither-present", "", "", false},
		{"header-correct-query-wrong", "shh", "nope", true}, // header wins, query ignored
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newReq()
			if tc.header != "" {
				req.Header.Set("X-Agent-Token", tc.header)
			}
			if tc.query != "" {
				q := req.URL.Query()
				q.Set("agentSecret", tc.query)
				req.URL.RawQuery = q.Encode()
			}
			if got := h.validateAgentAuth(req); got != tc.wantAllowed {
				t.Fatalf("%s: validateAgentAuth = %v, want %v", tc.name, got, tc.wantAllowed)
			}
		})
	}
}

func TestValidateAgentAuth_NoSecretConfigured_AlwaysAllowed(t *testing.T) {
	h := &Handler{agentSecret: ""}
	req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
	if !h.validateAgentAuth(req) {
		t.Fatal("expected validateAgentAuth to allow when no secret is configured (backward-compat bypass)")
	}
}

func TestValidateAgentAuth_MalformedAndEdgeHeaderValues(t *testing.T) {
	h := &Handler{agentSecret: "shh"}

	t.Run("bearer-prefixed value does not match raw secret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
		req.Header.Set("X-Agent-Token", "Bearer shh")
		if h.validateAgentAuth(req) {
			t.Fatal("expected rejection: raw string comparison, no Bearer-prefix parsing")
		}
	})

	t.Run("whitespace-only token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
		req.Header.Set("X-Agent-Token", "   ")
		if h.validateAgentAuth(req) {
			t.Fatal("expected rejection for whitespace-only token")
		}
	})

	t.Run("duplicate headers — first value wins via Header.Get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", nil)
		req.Header.Add("X-Agent-Token", "shh")
		req.Header.Add("X-Agent-Token", "nope")
		if !h.validateAgentAuth(req) {
			t.Fatal("expected the first added header value (the correct one) to be used")
		}
	})
}

func TestPingAgent_AuthGate(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "").WithAgentSecret("shh")

	ok := httptest.NewRequest(http.MethodGet, "/api/agents/ping", nil)
	ok.Header.Set("X-Agent-Token", "shh")
	rec := httptest.NewRecorder()
	h.PingAgent(rec, ok)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: status = %d, want 200", rec.Code)
	}

	bad := httptest.NewRequest(http.MethodGet, "/api/agents/ping", nil)
	bad.Header.Set("X-Agent-Token", "wrong")
	rec2 := httptest.NewRecorder()
	h.PingAgent(rec2, bad)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", rec2.Code)
	}
}

func TestEnrollAgent_AuthGate_NoRowCreatedOnFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "").WithAgentSecret("shh")
		body, _ := json.Marshal(map[string]string{"agentId": "agent-should-not-exist"})
		req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(body))
		req.Header.Set("X-Agent-Token", "wrong")
		rec := httptest.NewRecorder()
		h.EnrollAgent(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents WHERE agent_id = $1`, "agent-should-not-exist").Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Fatal("EnrollAgent must not create a row when auth fails")
		}
	})
}

func TestHeartbeat_AuthGate_NoRowCreatedOnFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "").WithAgentSecret("shh")
		body, _ := json.Marshal(map[string]string{"agentId": "agent-should-not-exist-2"})
		req := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(body))
		req.Header.Set("X-Agent-Token", "wrong")
		rec := httptest.NewRecorder()
		h.Heartbeat(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents WHERE agent_id = $1`, "agent-should-not-exist-2").Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Fatal("Heartbeat must not create a row when auth fails")
		}
	})
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestValidateAgentAuth|TestPingAgent_AuthGate|TestEnrollAgent_AuthGate|TestHeartbeat_AuthGate' -v`
Expected: all PASS.

- [ ] **Step 3: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/agent_auth_test.go
git commit -m "test(api): add agent-secret auth precedence and edge-case tests

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: `internal/api/agent_lifecycle_test.go`

**Files:**
- Create: `orchestrator/internal/api/agent_lifecycle_test.go`

**Interfaces:**
- Consumes: `Handler.EnrollAgent`, `Handler.Heartbeat`, `Handler.SetAgentState`, `Handler.GetAgents`, `Handler.PingAgent` (`handlers.go`); `withURLParam` (`event_handlers_test.go`, same package); `sharedDB`/`seedUser` (`testmain_test.go`).

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func enrollBody(agentID string, extra map[string]any) []byte {
	m := map[string]any{"agentId": agentID, "hostname": "host-" + agentID}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func heartbeatBody(agentID string) []byte {
	b, _ := json.Marshal(map[string]any{"agentId": agentID, "hostname": "host-" + agentID, "status": "idle"})
	return b
}

func TestEnrollAgent_MalformedAndMissingID(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	malformed := httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	h.EnrollAgent(rec, malformed)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: status = %d, want 400", rec.Code)
	}

	missing := httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody("", nil)))
	rec2 := httptest.NewRecorder()
	h.EnrollAgent(rec2, missing)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("missing agentId: status = %d, want 400", rec2.Code)
	}
}

func TestEnrollAgent_ReEnrollPreservesEnrolledAtAndResetsPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-reenroll-1"

		rec1 := httptest.NewRecorder()
		h.EnrollAgent(rec1, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if rec1.Code != http.StatusOK {
			t.Fatalf("first enroll: status = %d, body = %s", rec1.Code, rec1.Body.String())
		}
		var firstEnrolledAt time.Time
		if err := pool.QueryRow(context.Background(), `SELECT enrolled_at FROM agents WHERE agent_id=$1`, agentID).Scan(&firstEnrolledAt); err != nil {
			t.Fatalf("read enrolled_at: %v", err)
		}

		// Manually diverge policy_json to prove re-enroll resets it.
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET policy_json = '{"logLevel":"debug","maxConcurrentRuns":99,"heartbeatIntervalS":5}' WHERE agent_id=$1`, agentID); err != nil {
			t.Fatalf("diverge policy: %v", err)
		}

		time.Sleep(10 * time.Millisecond)
		rec2 := httptest.NewRecorder()
		h.EnrollAgent(rec2, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if rec2.Code != http.StatusOK {
			t.Fatalf("second enroll: status = %d, body = %s", rec2.Code, rec2.Body.String())
		}

		var secondEnrolledAt time.Time
		var policyRaw string
		if err := pool.QueryRow(context.Background(), `SELECT enrolled_at, policy_json::text FROM agents WHERE agent_id=$1`, agentID).Scan(&secondEnrolledAt, &policyRaw); err != nil {
			t.Fatalf("read after re-enroll: %v", err)
		}
		if !firstEnrolledAt.Equal(secondEnrolledAt) {
			t.Fatalf("enrolled_at changed on re-enroll: %v -> %v (must stay stable)", firstEnrolledAt, secondEnrolledAt)
		}
		var policy models.PolicyBundle
		if err := json.Unmarshal([]byte(policyRaw), &policy); err != nil {
			t.Fatalf("decode policy: %v", err)
		}
		if policy.LogLevel != "info" || policy.MaxConcurrentRuns != 1 || policy.HeartbeatInterval != 30 {
			t.Fatalf("policy after re-enroll = %+v, want the hardcoded default (re-enroll resets it, characterized behavior)", policy)
		}
	})
}

func TestEnrollAgent_PreservesQuarantinedAndRetiredState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		for _, state := range []string{"quarantined", "retired"} {
			agentID := "agent-preserve-" + state
			rec := httptest.NewRecorder()
			h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
			if rec.Code != http.StatusOK {
				t.Fatalf("initial enroll (%s): status = %d", state, rec.Code)
			}
			if _, err := pool.Exec(context.Background(), `UPDATE agents SET state=$1 WHERE agent_id=$2`, state, agentID); err != nil {
				t.Fatalf("set state: %v", err)
			}

			rec2 := httptest.NewRecorder()
			h.EnrollAgent(rec2, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
			if rec2.Code != http.StatusOK {
				t.Fatalf("re-enroll (%s): status = %d", state, rec2.Code)
			}
			var got string
			if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, agentID).Scan(&got); err != nil {
				t.Fatalf("read state: %v", err)
			}
			if got != state {
				t.Fatalf("state after re-enroll = %q, want %q preserved", got, state)
			}
		}
	})
}

func TestEnrollAgent_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-idempotent-enroll"
		for i := 0; i < 3; i++ {
			rec := httptest.NewRecorder()
			h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
			if rec.Code != http.StatusOK {
				t.Fatalf("enroll #%d: status = %d", i, rec.Code)
			}
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents WHERE agent_id=$1`, agentID).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count after 3 enrolls = %d, want 1", count)
		}
	})
}

func TestHeartbeat_MalformedAndMissingID(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	malformed := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	h.Heartbeat(rec, malformed)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: status = %d, want 400", rec.Code)
	}

	missing := httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody("")))
	rec2 := httptest.NewRecorder()
	h.Heartbeat(rec2, missing)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("missing agentId: status = %d, want 400", rec2.Code)
	}
}

func TestHeartbeat_IdempotentAndTimestampAdvances(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-idempotent-hb"

		rec1 := httptest.NewRecorder()
		h.Heartbeat(rec1, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
		if rec1.Code != http.StatusOK {
			t.Fatalf("first heartbeat: status = %d, body = %s", rec1.Code, rec1.Body.String())
		}
		var first time.Time
		if err := pool.QueryRow(context.Background(), `SELECT last_update FROM agents WHERE agent_id=$1`, agentID).Scan(&first); err != nil {
			t.Fatalf("read first last_update: %v", err)
		}

		time.Sleep(10 * time.Millisecond)
		for i := 0; i < 2; i++ {
			rec := httptest.NewRecorder()
			h.Heartbeat(rec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
			if rec.Code != http.StatusOK {
				t.Fatalf("heartbeat #%d: status = %d", i, rec.Code)
			}
		}

		var count int
		var second time.Time
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*), MAX(last_update) FROM agents WHERE agent_id=$1 GROUP BY agent_id`, agentID).Scan(&count, &second); err != nil {
			t.Fatalf("read after repeats: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count after 3 heartbeats = %d, want 1", count)
		}
		if !second.After(first) {
			t.Fatalf("last_update did not advance: first=%v second=%v", first, second)
		}
	})
}

func TestHeartbeat_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-concurrent-hb"

		const n = 20
		var wg sync.WaitGroup
		statuses := make([]int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rec := httptest.NewRecorder()
				h.Heartbeat(rec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
				statuses[i] = rec.Code
			}(i)
		}
		wg.Wait()

		for i, s := range statuses {
			if s != http.StatusOK {
				t.Errorf("goroutine %d: status = %d, want 200 (no panics/deadlocks/errors under concurrency)", i, s)
			}
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents WHERE agent_id=$1`, agentID).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Fatalf("row count after concurrent heartbeats = %d, want 1", count)
		}
	})
}

func TestSetAgentState_ValidationAndIdempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-setstate-1"
		enrollRec := httptest.NewRecorder()
		h.EnrollAgent(enrollRec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if enrollRec.Code != http.StatusOK {
			t.Fatalf("seed enroll: status = %d", enrollRec.Code)
		}

		invalidBody, _ := json.Marshal(map[string]string{"state": "not-a-state"})
		invalidReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/"+agentID+"/state", bytes.NewReader(invalidBody)), "agentId", agentID)
		rec := httptest.NewRecorder()
		h.SetAgentState(rec, invalidReq)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid state: status = %d, want 400", rec.Code)
		}

		unknownBody, _ := json.Marshal(map[string]string{"state": "restricted"})
		unknownReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/does-not-exist/state", bytes.NewReader(unknownBody)), "agentId", "does-not-exist")
		rec2 := httptest.NewRecorder()
		h.SetAgentState(rec2, unknownReq)
		if rec2.Code != http.StatusNotFound {
			t.Fatalf("unknown agent: status = %d, want 404", rec2.Code)
		}

		for i := 0; i < 2; i++ {
			validBody, _ := json.Marshal(map[string]string{"state": "restricted"})
			validReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/"+agentID+"/state", bytes.NewReader(validBody)), "agentId", agentID)
			rec3 := httptest.NewRecorder()
			h.SetAgentState(rec3, validReq)
			if rec3.Code != http.StatusOK {
				t.Fatalf("valid state set #%d: status = %d", i, rec3.Code)
			}
		}
		var got string
		if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, agentID).Scan(&got); err != nil {
			t.Fatalf("read state: %v", err)
		}
		if got != "restricted" {
			t.Fatalf("state = %q, want restricted", got)
		}
	})
}

func TestGetAgents_EmptyOrderingAndNullableFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")

		recEmpty := httptest.NewRecorder()
		h.GetAgents(recEmpty, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		var empty []map[string]any
		_ = json.Unmarshal(recEmpty.Body.Bytes(), &empty)
		if empty == nil {
			t.Fatal("expected [], got null for zero agents")
		}

		// Heartbeat-only agent: never enrolled, so enrolled_at must be null.
		hbRec := httptest.NewRecorder()
		h.Heartbeat(hbRec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody("agent-hb-only"))))
		if hbRec.Code != http.StatusOK {
			t.Fatalf("seed heartbeat: status = %d", hbRec.Code)
		}

		// Two more agents with distinct, explicit last_update values to prove ordering.
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, last_update) VALUES ('agent-old','h', NOW() - interval '2 hours')`); err != nil {
			t.Fatalf("seed old: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, last_update) VALUES ('agent-newest','h', NOW() + interval '1 hour')`); err != nil {
			t.Fatalf("seed newest: %v", err)
		}

		rec := httptest.NewRecorder()
		h.GetAgents(rec, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var agents []models.Agent
		if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(agents) != 3 {
			t.Fatalf("got %d agents, want 3", len(agents))
		}
		if agents[0].AgentID != "agent-newest" || agents[len(agents)-1].AgentID != "agent-old" {
			t.Fatalf("ordering not descending by last_update: %v", []string{agents[0].AgentID, agents[1].AgentID, agents[2].AgentID})
		}

		var hbOnly *models.Agent
		for i := range agents {
			if agents[i].AgentID == "agent-hb-only" {
				hbOnly = &agents[i]
			}
		}
		if hbOnly == nil {
			t.Fatal("agent-hb-only missing from response")
		}
		if hbOnly.EnrolledAt != nil {
			t.Fatalf("EnrolledAt = %v, want nil for a heartbeat-only agent", hbOnly.EnrolledAt)
		}
	})
}

func TestPingAgent_DoesNotTouchDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		rec := httptest.NewRecorder()
		h.PingAgent(rec, httptest.NewRequest(http.MethodGet, "/api/agents/ping", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM agents`).Scan(&count); err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 0 {
			t.Fatal("PingAgent must not create any agent row")
		}
	})
}

func TestAgentIdentity_EdgeCases(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")

		whitespace := "   "
		rec := httptest.NewRecorder()
		h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(whitespace, nil))))
		if rec.Code != http.StatusOK {
			t.Fatalf("whitespace-only agentId: status = %d (current validation only checks == \"\")", rec.Code)
		}

		longID := strings.Repeat("x", 500)
		rec2 := httptest.NewRecorder()
		h.EnrollAgent(rec2, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(longID, nil))))
		if rec2.Code != http.StatusOK {
			t.Fatalf("500-char agentId: status = %d, want 200 (no length constraint in schema)", rec2.Code)
		}

		unicodeID := "エージェント-🤖-агент"
		rec3 := httptest.NewRecorder()
		h.EnrollAgent(rec3, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(unicodeID, nil))))
		if rec3.Code != http.StatusOK {
			t.Fatalf("unicode agentId: status = %d, want 200", rec3.Code)
		}
		var gotID string
		if err := pool.QueryRow(context.Background(), `SELECT agent_id FROM agents WHERE agent_id=$1`, unicodeID).Scan(&gotID); err != nil {
			t.Fatalf("unicode agentId did not round-trip through Postgres: %v", err)
		}
		if gotID != unicodeID {
			t.Fatalf("round-tripped agentId = %q, want %q", gotID, unicodeID)
		}
	})
}

func TestAgentLifecycle_EndToEndChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-e2e-chain"

		pingRec := httptest.NewRecorder()
		h.PingAgent(pingRec, httptest.NewRequest(http.MethodGet, "/api/agents/ping", nil))
		if pingRec.Code != http.StatusOK {
			t.Fatalf("ping: status = %d", pingRec.Code)
		}

		enrollRec := httptest.NewRecorder()
		h.EnrollAgent(enrollRec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if enrollRec.Code != http.StatusOK {
			t.Fatalf("enroll: status = %d, body = %s", enrollRec.Code, enrollRec.Body.String())
		}

		hbRec := httptest.NewRecorder()
		h.Heartbeat(hbRec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
		if hbRec.Code != http.StatusOK {
			t.Fatalf("heartbeat: status = %d", hbRec.Code)
		}

		listRec1 := httptest.NewRecorder()
		h.GetAgents(listRec1, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		var agents1 []models.Agent
		_ = json.Unmarshal(listRec1.Body.Bytes(), &agents1)
		found := false
		for _, a := range agents1 {
			if a.AgentID == agentID {
				found = true
				if a.State != models.AgentStateActive {
					t.Fatalf("state after enroll+heartbeat = %q, want active", a.State)
				}
			}
		}
		if !found {
			t.Fatal("agent not visible in GetAgents after enroll+heartbeat")
		}

		stateBody, _ := json.Marshal(map[string]string{"state": "quarantined"})
		stateReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/"+agentID+"/state", bytes.NewReader(stateBody)), "agentId", agentID)
		stateRec := httptest.NewRecorder()
		h.SetAgentState(stateRec, stateReq)
		if stateRec.Code != http.StatusOK {
			t.Fatalf("set state: status = %d", stateRec.Code)
		}

		hbRec2 := httptest.NewRecorder()
		h.Heartbeat(hbRec2, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBody(agentID))))
		if hbRec2.Code != http.StatusOK {
			t.Fatalf("second heartbeat: status = %d", hbRec2.Code)
		}
		var resp models.HeartbeatResponse
		if err := json.Unmarshal(hbRec2.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode heartbeat response: %v", err)
		}
		if resp.State != models.AgentStateQuarantined {
			t.Fatalf("heartbeat response state = %q, want quarantined (heartbeat's upsert never touches state on conflict)", resp.State)
		}

		listRec2 := httptest.NewRecorder()
		h.GetAgents(listRec2, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
		var agents2 []models.Agent
		_ = json.Unmarshal(listRec2.Body.Bytes(), &agents2)
		for _, a := range agents2 {
			if a.AgentID == agentID && a.State != models.AgentStateQuarantined {
				t.Fatalf("final GetAgents state = %q, want quarantined", a.State)
			}
		}
	})
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestEnrollAgent|TestHeartbeat|TestSetAgentState|TestGetAgents|TestPingAgent_DoesNotTouchDB|TestAgentIdentity|TestAgentLifecycle_EndToEndChain' -v`
Expected: all PASS. If `TestEnrollAgent_ReEnrollPreservesEnrolledAtAndResetsPolicy` fails on the `enrolled_at` comparison, check whether Postgres's `timestamptz` round-trip through pgx needs `.Truncate` before `.Equal` — adjust to `firstEnrolledAt.Truncate(time.Microsecond).Equal(secondEnrolledAt.Truncate(time.Microsecond))` if so.

- [ ] **Step 3: Concurrency checkpoint — extra rigor**

Run: `go test ./internal/api/... -run 'TestHeartbeat_Concurrent' -count=10 -v`
Expected: 10/10 clean, no flakes.

- [ ] **Step 4: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/agent_lifecycle_test.go
git commit -m "test(api): add agent lifecycle handler tests — enroll/heartbeat/state/list, idempotency, concurrency, identity edge cases, E2E chain

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: `internal/api/agent_trust_test.go`

**Files:**
- Create: `orchestrator/internal/api/agent_trust_test.go`

**Interfaces:**
- Consumes: `Handler.WithManifest(m *integrity.Manifest) *Handler`, `integrity.LoadManifest(path string) *integrity.Manifest`, `Handler.EnrollAgent`, `Handler.Heartbeat`, `Handler.SetAgentState` (all from earlier tasks/`handlers.go`).

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	trustTestTrustedHash   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	trustTestUntrustedHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func trustTestManifest(t *testing.T) *integrity.Manifest {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "BINARIES.sha256")
	content := trustTestTrustedHash + "  test-binary\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write manifest fixture: %v", err)
	}
	return integrity.LoadManifest(path)
}

func heartbeatBodyWithHash(agentID, hash string) []byte {
	b, _ := json.Marshal(map[string]any{"agentId": agentID, "hostname": "h", "status": "idle", "binaryHash": hash})
	return b
}

func enrollBodyWithHash(agentID, hash string) []byte {
	b, _ := json.Marshal(map[string]any{"agentId": agentID, "hostname": "h", "binaryHash": hash})
	return b
}

func TestAgentTrust_FullMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		manifest := trustTestManifest(t)

		type manifestCase struct {
			name    string
			m       *integrity.Manifest
			hash    string
			trusted bool
		}
		manifestCases := []manifestCase{
			{"no-manifest-loaded", nil, trustTestTrustedHash, false},
			{"trusted-hash", manifest, trustTestTrustedHash, true},
			{"untrusted-hash", manifest, trustTestUntrustedHash, false},
		}
		priorStates := []string{"active", "quarantined", "retired"}

		for _, mc := range manifestCases {
			for _, prior := range priorStates {
				t.Run(mc.name+"/prior="+prior, func(t *testing.T) {
					h := New(pool, ws.NewHub(), nil, "")
					if mc.m != nil {
						h = h.WithManifest(mc.m)
					}
					agentID := "agent-trust-" + mc.name + "-" + prior

					enrollRec := httptest.NewRecorder()
					h.EnrollAgent(enrollRec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
					if enrollRec.Code != http.StatusOK {
						t.Fatalf("seed enroll: status = %d", enrollRec.Code)
					}
					if _, err := pool.Exec(context.Background(), `UPDATE agents SET state=$1 WHERE agent_id=$2`, prior, agentID); err != nil {
						t.Fatalf("set prior state: %v", err)
					}

					hbRec := httptest.NewRecorder()
					h.Heartbeat(hbRec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBodyWithHash(agentID, mc.hash))))
					if hbRec.Code != http.StatusOK {
						t.Fatalf("heartbeat: status = %d, body = %s", hbRec.Code, hbRec.Body.String())
					}

					var gotTrusted bool
					var gotState string
					if err := pool.QueryRow(context.Background(), `SELECT binary_trusted, state FROM agents WHERE agent_id=$1`, agentID).Scan(&gotTrusted, &gotState); err != nil {
						t.Fatalf("read: %v", err)
					}
					if gotTrusted != mc.trusted {
						t.Fatalf("binary_trusted = %v, want %v", gotTrusted, mc.trusted)
					}

					wantState := prior
					if prior == "active" && mc.m != nil && !mc.trusted {
						wantState = "quarantined" // only active->quarantined auto-transitions
					}
					if gotState != wantState {
						t.Fatalf("state = %q, want %q (prior=%s trusted=%v manifestLoaded=%v)", gotState, wantState, prior, mc.trusted, mc.m != nil)
					}
				})
			}
		}
	})
}

func TestAgentTrust_RatchetSequence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		manifest := trustTestManifest(t)
		h := New(pool, ws.NewHub(), nil, "").WithManifest(manifest)
		agentID := "agent-trust-ratchet"

		enrollRec := httptest.NewRecorder()
		h.EnrollAgent(enrollRec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBody(agentID, nil))))
		if enrollRec.Code != http.StatusOK {
			t.Fatalf("enroll: status = %d", enrollRec.Code)
		}

		beat := func(hash string) string {
			rec := httptest.NewRecorder()
			h.Heartbeat(rec, httptest.NewRequest(http.MethodPost, "/api/heartbeat", bytes.NewReader(heartbeatBodyWithHash(agentID, hash))))
			if rec.Code != http.StatusOK {
				t.Fatalf("heartbeat: status = %d", rec.Code)
			}
			var state string
			if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, agentID).Scan(&state); err != nil {
				t.Fatalf("read state: %v", err)
			}
			return state
		}

		if s := beat(trustTestTrustedHash); s != "active" {
			t.Fatalf("after trusted heartbeat: state = %q, want active", s)
		}
		if s := beat(trustTestUntrustedHash); s != "quarantined" {
			t.Fatalf("after untrusted heartbeat: state = %q, want quarantined", s)
		}
		if s := beat(trustTestTrustedHash); s != "quarantined" {
			t.Fatalf("after trusted heartbeat post-quarantine: state = %q, want quarantined (no auto-restore)", s)
		}

		stateBody, _ := json.Marshal(map[string]string{"state": "active"})
		stateReq := withURLParam(httptest.NewRequest(http.MethodPut, "/api/agents/"+agentID+"/state", bytes.NewReader(stateBody)), "agentId", agentID)
		stateRec := httptest.NewRecorder()
		h.SetAgentState(stateRec, stateReq)
		if stateRec.Code != http.StatusOK {
			t.Fatalf("admin restore: status = %d", stateRec.Code)
		}

		if s := beat(trustTestTrustedHash); s != "active" {
			t.Fatalf("after admin restore + trusted heartbeat: state = %q, want active", s)
		}
	})
}

func TestEnrollAgent_TrustedAndUntrustedHash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		manifest := trustTestManifest(t)
		h := New(pool, ws.NewHub(), nil, "").WithManifest(manifest)

		trustedID := "agent-enroll-trusted"
		rec := httptest.NewRecorder()
		h.EnrollAgent(rec, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBodyWithHash(trustedID, trustTestTrustedHash))))
		if rec.Code != http.StatusOK {
			t.Fatalf("enroll trusted: status = %d", rec.Code)
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["trusted"] != true {
			t.Fatalf("enroll response trusted = %v, want true", resp["trusted"])
		}

		untrustedID := "agent-enroll-untrusted"
		rec2 := httptest.NewRecorder()
		h.EnrollAgent(rec2, httptest.NewRequest(http.MethodPost, "/api/agents/enroll", bytes.NewReader(enrollBodyWithHash(untrustedID, trustTestUntrustedHash))))
		if rec2.Code != http.StatusOK {
			t.Fatalf("enroll untrusted: status = %d", rec2.Code)
		}
		var resp2 map[string]any
		_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
		if resp2["trusted"] != false {
			t.Fatalf("enroll response trusted = %v, want false", resp2["trusted"])
		}
		// EnrollAgent itself never quarantines on an untrusted hash — only
		// Heartbeat's post-enroll check does. Enroll always leaves state
		// active (or preserves quarantined/retired per the CASE clause).
		var state string
		if err := pool.QueryRow(context.Background(), `SELECT state FROM agents WHERE agent_id=$1`, untrustedID).Scan(&state); err != nil {
			t.Fatalf("read state: %v", err)
		}
		if state != "active" {
			t.Fatalf("state after untrusted enroll = %q, want active (enroll doesn't auto-quarantine, only heartbeat does)", state)
		}
	})
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestAgentTrust|TestEnrollAgent_TrustedAndUntrustedHash' -v`
Expected: all PASS (this is `3 manifestCases × 3 priorStates = 9` subtests for the matrix, plus the ratchet sequence and the enroll-hash tests).

- [ ] **Step 3: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/agent_trust_test.go
git commit -m "test(api): add binary-hash trust/quarantine matrix and ratchet-sequence tests

Full cross-product over {no manifest, trusted hash, untrusted hash} x
{active, quarantined, retired} for Heartbeat, plus a sequence test proving
quarantine only clears via SetAgentState (admin action), never a
subsequent trusted heartbeat.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: `internal/api/download_agent_test.go`

**Files:**
- Create: `orchestrator/internal/api/download_agent_test.go`

**Interfaces:**
- Consumes: `Handler.DownloadAgent` (`handlers.go`), `agentFiles` (unexported package-level map, `handlers.go`), `withURLParam` (`event_handlers_test.go`).

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/audspect/bas/internal/ws"
)

func TestDownloadAgent_UnknownPlatform(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/agents/download/not-a-real-platform", nil), "platform", "not-a-real-platform")
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestDownloadAgent_KnownPlatformNoFilePresent(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/agents/download/linux-amd64", nil), "platform", "linux-amd64")
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (no binaries are checked into git — this is today's real dev/CI behavior)", rec.Code)
	}
}

func TestDownloadAgent_PathTraversalAttemptRejectedAsUnknownPlatform(t *testing.T) {
	h := New(nil, ws.NewHub(), nil, "")
	traversalValues := []string{
		"../../../../etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"linux-amd64/../../secret",
	}
	for _, v := range traversalValues {
		t.Run(v, func(t *testing.T) {
			req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/agents/download/x", nil), "platform", v)
			rec := httptest.NewRecorder()
			h.DownloadAgent(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (must resolve as unknown platform via the allowlist map, never reach os.Open with this value)", rec.Code)
			}
		})
	}
}

func TestDownloadAgent_SuccessPath(t *testing.T) {
	entry, ok := agentFiles["linux-amd64"]
	if !ok {
		t.Fatal("agentFiles missing linux-amd64 — update this test if the allowlist changed")
	}
	dir := "./agents"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	fixturePath := filepath.Join(dir, entry.filename)
	content := []byte("fake-agent-binary-content-for-test")
	if err := os.WriteFile(fixturePath, content, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(fixturePath)
	})

	h := New(nil, ws.NewHub(), nil, "")
	req := withURLParam(httptest.NewRequest(http.MethodGet, "/api/agents/download/linux-amd64", nil), "platform", "linux-amd64")
	rec := httptest.NewRecorder()
	h.DownloadAgent(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != entry.mimeType {
		t.Fatalf("Content-Type = %q, want %q", got, entry.mimeType)
	}
	wantDisposition := `attachment; filename="` + entry.filename + `"`
	if got := rec.Header().Get("Content-Disposition"); got != wantDisposition {
		t.Fatalf("Content-Disposition = %q, want %q", got, wantDisposition)
	}
	if rec.Body.String() != string(content) {
		t.Fatalf("body = %q, want %q", rec.Body.String(), string(content))
	}
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestDownloadAgent' -v`
Expected: all PASS.

- [ ] **Step 3: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

Run: `git status --short internal/api/agents/` — expected: empty (the fixture file was removed by `t.Cleanup`; the directory itself may remain, which is harmless since git doesn't track empty directories).

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/download_agent_test.go
git commit -m "test(api): add DownloadAgent tests — unknown platform, missing file, path-traversal rejection, and success path via transient fixture

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 5: Final validation pass

**Files:** none (verification only).

- [ ] **Step 1: Full build**

Run: `cd orchestrator && go build ./...`
Expected: clean.

- [ ] **Step 2: Full test suite**

Run: `go test ./...`
Expected: all packages PASS.

- [ ] **Step 3: vet + staticcheck + gofmt**

Run: `go vet ./... && staticcheck ./...`
Expected: clean.

Run (for each new file): `git show HEAD:internal/api/agent_auth_test.go | gofmt -l -` (repeat for `agent_lifecycle_test.go`, `agent_trust_test.go`, `download_agent_test.go`)
Expected: no output (clean).

- [ ] **Step 4: Determinism**

Run: `go test ./internal/api/... -count=10`
Expected: 10/10 clean, no flakes across the whole package (not just the concurrency subset checked at Task 2's checkpoint).

- [ ] **Step 5: -race note**

Unavailable locally (no cgo on this Windows host); verified on `ubuntu-latest` in CI.

- [ ] **Step 6: Coverage review**

Run: `go test ./internal/api/... -coverprofile=coverage-3c.out && go tool cover -func=coverage-3c.out | grep -E "\b(EnrollAgent|Heartbeat|SetAgentState|DownloadAgent|PingAgent|GetAgents|validateAgentAuth)\b"`
Expected: every one of these 7 symbols shows nonzero coverage; review for any authorization/validation/error branch still at 0% and note it (don't chase pure DB-fault branches needing fault injection — same honest-ceiling precedent as Phases 1/3a).

Delete the scratch profile when done: `rm coverage-3c.out`.

- [ ] **Step 7: Update memory**

Update `project_test_generation_phase0.md` with a "Phase 3c DONE" section (commit range, coverage summary, key learnings — the trust ratchet's one-way behavior, the `policy_json` reset-on-re-enroll characterization, the `DownloadAgent` fixture-file testing approach) and the `MEMORY.md` index line.

---

## Self-Review

**Spec coverage:** All 4 spec test files have a task. Idempotency (Tasks 2/3), timestamp advancement (Task 2), identity edge cases (Task 2), trust ratchet (Task 3), path traversal (Task 4), concurrency (Task 2 + checkpoint), GetAgents ordering/nullable fields (Task 2), auth precedence expansion (Task 1), E2E lifecycle chain (Task 2) — all present. The two "won't fabricate" items from the spec (policy updates, filtering/pagination) correctly have no task, since no such feature exists to test.

**Placeholder scan:** No TBD/TODO. No dead/defensive scaffolding left in any code block.

**Type consistency:** `enrollBody`/`heartbeatBody`/`enrollBodyWithHash`/`heartbeatBodyWithHash` (Tasks 2/3) match `models.Heartbeat`'s JSON tags (`agentId`, `hostname`, `status`, `binaryHash`) exactly as defined in `internal/models/schema.go`. `trustTestManifest`/`trustTestTrustedHash`/`trustTestUntrustedHash` (Task 3) are used consistently across `TestAgentTrust_FullMatrix`, `TestAgentTrust_RatchetSequence`, and `TestEnrollAgent_TrustedAndUntrustedHash`. `agentFiles`/`withURLParam` (Task 4) match the exact unexported symbols already present in `handlers.go`/`event_handlers_test.go`.
