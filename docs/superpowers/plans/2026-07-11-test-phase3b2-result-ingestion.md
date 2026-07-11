# Phase 3b.2 Result Ingestion Test Generation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add regression-safety test coverage for `SubmitScenarioResult`, `ListScenarioRuns`, and `CancelRun` in `orchestrator/internal/api`, per the approved design at `docs/superpowers/specs/2026-07-11-test-phase3b2-result-ingestion-design.md`.

**Architecture:** Five new test files in `orchestrator/internal/api`: a shared infrastructure file (MAC signing, request builders, a `seedRun` fixture helper, a fake-browser WS client), a dedicated MAC/tamper-detection matrix, the core `SubmitScenarioResult` orchestration tests (split across two tasks), a `ListScenarioRuns` read-model contract file, and a `CancelRun` state-machine file. All tests are characterization tests against existing, already-shipped behavior — no production code changes are expected in this phase (contrast with 3b.1, which found and fixed two real bugs; if a test here reveals a genuine bug, stop and flag it to the user before fixing, per project convention).

**Tech Stack:** Go 1.x, `testing` + table-driven subtests, `pgx/v5` (`sharedDB.RunWithPool` for per-test Postgres isolation via testcontainers), `gorilla/websocket` (fake WS clients), existing helpers from `internal/api/run_dispatch_helpers_test.go` (`wsEnvelope`, `wsProbeMessage`, `startFakeAgent`, `minimalLiveScenario`) and `internal/api/run_scenario_gates_test.go` (`seedActiveAgent`, `withURLParam`).

## Global Constraints

- Every DB-backed test starts with `if testing.Short() { t.Skip("skipping container-backed test in -short mode") }` — matches every existing test file in this package.
- Every DB-backed test body is wrapped in `sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) { ... })` — this package's established per-test isolation pattern (truncate-based, not per-test containers).
- Reuse existing helpers instead of redefining them: `wsEnvelope`, `wsProbeMessage()`, `startFakeAgent`, `waitForAgentConnected`, `minimalLiveScenario`, `minimalPostureScenario`, `seedActiveAgent`, `withURLParam` are already defined in `run_dispatch_helpers_test.go` / `run_scenario_gates_test.go` / `event_handlers_test.go` (same package `api` — no import needed, just don't redeclare).
- `New(pool, hub, engine, secret)`'s 4th argument is the **JWT** secret (`h.secret`), not the agent secret. The agent secret (`h.agentSecret`, gates both `validateAgentAuth` and `verifyResultMAC`) is set separately via `.WithAgentSecret(s)`, which returns `*Handler` and is chainable off `New(...)`.
- `scenario_runs.agent_id` has `CONSTRAINT fk_agent FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE` — every seeded run needs a corresponding `agents` row first. The `seedRun` helper built in Task 1 handles this automatically via an idempotent `ON CONFLICT (agent_id) DO NOTHING` insert.
- `scenario_runs` has a partial unique index `idx_scenario_runs_agent_running ON scenario_runs(agent_id) WHERE status = 'running'` (from Phase 3b.1) — at most one `'running'` row per agent at a time. Table-driven (sub)tests that reuse one agent ID across cases must ensure each prior case's row has left `'running'` status before the next case seeds a new one; this is naturally satisfied wherever a case's own `SubmitScenarioResult`/`CancelRun` call transitions the row out of `'running'` before the next subtest runs (subtests execute sequentially, not in parallel, since no step below calls `t.Parallel()`).
- `scenario_runs.results` is `jsonb NOT NULL DEFAULT '[]'` (never `NULL`); `scenario_runs.score` is nullable `jsonb` (`NULL` until first scored). Don't confuse the two when asserting "nothing was written."
- Money quote from the design doc's scope boundary: verify the *trigger conditions* of `upsertFindingsForRun`, `upsertVariantFindingsForRun`, and `persistVariantResults` (fired vs. skipped, via an observable DB row appearing or not) — never their internal derivation correctness. Never assert on the three async goroutine fan-outs (compliance snapshot refresh, SIEM auto-correlate, campaign/variant-technique summary) at all — no polling, no sleeping.
- Commit trailer on every commit: `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`. Push immediately after every commit (per project convention — Windows is the build host, the user pulls on the VM).

---

### Task 1: Shared Test Infrastructure

**Files:**
- Create: `orchestrator/internal/api/result_ingestion_helpers_test.go`

**Interfaces:**
- Produces (used by every later task in this plan):
  - `func signResultMAC(secret string, body []byte) string`
  - `func submitResultReq(agentToken, mac string, body []byte) *http.Request`
  - `func validSubmitResultReq(secret string, body []byte) *http.Request`
  - `func rawResultBody(t *testing.T, raw scenario.RawRunResult) []byte`
  - `func seedRun(t *testing.T, pool *pgxpool.Pool, runID, scenarioID, agentID, status string)`
  - `type fakeBrowser struct{ ... }`
  - `func startFakeBrowser(t *testing.T, hub *ws.Hub) *fakeBrowser`
  - `func (b *fakeBrowser) WaitForMessage(t *testing.T, timeout time.Duration) wsEnvelope`
  - `func (b *fakeBrowser) Disconnect(t *testing.T)`
  - `func (b *fakeBrowser) Reconnect(t *testing.T, hub *ws.Hub)`
- Consumes: `wsEnvelope`, `wsProbeMessage()` from `run_dispatch_helpers_test.go` (same package, no import).

- [ ] **Step 1: Write the helper file**

```go
package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
)

// signResultMAC mirrors integrity.VerifyResultMAC's construction (HMAC-SHA256
// over the raw body, hex-encoded) so tests can build valid MACs without
// importing anything beyond the documented wire contract.
func signResultMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// submitResultReq builds a raw POST /api/scenarios/result request with full
// control over both auth headers. Pass "" for either to omit that header
// entirely (distinct from an explicitly-empty header value only in intent,
// not in observed behavior — both read back as "" server-side).
func submitResultReq(agentToken, mac string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/result", strings.NewReader(string(body)))
	if agentToken != "" {
		req.Header.Set("X-Agent-Token", agentToken)
	}
	if mac != "" {
		req.Header.Set("X-Result-MAC", mac)
	}
	return req
}

// validSubmitResultReq builds a request with correctly-computed auth headers
// for the given secret. Pass "" to build a request with no auth headers at
// all, matching an unconfigured (bypass) agentSecret.
func validSubmitResultReq(secret string, body []byte) *http.Request {
	if secret == "" {
		return submitResultReq("", "", body)
	}
	return submitResultReq(secret, signResultMAC(secret, body), body)
}

// rawResultBody marshals a RawRunResult the same way an agent would.
func rawResultBody(t *testing.T, raw scenario.RawRunResult) []byte {
	t.Helper()
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal RawRunResult: %v", err)
	}
	return b
}

// seedRun inserts a minimal agents row (idempotent — ON CONFLICT DO NOTHING,
// so callers don't need to separately track whether an agent ID was already
// seeded) and a scenario_runs row with the given status. Use direct SQL
// instead when a test needs to seed a status other than what seedRun's
// caller controls, or when the agent needs specific OS/state values (use
// seedActiveAgent from run_scenario_gates_test.go for that).
func seedRun(t *testing.T, pool *pgxpool.Pool, runID, scenarioID, agentID, status string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')
		 ON CONFLICT (agent_id) DO NOTHING`, agentID); err != nil {
		t.Fatalf("seed agent for run: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
		 VALUES ($1,$2,$3,'test-run',$4,NOW())`, runID, scenarioID, agentID, status); err != nil {
		t.Fatalf("seed run: %v", err)
	}
}

// fakeBrowser is a real WebSocket client standing in for a dashboard browser,
// mirroring fakeAgent in run_dispatch_helpers_test.go. Reusable WS test
// infrastructure, not tied to result ingestion specifically.
type fakeBrowser struct {
	hub      *ws.Hub
	server   *httptest.Server
	conn     *websocket.Conn
	received chan wsEnvelope
}

func startFakeBrowser(t *testing.T, hub *ws.Hub) *fakeBrowser {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeBrowserWS))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial fake browser: %v", err)
	}
	b := &fakeBrowser{hub: hub, server: server, conn: conn, received: make(chan wsEnvelope, 32)}
	go b.readLoop()
	b.waitConnected(t)
	return b
}

func (b *fakeBrowser) readLoop() {
	for {
		_, raw, err := b.conn.ReadMessage()
		if err != nil {
			return
		}
		var env wsEnvelope
		if json.Unmarshal(raw, &env) == nil {
			b.received <- env
		}
	}
}

// waitConnected polls by broadcasting a harmless probe until this browser's
// own read loop observes it, proving ServeBrowserWS has finished registering
// the connection in hub.browsers. Same bounded-poll-for-connection-readiness
// pattern as waitForAgentConnected — not a poll for business-logic state.
func (b *fakeBrowser) waitConnected(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.hub.BroadcastBrowsers(wsProbeMessage())
		select {
		case env := <-b.received:
			if env.Type == "__test_probe__" {
				return
			}
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("fake browser never showed as connected")
}

func (b *fakeBrowser) WaitForMessage(t *testing.T, timeout time.Duration) wsEnvelope {
	t.Helper()
	select {
	case env := <-b.received:
		if env.Type == "__test_probe__" {
			return b.WaitForMessage(t, timeout)
		}
		return env
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a WebSocket message")
		return wsEnvelope{}
	}
}

func (b *fakeBrowser) Disconnect(t *testing.T) {
	t.Helper()
	_ = b.conn.Close()
	b.server.Close()
}

// Reconnect re-dials against hub, replacing this fakeBrowser's connection and
// read loop in place.
func (b *fakeBrowser) Reconnect(t *testing.T, hub *ws.Hub) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeBrowserWS))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("reconnect fake browser: %v", err)
	}
	b.hub = hub
	b.server = server
	b.conn = conn
	b.received = make(chan wsEnvelope, 32)
	go b.readLoop()
	b.waitConnected(t)
}

func TestFakeBrowser_ConnectReceiveDisconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	hub := ws.NewHub()
	browser := startFakeBrowser(t, hub)

	hub.BroadcastBrowsers(models.WSMessage{Type: "hello"})
	env := browser.WaitForMessage(t, 2*time.Second)
	if env.Type != "hello" {
		t.Fatalf("received type = %q, want hello", env.Type)
	}

	browser.Disconnect(t)

	browser.Reconnect(t, hub)
	hub.BroadcastBrowsers(models.WSMessage{Type: "hello-again"})
	env2 := browser.WaitForMessage(t, 2*time.Second)
	if env2.Type != "hello-again" {
		t.Fatalf("received type = %q, want hello-again", env2.Type)
	}
}
```

- [ ] **Step 2: Build and run the self-test**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestFakeBrowser_ConnectReceiveDisconnect -v`
Expected: `PASS` — confirms the fake-browser helper actually round-trips a broadcast message before any other task depends on it.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/result_ingestion_helpers_test.go
git commit -m "$(cat <<'EOF'
test(api): add Phase 3b.2 result-ingestion test infrastructure

MAC signing helper, request builders, a seedRun fixture, and a
fake-browser WS client mirroring 3b.1's fake-agent helper.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 2: MAC / Tamper-Detection Matrix

**Files:**
- Create: `orchestrator/internal/api/result_mac_test.go`

**Interfaces:**
- Consumes: everything from Task 1 (`signResultMAC`, `submitResultReq`, `validSubmitResultReq`, `rawResultBody`, `seedRun`), plus `sharedDB`, `New`, `ws.NewHub`, `scenario.NewEngine`, `scenario.RawRunResult`, `scenario.ExecResult`.

- [ ] **Step 1: Write the MAC matrix test**

```go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSubmitScenarioResult_MAC_Matrix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		seedRun(t, pool, "mac-matrix-run", "sc-mac", "agent-mac", "running")
		validBody := rawResultBody(t, scenario.RawRunResult{RunID: "mac-matrix-run", ScenarioID: "sc-mac", AgentID: "agent-mac"})
		otherBody := rawResultBody(t, scenario.RawRunResult{RunID: "mac-matrix-run", ScenarioID: "sc-mac", AgentID: "agent-mac", Partial: true})
		bodyCompact := []byte(`{"runId":"mac-matrix-run","scenarioId":"sc-mac","agentId":"agent-mac"}`)
		bodySpaced := []byte(`{"agentId": "agent-mac", "runId":  "mac-matrix-run", "scenarioId": "sc-mac"}`)

		cases := []struct {
			name       string
			secret     string // handler's configured agentSecret; "" = intentional bypass
			token      string
			mac        string
			body       []byte
			wantStatus int
		}{
			{"valid MAC accepted", "s3cr3t", "s3cr3t", signResultMAC("s3cr3t", validBody), validBody, http.StatusOK},
			{"missing MAC header rejected", "s3cr3t", "s3cr3t", "", validBody, http.StatusUnauthorized},
			{"wrong MAC rejected", "s3cr3t", "s3cr3t", strings.Repeat("0", 64), validBody, http.StatusUnauthorized},
			{"malformed hex rejected", "s3cr3t", "s3cr3t", "not-hex-garbage!!", validBody, http.StatusUnauthorized},
			{"MAC from a different secret rejected", "s3cr3t", "s3cr3t", signResultMAC("other-secret", validBody), validBody, http.StatusUnauthorized},
			{"MAC computed for a different body is rejected (tamper detection)", "s3cr3t", "s3cr3t", signResultMAC("s3cr3t", otherBody), validBody, http.StatusUnauthorized},
			{"MAC boundary is raw bytes, not parsed JSON (reordered/whitespace body rejected)", "s3cr3t", "s3cr3t", signResultMAC("s3cr3t", bodyCompact), bodySpaced, http.StatusUnauthorized},
			{"empty secret configured bypasses MAC entirely", "", "", "", validBody, http.StatusOK},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				h := New(pool, ws.NewHub(), engine, "").WithAgentSecret(tc.secret)
				req := submitResultReq(tc.token, tc.mac, tc.body)
				rec := httptest.NewRecorder()
				h.SubmitScenarioResult(rec, req)
				if rec.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d, body = %s", rec.Code, tc.wantStatus, rec.Body.String())
				}
			})
		}
	})
}

func TestSubmitScenarioResult_MAC_RejectionPrecedesMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		h := New(pool, ws.NewHub(), engine, "").WithAgentSecret("s3cr3t")
		seedRun(t, pool, "mac-guard-run", "sc-mac-guard", "agent-mac-guard", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "mac-guard-run", ScenarioID: "sc-mac-guard", AgentID: "agent-mac-guard",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: should never persist"}},
		})
		req := submitResultReq("s3cr3t", strings.Repeat("0", 64), body) // valid token, wrong MAC
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}

		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT status, completed_at FROM scenario_runs WHERE id = $1`, "mac-guard-run",
		).Scan(&status, &completedAt); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "running" || completedAt != nil {
			t.Fatalf("run was mutated despite MAC rejection: status=%q completedAt=%v", status, completedAt)
		}
	})
}
```

- [ ] **Step 2: Build and run**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestSubmitScenarioResult_MAC -v`
Expected: `PASS` for all 8 subtests of `TestSubmitScenarioResult_MAC_Matrix` and for `TestSubmitScenarioResult_MAC_RejectionPrecedesMutation`.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/result_mac_test.go
git commit -m "$(cat <<'EOF'
test(api): add SubmitScenarioResult MAC tamper-detection matrix

Locks down the X-Result-MAC trust boundary: valid/missing/wrong/
malformed/wrong-secret/tampered-body/byte-exact-boundary/empty-secret-
bypass, plus a rejection-precedes-mutation guarantee.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 3: SubmitScenarioResult — Validation, Idempotency, Interpretation

**Files:**
- Create: `orchestrator/internal/api/submit_scenario_result_test.go`

**Interfaces:**
- Consumes: Task 1 helpers, `minimalLiveScenario` (from `run_dispatch_helpers_test.go`), `models.SimulationResult`, `models.ResultPass`/`ResultFail`.
- Produces (for Task 4, appended to the same file): nothing new — Task 4 adds more test functions to this file, no shared types between them beyond what Task 1 already provides.

- [ ] **Step 1: Write the validation-gate, idempotency, and interpretation tests**

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSubmitScenarioResult_MissingRunID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body := []byte(`{"scenarioId":"s1","agentId":"a1"}`)
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestSubmitScenarioResult_MalformedJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body := []byte(`{not valid json`)
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// An unknown runId matches zero rows in the UPDATE, which pgx does not
// surface as an error, so the handler proceeds through the rest of the
// function and returns 200. This test locks down that no-op-accept behavior
// explicitly (see the design doc's scope-boundary note on this exact point).
func TestSubmitScenarioResult_UnknownRunID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body := rawResultBody(t, scenario.RawRunResult{RunID: "does-not-exist", ScenarioID: "whatever", AgentID: "whoever"})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("unknown runId: status = %d, want 200 (no-op accept), body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestSubmitScenarioResult_REPLACENotAppend(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "replace-run", "sc-missing", "agent-replace", "running")

		first := rawResultBody(t, scenario.RawRunResult{
			RunID: "replace-run", ScenarioID: "sc-missing", AgentID: "agent-replace",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: first"}},
		})
		rec1 := httptest.NewRecorder()
		h.SubmitScenarioResult(rec1, validSubmitResultReq("", first))
		if rec1.Code != http.StatusOK {
			t.Fatalf("first submit: status = %d", rec1.Code)
		}

		second := rawResultBody(t, scenario.RawRunResult{
			RunID: "replace-run", ScenarioID: "sc-missing", AgentID: "agent-replace",
			Results: []scenario.ExecResult{
				{TaskID: "t1", ExitCode: 0, Stdout: "FAIL: second-a"},
				{TaskID: "t2", ExitCode: 0, Stdout: "PASS: second-b"},
			},
		})
		rec2 := httptest.NewRecorder()
		h.SubmitScenarioResult(rec2, validSubmitResultReq("", second))
		if rec2.Code != http.StatusOK {
			t.Fatalf("second submit: status = %d", rec2.Code)
		}

		var resultsRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT results FROM scenario_runs WHERE id=$1`, "replace-run").Scan(&resultsRaw); err != nil {
			t.Fatalf("read results: %v", err)
		}
		var results []models.SimulationResult
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			t.Fatalf("decode results: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("results has %d entries, want 2 (REPLACE, not append)", len(results))
		}
		foundSecondA := false
		for _, r := range results {
			if r.Details == "second-a" {
				foundSecondA = true
			}
			if r.Details == "first" {
				t.Fatalf("results still contains the first submission's content: %+v", results)
			}
		}
		if !foundSecondA {
			t.Fatalf("results = %+v, want the second submission's content present", results)
		}
	})
}

func TestSubmitScenarioResult_LateSubmissionHealsPartialToCompleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "heal-run", "sc-heal", "agent-heal", "partial")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "heal-run", ScenarioID: "sc-heal", AgentID: "agent-heal",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: late but complete"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id=$1`, "heal-run").Scan(&status); err != nil {
			t.Fatalf("read status: %v", err)
		}
		if status != "completed" {
			t.Fatalf("status = %q, want completed (late valid submission heals a partial run)", status)
		}
	})
}

func TestSubmitScenarioResult_PartialFlag_SetsPartialStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "partial-flag-run", "sc-partial-flag", "agent-partial-flag", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "partial-flag-run", ScenarioID: "sc-partial-flag", AgentID: "agent-partial-flag", Partial: true,
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: incomplete run"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(context.Background(), `SELECT status, completed_at FROM scenario_runs WHERE id=$1`, "partial-flag-run").Scan(&status, &completedAt); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "partial" {
			t.Fatalf("status = %q, want partial", status)
		}
		if completedAt == nil {
			t.Fatal("completed_at = nil, want set even for a partial submission")
		}
	})
}

func TestSubmitScenarioResult_ResultsInterpretedViaSteps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-interp", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		seedRun(t, pool, "interp-run", sc.ID, "agent-interp", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "interp-run", ScenarioID: sc.ID, AgentID: "agent-interp",
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var resultsRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT results FROM scenario_runs WHERE id=$1`, "interp-run").Scan(&resultsRaw); err != nil {
			t.Fatalf("read results: %v", err)
		}
		var results []models.SimulationResult
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			t.Fatalf("decode results: %v", err)
		}
		if len(results) != 1 || results[0].Technique.ID != "T1059" || results[0].Result != models.ResultPass {
			t.Fatalf("results = %+v, want one T1059 pass result derived via scenario.Interpret", results)
		}
	})
}

func TestSubmitScenarioResult_ChecksTakePriorityOverResults(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "checks-run", "sc-checks", "agent-checks", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "checks-run", ScenarioID: "sc-checks", AgentID: "agent-checks",
			Results: []scenario.ExecResult{{TaskID: "should-be-ignored", ExitCode: 0, Stdout: "PASS: ignored"}},
			Checks: []scenario.SimCheckResult{{
				ID: "chk-1", TechniqueID: "T1218", TechniqueName: "Signed Binary Proxy",
				Tactic: "defense-evasion", Result: "pass", Severity: "High",
			}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var resultsRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT results FROM scenario_runs WHERE id=$1`, "checks-run").Scan(&resultsRaw); err != nil {
			t.Fatalf("read results: %v", err)
		}
		var results []models.SimulationResult
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			t.Fatalf("decode results: %v", err)
		}
		if len(results) != 1 || results[0].ID != "chk-1" || results[0].Technique.ID != "T1218" {
			t.Fatalf("results = %+v, want exactly the Checks entry (Results must be ignored when Checks is present)", results)
		}
	})
}

func TestSubmitScenarioResult_UnknownTaskIDFallsBackToCustom(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-unknown-task", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		seedRun(t, pool, "unknown-task-run", sc.ID, "agent-unknown-task", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "unknown-task-run", ScenarioID: sc.ID, AgentID: "agent-unknown-task",
			Results: []scenario.ExecResult{{TaskID: "not-in-scenario-or-step-meta", ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var resultsRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT results FROM scenario_runs WHERE id=$1`, "unknown-task-run").Scan(&resultsRaw); err != nil {
			t.Fatalf("read results: %v", err)
		}
		var results []models.SimulationResult
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			t.Fatalf("decode results: %v", err)
		}
		if len(results) != 1 || results[0].Framework != "custom" {
			t.Fatalf("results = %+v, want one result with Framework=custom fallback", results)
		}
	})
}
```

- [ ] **Step 2: Build and run**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestSubmitScenarioResult_ -v`
Expected: `PASS` for all 9 tests written so far (`MissingRunID`, `MalformedJSON`, `UnknownRunID`, `REPLACENotAppend`, `LateSubmissionHealsPartialToCompleted`, `PartialFlag_SetsPartialStatus`, `ResultsInterpretedViaSteps`, `ChecksTakePriorityOverResults`, `UnknownTaskIDFallsBackToCustom`).

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/submit_scenario_result_test.go
git commit -m "$(cat <<'EOF'
test(api): add SubmitScenarioResult validation/idempotency/interpretation tests

Payload validation gate, REPLACE-not-append idempotency, late-
submission healing, Partial-flag status transition, and the
Results-vs-Checks interpretation branch including the unknown-TaskID
fallback to framework=custom.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 4: SubmitScenarioResult — Score, Hygiene, Sync Fan-Outs, WS Broadcast

**Files:**
- Modify: `orchestrator/internal/api/submit_scenario_result_test.go` (append)

**Interfaces:**
- Consumes: Task 1 (`fakeBrowser`, `startFakeBrowser`), `run_dispatch_helpers_test.go` (`startFakeAgent`, `seedActiveAgent`, `wsEnvelope`), `Handler.dispatchRun`/`dispatchOpts` (from `handlers.go`, already used by 3b.1's tests in this package), `scenario.VariantDepthQuick`, `scenario.StepMeta`, `scenario.ScenarioCommand`, `models.MsgScenarioResult`.

- [ ] **Step 1: Append the score/hygiene/fan-out/broadcast tests**

Append to `orchestrator/internal/api/submit_scenario_result_test.go`. First, extend the import block at the top of the file to:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)
```

(Only `"fmt"` is new versus Task 3's import block.) Then append:

```go
func TestSubmitScenarioResult_ScoreComputedWhenResultsNonEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "score-run", "sc-score", "agent-score", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "score-run", ScenarioID: "sc-score", AgentID: "agent-score",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var scoreRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT score FROM scenario_runs WHERE id=$1`, "score-run").Scan(&scoreRaw); err != nil {
			t.Fatalf("read score: %v", err)
		}
		var score models.Score
		if err := json.Unmarshal(scoreRaw, &score); err != nil {
			t.Fatalf("decode score: %v", err)
		}
		if score.Trend != "Baseline" {
			t.Fatalf("trend = %q, want Baseline (no prior run)", score.Trend)
		}
		if score.TotalTechniques != 1 {
			t.Fatalf("totalTechniques = %d, want 1", score.TotalTechniques)
		}
	})
}

func TestSubmitScenarioResult_ScoreSkippedWhenResultsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "score-empty-run", "sc-score-empty", "agent-score-empty", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "score-empty-run", ScenarioID: "sc-score-empty", AgentID: "agent-score-empty",
			Partial: true, Results: []scenario.ExecResult{},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var scoreRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT score FROM scenario_runs WHERE id=$1`, "score-empty-run").Scan(&scoreRaw); err != nil {
			t.Fatalf("read score: %v", err)
		}
		if len(scoreRaw) != 0 {
			t.Fatalf("score = %s, want untouched/NULL (no results to score)", scoreRaw)
		}
	})
}

func TestSubmitScenarioResult_PrevScorePickedFromSameScenarioAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		priorScore := models.Score{Trend: "Baseline", TacticBreakdown: map[string]models.TacticScore{}, CriticalFailures: []models.CriticalFailure{}}
		priorScoreJSON, _ := json.Marshal(priorScore)
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-prev','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, completed_at, score)
			 VALUES ('prev-run','sc-prev','agent-prev','x','completed',NOW() - interval '1 hour',NOW() - interval '1 hour',$1)`,
			priorScoreJSON); err != nil {
			t.Fatalf("seed prior run: %v", err)
		}
		seedRun(t, pool, "current-run", "sc-prev", "agent-prev", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "current-run", ScenarioID: "sc-prev", AgentID: "agent-prev",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var scoreRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT score FROM scenario_runs WHERE id=$1`, "current-run").Scan(&scoreRaw); err != nil {
			t.Fatalf("read score: %v", err)
		}
		var score models.Score
		_ = json.Unmarshal(scoreRaw, &score)
		if score.Trend == "Baseline" {
			t.Fatalf("trend = Baseline, want a prior score to have been picked up (non-Baseline)")
		}
	})
}

func TestSubmitScenarioResult_PrevScoreExcludesOtherAgentsAndScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		priorScore := models.Score{Trend: "Baseline", TacticBreakdown: map[string]models.TacticScore{}, CriticalFailures: []models.CriticalFailure{}}
		priorScoreJSON, _ := json.Marshal(priorScore)
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-other','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		// Same scenario, different agent — must NOT be picked up as prevScore.
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, completed_at, score)
			 VALUES ('prev-other-agent','sc-excl','agent-other','x','completed',NOW() - interval '1 hour',NOW() - interval '1 hour',$1)`,
			priorScoreJSON); err != nil {
			t.Fatalf("seed prior run (other agent): %v", err)
		}
		seedRun(t, pool, "current-excl-run", "sc-excl", "agent-excl", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "current-excl-run", ScenarioID: "sc-excl", AgentID: "agent-excl",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var scoreRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT score FROM scenario_runs WHERE id=$1`, "current-excl-run").Scan(&scoreRaw); err != nil {
			t.Fatalf("read score: %v", err)
		}
		var score models.Score
		_ = json.Unmarshal(scoreRaw, &score)
		if score.Trend != "Baseline" {
			t.Fatalf("trend = %q, want Baseline (a different agent's prior run must not be picked up)", score.Trend)
		}
	})
}

func TestSubmitScenarioResult_HygieneScoreOrchestration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		cases := []struct {
			name        string
			verdicts    []string
			wantHygiene float64
			wantLeaked  int
		}{
			{"no cleanup verdicts at all", []string{"", ""}, 100.0, 0},
			{"all reverted", []string{"reverted", "reverted"}, 100.0, 0},
			{"one leaked of two cleanable", []string{"reverted", "leaked"}, 50.0, 1},
			{"one partial of two cleanable", []string{"reverted", "partial"}, 50.0, 1},
		}
		for i, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				h := New(pool, ws.NewHub(), engine, "")
				runID := fmt.Sprintf("hygiene-run-%d", i)
				seedRun(t, pool, runID, "sc-hygiene", "agent-hygiene", "running")

				results := make([]scenario.ExecResult, len(tc.verdicts))
				for j, v := range tc.verdicts {
					results[j] = scenario.ExecResult{TaskID: fmt.Sprintf("t%d", j), ExitCode: 0, Stdout: "PASS: ok", CleanupVerdict: v}
				}
				body := rawResultBody(t, scenario.RawRunResult{RunID: runID, ScenarioID: "sc-hygiene", AgentID: "agent-hygiene", Results: results})
				rec := httptest.NewRecorder()
				h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
				}

				var hygiene float64
				var leaked int
				if err := pool.QueryRow(context.Background(), `SELECT hygiene_score, leaked_steps FROM scenario_runs WHERE id=$1`, runID).Scan(&hygiene, &leaked); err != nil {
					t.Fatalf("read hygiene: %v", err)
				}
				if hygiene != tc.wantHygiene {
					t.Fatalf("hygiene_score = %v, want %v", hygiene, tc.wantHygiene)
				}
				if leaked != tc.wantLeaked {
					t.Fatalf("leaked_steps = %d, want %d", leaked, tc.wantLeaked)
				}
			})
		}
	})
}

func TestSubmitScenarioResult_FindingsFireOnCompletedRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-findings", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-findings"
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		seedRun(t, pool, "findings-run", sc.ID, agentID, "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "findings-run", ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "FAIL: allowed"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM findings WHERE agent_id=$1 AND technique_id='T1059'`, agentID,
		).Scan(&count); err != nil {
			t.Fatalf("count findings: %v", err)
		}
		if count == 0 {
			t.Fatal("expected a findings row for a completed run with a FAIL result, got none")
		}
	})
}

func TestSubmitScenarioResult_FindingsSkippedOnPartialRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-findings-partial", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-findings-partial"
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		seedRun(t, pool, "findings-partial-run", sc.ID, agentID, "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "findings-partial-run", ScenarioID: sc.ID, AgentID: agentID, Partial: true,
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "FAIL: allowed"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM findings WHERE agent_id=$1 AND technique_id='T1059'`, agentID,
		).Scan(&count); err != nil {
			t.Fatalf("count findings: %v", err)
		}
		if count != 0 {
			t.Fatalf("expected no findings row for a Partial run (must not heal on incomplete data), got %d", count)
		}
	})
}

func TestSubmitScenarioResult_VariantFanOutsFireForVariantRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "base-1", TechniqueID: "T1059", Framework: "custom", Command: "echo b1", Executor: "powershell"},
		}
		sc, engine := minimalLiveScenario(t, "sc-variant-fanout", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-variant-fanout"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "telemetry", VariantDepth: scenario.VariantDepthQuick})
		if err != nil || skip != "" {
			t.Fatalf("variant dispatch: skip=%q err=%v", skip, err)
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode dispatched command: %v", err)
		}

		var metaRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT step_meta FROM scenario_runs WHERE id=$1`, runID).Scan(&metaRaw); err != nil {
			t.Fatalf("read step_meta: %v", err)
		}
		var meta map[string]scenario.StepMeta
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			t.Fatalf("decode step_meta: %v", err)
		}
		var variantTaskID string
		for taskID, m := range meta {
			if m.BaseTaskID != "" {
				variantTaskID = taskID
				break
			}
		}
		if variantTaskID == "" {
			t.Fatal("expected at least one variant step in step_meta")
		}

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: runID, ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: variantTaskID, ExitCode: 0, Stdout: "PASS: blocked"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM scenario_variant_results WHERE run_id=$1`, runID,
		).Scan(&count); err != nil {
			t.Fatalf("count variant results: %v", err)
		}
		if count == 0 {
			t.Fatal("expected a scenario_variant_results row for a variant-bearing run, got none")
		}
	})
}

func TestSubmitScenarioResult_VariantFanOutsNoOpForNonVariantRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"}}
		sc, engine := minimalLiveScenario(t, "sc-no-variant-fanout", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-no-variant-fanout"
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		seedRun(t, pool, "no-variant-run", sc.ID, agentID, "running") // step_meta left at its '{}' default — no dispatch, no variant meta

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "no-variant-run", ScenarioID: sc.ID, AgentID: agentID,
			Results: []scenario.ExecResult{{TaskID: scenario.TaskID("T1059", "step-0"), ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM scenario_variant_results WHERE run_id=$1`, "no-variant-run",
		).Scan(&count); err != nil {
			t.Fatalf("count variant results: %v", err)
		}
		if count != 0 {
			t.Fatalf("expected no scenario_variant_results rows for a non-variant run, got %d", count)
		}
	})
}

func TestSubmitScenarioResult_BroadcastsToConnectedBrowser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "broadcast-run", "sc-broadcast", "agent-broadcast", "running")
		browser := startFakeBrowser(t, h.hub)
		defer browser.Disconnect(t)

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "broadcast-run", ScenarioID: "sc-broadcast", AgentID: "agent-broadcast",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := browser.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgScenarioResult {
			t.Fatalf("message type = %q, want %q", env.Type, models.MsgScenarioResult)
		}
		if env.AgentID != "agent-broadcast" {
			t.Fatalf("message agentId = %q, want agent-broadcast", env.AgentID)
		}
		var data struct {
			RunID      string `json:"runId"`
			ScenarioID string `json:"scenarioId"`
			AgentID    string `json:"agentId"`
			Status     string `json:"status"`
		}
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode broadcast data: %v", err)
		}
		if data.RunID != "broadcast-run" || data.ScenarioID != "sc-broadcast" || data.AgentID != "agent-broadcast" || data.Status != "completed" {
			t.Fatalf("broadcast data = %+v, want matching runId/scenarioId/agentId/status=completed", data)
		}
	})
}

func TestSubmitScenarioResult_NoBrowsersConnected_StillReturns200(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "no-browser-run", "sc-no-browser", "agent-no-browser", "running")

		body := rawResultBody(t, scenario.RawRunResult{
			RunID: "no-browser-run", ScenarioID: "sc-no-browser", AgentID: "agent-no-browser",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: ok"}},
		})
		rec := httptest.NewRecorder()
		h.SubmitScenarioResult(rec, validSubmitResultReq("", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Build and run**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestSubmitScenarioResult_ -v`
Expected: `PASS` for all 20 `TestSubmitScenarioResult_*` tests in the file now (9 from Task 3 + 11 from this task, counting `HygieneScoreOrchestration`'s 4 subtests as one test function).

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/submit_scenario_result_test.go
git commit -m "$(cat <<'EOF'
test(api): add SubmitScenarioResult score/hygiene/fan-out/broadcast tests

Score orchestration (computed vs skipped, prevScore scoping),
hygiene-score computation matrix, synchronous fan-out trigger
conditions for findings and variant results (fired vs skipped per the
documented rules), and the BroadcastBrowsers WS contract.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 5: ListScenarioRuns — Read-Model Contract

**Files:**
- Create: `orchestrator/internal/api/list_scenario_runs_test.go`

**Interfaces:**
- Consumes: Task 1's `seedRun`, `sharedDB`, `New`, `ws.NewHub`, `scenario.NewEngine`, `models.Score`, `models.TacticScore`, `models.CriticalFailure`.

- [ ] **Step 1: Write the read-model contract tests**

```go
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestListScenarioRuns_NoFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "list-run-1", "sc-list", "agent-list-1", "completed")
		seedRun(t, pool, "list-run-2", "sc-list", "agent-list-2", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 2 {
			t.Fatalf("runs = %d, want 2", len(runs))
		}
	})
}

func TestListScenarioRuns_Filters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRun(t, pool, "filt-run-a", "sc-filt-1", "agent-filt-1", "completed")
		seedRun(t, pool, "filt-run-b", "sc-filt-2", "agent-filt-1", "completed")
		seedRun(t, pool, "filt-run-c", "sc-filt-1", "agent-filt-2", "completed")

		cases := []struct {
			name       string
			agentID    string
			scenarioID string
			wantRunIDs []string
		}{
			{"by agentId", "agent-filt-1", "", []string{"filt-run-a", "filt-run-b"}},
			{"by scenarioId", "", "sc-filt-1", []string{"filt-run-a", "filt-run-c"}},
			{"by both", "agent-filt-1", "sc-filt-1", []string{"filt-run-a"}},
			{"matches neither", "no-such-agent", "no-such-scenario", nil},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				url := "/api/scenarios/runs?agentId=" + tc.agentID + "&scenarioId=" + tc.scenarioID
				rec := httptest.NewRecorder()
				h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, url, nil))
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
				}
				var raw []any
				if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
					t.Fatalf("decode (want a JSON array, possibly empty, never null): %v — body = %s", err, rec.Body.String())
				}
				var runs []map[string]any
				for _, item := range raw {
					runs = append(runs, item.(map[string]any))
				}
				if len(runs) != len(tc.wantRunIDs) {
					t.Fatalf("got %d runs, want %d (%+v)", len(runs), len(tc.wantRunIDs), runs)
				}
				got := map[string]bool{}
				for _, r := range runs {
					got[r["id"].(string)] = true
				}
				for _, id := range tc.wantRunIDs {
					if !got[id] {
						t.Fatalf("expected run %q in response, runs = %+v", id, runs)
					}
				}
			})
		}
	})
}

func TestListScenarioRuns_OrderedByStartedAtDesc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-order','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		base := time.Now().Add(-1 * time.Hour)
		for i, id := range []string{"order-run-oldest", "order-run-middle", "order-run-newest"} {
			if _, err := pool.Exec(context.Background(),
				`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
				 VALUES ($1,'sc-order','agent-order','x','completed',$2)`,
				id, base.Add(time.Duration(i)*time.Minute)); err != nil {
				t.Fatalf("seed run %s: %v", id, err)
			}
		}

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-order", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 3 {
			t.Fatalf("runs = %d, want 3", len(runs))
		}
		wantOrder := []string{"order-run-newest", "order-run-middle", "order-run-oldest"}
		for i, want := range wantOrder {
			if runs[i]["id"] != want {
				t.Fatalf("runs[%d].id = %v, want %s (DESC by started_at)", i, runs[i]["id"], want)
			}
		}
	})
}

func TestListScenarioRuns_LimitOneHundred(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-limit','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		base := time.Now().Add(-200 * time.Minute)
		for i := 0; i < 105; i++ {
			if _, err := pool.Exec(context.Background(),
				`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
				 VALUES ($1,'sc-limit','agent-limit','x','completed',$2)`,
				fmt.Sprintf("limit-run-%03d", i), base.Add(time.Duration(i)*time.Minute)); err != nil {
				t.Fatalf("seed run %d: %v", i, err)
			}
		}

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-limit", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 100 {
			t.Fatalf("runs = %d, want exactly 100", len(runs))
		}
		if runs[0]["id"] != "limit-run-104" {
			t.Fatalf("runs[0].id = %v, want the most recent (limit-run-104)", runs[0]["id"])
		}
	})
}

func TestListScenarioRuns_DetectedTechsProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-det','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		detJSON := []byte(`{"techniques":[{"techniqueId":"T1059","verdict":"detected"}]}`)
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, detection_summary)
			 VALUES ('det-run','sc-det','agent-det','x','completed',NOW(),$1)`, detJSON); err != nil {
			t.Fatalf("seed run with detection_summary: %v", err)
		}
		seedRun(t, pool, "no-det-run", "sc-det", "agent-det", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-det", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var withDet, withoutDet map[string]any
		for _, r := range runs {
			if r["id"] == "det-run" {
				withDet = r
			}
			if r["id"] == "no-det-run" {
				withoutDet = r
			}
		}
		if withDet == nil || withoutDet == nil {
			t.Fatalf("expected both seeded runs in response, got %+v", runs)
		}
		dt, ok := withDet["detectedTechs"].(map[string]any)
		if !ok || dt["T1059"] != true {
			t.Fatalf("det-run detectedTechs = %v, want {T1059:true}", withDet["detectedTechs"])
		}
		if _, present := withoutDet["detectedTechs"]; present {
			t.Fatalf("no-det-run unexpectedly has detectedTechs: %v", withoutDet["detectedTechs"])
		}
	})
}

func TestListScenarioRuns_ProgressProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-prog','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, steps_total, steps_done)
			 VALUES ('prog-run','sc-prog','agent-prog','x','running',NOW(),5,2)`); err != nil {
			t.Fatalf("seed run with progress: %v", err)
		}
		seedRun(t, pool, "no-prog-run", "sc-prog", "agent-prog", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-prog", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var withProg, withoutProg map[string]any
		for _, r := range runs {
			if r["id"] == "prog-run" {
				withProg = r
			}
			if r["id"] == "no-prog-run" {
				withoutProg = r
			}
		}
		if withProg == nil || withoutProg == nil {
			t.Fatalf("expected both seeded runs, got %+v", runs)
		}
		if withProg["progress"] == nil {
			t.Fatal("prog-run: expected a populated progress field")
		}
		if withoutProg["progress"] != nil {
			t.Fatalf("no-prog-run: expected omitted progress, got %v", withoutProg["progress"])
		}
	})
}

func TestListScenarioRuns_ScoreProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-score-proj','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		scoreJSON, _ := json.Marshal(models.Score{
			Trend: "Improving", PreventionScore: 75.5,
			TacticBreakdown: map[string]models.TacticScore{}, CriticalFailures: []models.CriticalFailure{},
		})
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, score)
			 VALUES ('score-proj-run','sc-score-proj','agent-score-proj','x','completed',NOW(),$1)`, scoreJSON); err != nil {
			t.Fatalf("seed run with score: %v", err)
		}
		seedRun(t, pool, "null-score-run", "sc-score-proj", "agent-score-proj", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-score-proj", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var withScore, withoutScore map[string]any
		for _, r := range runs {
			if r["id"] == "score-proj-run" {
				withScore = r
			}
			if r["id"] == "null-score-run" {
				withoutScore = r
			}
		}
		if withScore == nil || withoutScore == nil {
			t.Fatalf("expected both seeded runs, got %+v", runs)
		}
		sc, ok := withScore["score"].(map[string]any)
		if !ok || sc["trend"] != "Improving" {
			t.Fatalf("score-proj-run score = %v, want trend=Improving", withScore["score"])
		}
		if withoutScore["score"] != nil {
			t.Fatalf("null-score-run: expected nil score, got %v", withoutScore["score"])
		}
	})
}

func TestListScenarioRuns_MalformedResultsJSON_DegradesGracefully(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-malformed','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		// Valid JSON, wrong shape for []models.SimulationResult (object instead of array).
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, results)
			 VALUES ('malformed-run','sc-malformed','agent-malformed','x','completed',NOW(),'{"not":"an array"}'::jsonb)`); err != nil {
			t.Fatalf("seed run with malformed results: %v", err)
		}

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-malformed", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (must degrade gracefully, not 500), body = %s", rec.Code, rec.Body.String())
		}
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 1 || runs[0]["id"] != "malformed-run" {
			t.Fatalf("runs = %+v, want exactly one run with id=malformed-run present despite the malformed results blob", runs)
		}
	})
}

func TestListScenarioRuns_DBError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		closedPool, err := pgxpool.New(context.Background(), sharedDB.Pool.Config().ConnString())
		if err != nil {
			t.Fatalf("new pool: %v", err)
		}
		closedPool.Close()
		h := New(closedPool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500, body = %s", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Build and run**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestListScenarioRuns_ -v`
Expected: `PASS` for all 9 test functions (`NoFilters`, `Filters` with its 4 subtests, `OrderedByStartedAtDesc`, `LimitOneHundred`, `DetectedTechsProjection`, `ProgressProjection`, `ScoreProjection`, `MalformedResultsJSON_DegradesGracefully`, `DBError`).

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/list_scenario_runs_test.go
git commit -m "$(cat <<'EOF'
test(api): add ListScenarioRuns read-model contract tests

Filter combinations, DESC ordering, the 100-row LIMIT, detectedTechs/
progress/score projection correctness, graceful degradation on a
malformed results blob, and the closed-pool 500 path.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 6: CancelRun — State Machine

**Files:**
- Create: `orchestrator/internal/api/cancel_run_test.go`

**Interfaces:**
- Consumes: Task 1's `seedRun`, `withURLParam` (from `event_handlers_test.go`), `startFakeAgent`/`wsEnvelope` (from `run_dispatch_helpers_test.go`), `models.MsgCommandCancel`.

- [ ] **Step 1: Write the state-machine tests**

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func cancelRunReq(runID string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/"+runID+"/cancel", nil)
	return withURLParam(req, "runId", runID)
}

func TestCancelRun_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.CancelRun(rec, cancelRunReq("no-such-run"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestCancelRun_TerminalStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		for _, status := range []string{"completed", "partial", "failed"} {
			t.Run(status, func(t *testing.T) {
				runID := "cancel-terminal-" + status
				seedRun(t, pool, runID, "sc-cancel-terminal", "agent-cancel-terminal-"+status, status)

				rec := httptest.NewRecorder()
				h.CancelRun(rec, cancelRunReq(runID))
				if rec.Code != http.StatusConflict {
					t.Fatalf("status=%s: response code = %d, want 409", status, rec.Code)
				}

				var gotStatus string
				if err := pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id=$1`, runID).Scan(&gotStatus); err != nil {
					t.Fatalf("read run: %v", err)
				}
				if gotStatus != status {
					t.Fatalf("run status = %q, want unchanged %q", gotStatus, status)
				}
			})
		}
	})
}

func TestCancelRun_Running_AgentOnline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		agentID := "agent-cancel-online"
		runID := "cancel-online-run"
		seedRun(t, pool, runID, "sc-cancel-online", agentID, "running")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.CancelRun(rec, cancelRunReq(runID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp["status"] != "cancelling" {
			t.Fatalf("resp = %+v, want status=cancelling", resp)
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandCancel {
			t.Fatalf("message type = %q, want %q", env.Type, models.MsgCommandCancel)
		}
		var data map[string]string
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode command data: %v", err)
		}
		if data["runId"] != runID {
			t.Fatalf("command data = %+v, want runId=%s", data, runID)
		}

		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id=$1`, runID).Scan(&status); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "running" {
			t.Fatalf("run status = %q, want still running (agent will report back)", status)
		}
	})
}

func TestCancelRun_Running_AgentOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		agentID := "agent-cancel-offline"
		runID := "cancel-offline-run"
		seedRun(t, pool, runID, "sc-cancel-offline", agentID, "running")

		rec := httptest.NewRecorder()
		h.CancelRun(rec, cancelRunReq(runID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp["status"] != "partial" {
			t.Fatalf("resp = %+v, want status=partial", resp)
		}

		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(context.Background(), `SELECT status, completed_at FROM scenario_runs WHERE id=$1`, runID).Scan(&status, &completedAt); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "partial" {
			t.Fatalf("run status = %q, want partial", status)
		}
		if completedAt == nil {
			t.Fatal("completed_at = nil, want set")
		}
	})
}
```

- [ ] **Step 2: Build and run**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestCancelRun_ -v`
Expected: `PASS` for `NotFound`, `TerminalStatus` (3 subtests), `Running_AgentOnline`, `Running_AgentOffline`.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/api/cancel_run_test.go
git commit -m "$(cat <<'EOF'
test(api): add CancelRun state-machine tests

Not-found, every terminal status (409, no mutation), the online-agent
cancelling path with the WS command contract, and the offline-agent
partial-fallback path.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
git push
```

---

### Task 7: Final Validation and Memory Update

**Files:** None created — verification and memory-file updates only.

- [ ] **Step 1: Full build and vet**

Run: `cd orchestrator && go build ./... && go vet ./...`
Expected: clean, no output.

- [ ] **Step 2: staticcheck**

Run: `cd orchestrator && staticcheck ./...`
Expected: clean, no output. If any new helper (e.g. `fakeBrowser.Reconnect`, if unused by any test written above) is flagged U1000, that's expected only if genuinely unused — check whether `TestFakeBrowser_ConnectReceiveDisconnect` (Task 1) already exercises it before treating it as a real finding.

- [ ] **Step 3: gofmt check on every new/changed file**

Run:
```bash
cd orchestrator
gofmt -l internal/api/result_ingestion_helpers_test.go internal/api/result_mac_test.go internal/api/submit_scenario_result_test.go internal/api/list_scenario_runs_test.go internal/api/cancel_run_test.go
```
Expected: empty output (no files listed = all clean).

- [ ] **Step 4: Full test suite**

Run: `cd orchestrator && go test ./...`
Expected: all packages `ok`, including `internal/api` and `internal/ws`.

- [ ] **Step 5: Stress run for determinism**

Run: `cd orchestrator && go test ./internal/api/... -count=10`
Expected: `ok` on every iteration. This package now includes real WebSocket dial/handshake code (fake agent + fake browser) in many of these new tests — confirm no flakiness before calling the phase done, per this session's established bar.

- [ ] **Step 6: Coverage review of the in-scope symbols**

Run:
```bash
cd orchestrator
go test ./internal/api/... -coverprofile=/tmp/3b2-cov.out -covermode=atomic
go tool cover -func=/tmp/3b2-cov.out | grep -E "SubmitScenarioResult|ListScenarioRuns|CancelRun|verifyResultMAC"
```
Expected: review the printed percentages for these four symbols. Per this session's established precedent (Phases 3a/3c/3b.1), close gaps that are genuine in-scope authorization/validation branches; don't chase DB-fault branches that would need fault injection beyond the closed-pool pattern already used. Delete `/tmp/3b2-cov.out` when done (or the Windows-appropriate temp path if `/tmp` isn't writable in this shell — use the scratchpad directory instead).

- [ ] **Step 7: Update memory**

Update `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_test_generation_phase0.md`:
- Update the `description` frontmatter to include "3b.2 (result ingestion)" in the DONE list and remove it from "not started."
- Add a "Phase 3b.2 DONE" section summarizing: files added, the MAC tamper-detection matrix, the black-boxed-fan-out scope decision (and the mid-planning correction dropping the `CancelRun` audit-log test for the same async reason), the fake-browser WS helper, and coverage results.
- Update the "Not started" list to remove 3b.2 and confirm 3b.3 (Scenario Authoring) is next.

Update `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\MEMORY.md`:
- Update the `project_test_generation_phase0.md` index line to read: `- [Test Generation Phases 0-3b.2](project_test_generation_phase0.md) — Phase 0-2 + 3a + 3c + 3b.1 + 3b.2 (result ingestion) DONE; 3b.3 Scenario Authoring next`

- [ ] **Step 8: Report completion to the user**

Summarize: files added, test counts, coverage numbers for the four in-scope symbols, confirmation that no production-code bugs were found this phase (contrast with 3b.1's two), and that 3b.3 (Scenario Authoring — CRUD) is the next and final leg of Phase 3b per the user's original risk-based ordering, awaiting their explicit go-ahead.
