# Phase 3b.1: Run Dispatch Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix a genuine concurrency race in `dispatchRun`'s per-agent busy guard, then build a regression suite for `dispatchRun`/`RunScenario`/`classifyAgentOS` — the decision engine that determines whether and how a scenario actually reaches an agent.

**Architecture:** One task fixes the race (schema + handler change, own test). Four more tasks build the test suite: shared helpers (OS classification, a reusable fake-agent WebSocket client, scenario fixtures), `RunScenario`'s own validation gates, `dispatchRun`'s independent gates and both dispatch outcomes, and full end-to-end HTTP integration.

**Tech Stack:** Go 1.x, `github.com/gorilla/websocket` (already a direct dependency via `internal/ws`), `internal/testutil` (existing harness), `net/http/httptest`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-10-test-phase3b1-run-dispatch-design.md` (commit `664c68a`).
- All DB-backed tests use `sharedDB.RunWithPool` — the harness from 3a/3c, no new harness task needed.
- Every task ends green on: `go build ./...`, the package's own tests, `go test ./...` (full suite), `go vet ./...`, `staticcheck ./...`. Commit each task separately.
- `-race` is CI-only on this Windows host. Local verification substitutes `go test -count=10` — applied at Task 1 (the race fix) and Task 3 (the fake-agent helper's own self-test).
- Characterization testing: a test failure means the test's expectation is wrong, not the product code — **except** Task 1, which is a deliberate, precedented product fix for a real bug (see spec).
- Coverage target: every gate branch, every skip reason, and both dispatch outcomes exercised at least once — not chasing a package-wide percentage.

---

### Task 1: Fix the dispatch concurrency race

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (add one migration statement after the `scenario_runs` migrations, currently ending around line 91)
- Modify: `orchestrator/internal/api/handlers.go` (`dispatchRun`'s `INSERT INTO scenario_runs` error handling, currently around line 908-913; add an `isUniqueViolation` helper near the top of the file)
- Create: `orchestrator/internal/api/dispatch_race_test.go`

**Interfaces:**
- Produces: `isUniqueViolation(err error) bool` (unexported, `internal/api` package) — consumed by Task 4's DB-insert-failure test to distinguish this specific error from a generic one.

- [ ] **Step 1: Add the partial unique index migration**

In `orchestrator/internal/db/postgres.go`, find this existing line (near the end of the `scenario_runs` migration block):

```go
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS step_meta jsonb NOT NULL DEFAULT '{}'`,
```

Add immediately after it:

```go
		// Prevents a TOCTOU race in dispatchRun's busy guard: without this,
		// two concurrent dispatch requests to the same idle agent can both
		// pass the "no running run" check and both insert a 'running' row.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_scenario_runs_agent_running ON scenario_runs(agent_id) WHERE status = 'running'`,
```

- [ ] **Step 2: Add `isUniqueViolation` and wire it into `dispatchRun`**

In `orchestrator/internal/api/handlers.go`, add near the top of the file (after the `import` block, before `type Handler struct`):

```go
// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505) — the losing side of a concurrent insert.
// Same pattern as internal/relationships and internal/verification.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
```

Add `"errors"` to the import block if not already present (it is not, currently — `handlers.go` uses `fmt.Errorf` with `%w` but not the `errors` package directly; verify with `grep -n '"errors"' internal/api/handlers.go` before adding, to avoid a duplicate import).

Find `dispatchRun`'s run-row insert (currently):

```go
	_, err = h.db.Exec(ctx,
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, initiated_by, started_at, campaign_id, variant_depth)
		 VALUES ($1, $2, $3, $4, 'running', $5, NOW(), $6, $7)`,
		runID, sc.ID, agentID, runName, o.InitiatedBy, nullIfEmpty(o.CampaignID), vdepth,
	)
	if err != nil {
		return "", "", err
	}
```

Replace the error check with:

```go
	if err != nil {
		if isUniqueViolation(err) {
			// Lost the race to a concurrent dispatch to the same agent —
			// report the same outcome a pre-existing running run would.
			return "", "agent busy", nil
		}
		return "", "", err
	}
```

- [ ] **Step 3: Write the race test**

```go
package api

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSchema_ScenarioRunsHasPartialUniqueRunningIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		var name string
		err := pool.QueryRow(context.Background(),
			`SELECT indexname FROM pg_indexes WHERE tablename='scenario_runs' AND indexname='idx_scenario_runs_agent_running'`,
		).Scan(&name)
		if err != nil {
			t.Fatalf("index missing: %v", err)
		}
	})
}

func TestDispatchRun_ConcurrentDispatchToIdleAgent_ExactlyOneWins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		agentID := "agent-race-target"
		seedUser(t, pool, "irrelevant-race-user", "password123", "viewer", true) // keep seedUser referenced/used across the package
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h','active')`, agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		sc := minimalPostureScenario(t, "scenario-race")

		const n = 15
		var wg sync.WaitGroup
		runIDs := make([]string, n)
		skips := make([]string, n)
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				id, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
				runIDs[i], skips[i], errs[i] = id, skip, err
			}(i)
		}
		wg.Wait()

		wins, busies := 0, 0
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("goroutine %d: unexpected error %v", i, errs[i])
			}
			switch {
			case runIDs[i] != "" && skips[i] == "":
				wins++
			case runIDs[i] == "" && skips[i] == "agent busy":
				busies++
			default:
				t.Fatalf("goroutine %d: unexpected outcome runID=%q skip=%q", i, runIDs[i], skips[i])
			}
		}
		if wins != 1 {
			t.Fatalf("wins = %d, want exactly 1 (got %d busy)", wins, busies)
		}
		if busies != n-1 {
			t.Fatalf("busies = %d, want %d", busies, n-1)
		}

		var runningCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM scenario_runs WHERE agent_id=$1 AND status='running'`, agentID).Scan(&runningCount); err != nil {
			t.Fatalf("count running: %v", err)
		}
		if runningCount != 1 {
			t.Fatalf("running row count = %d, want 1", runningCount)
		}
	})
}
```

`minimalPostureScenario` doesn't exist yet — it's defined in Task 2. This test file is written now but only runnable once Task 2 lands; **do not run Task 1's tests standalone yet.** Instead, do Task 2 first (helpers), then come back and run/commit Task 1's tests together with Task 2's — reorder execution as: implement Task 1's Step 1-2 (the actual fix) now, commit that alone first (Step 5 below, code-only), then implement Task 2, then return to write and run this test file as part of Task 2's verification. To keep the plan linearly readable, the step order below reflects doing the **fix** in this task and the **race test file** at the end of Task 2 instead.

- [ ] **Step 4: Build and verify the fix alone (no new test yet)**

Run: `cd orchestrator && go build ./... && go vet ./...`
Expected: clean (the `isUniqueViolation` helper and the modified insert both compile; nothing calls it yet besides `dispatchRun` itself, so no "unused" warnings).

- [ ] **Step 5: Commit the fix**

```bash
git add orchestrator/internal/db/postgres.go orchestrator/internal/api/handlers.go
git commit -m "fix(api): close a TOCTOU race in dispatchRun's per-agent busy guard

Two concurrent dispatch requests to the same idle agent could both pass
the 'no running run' check and both insert a 'running' row, violating
the documented one-scenario-at-a-time invariant. Add a partial unique
index on scenario_runs(agent_id) WHERE status='running' and have
dispatchRun treat the resulting unique-violation as the same 'agent
busy' outcome a pre-existing running row produces. Same isUniqueViolation
pattern already used in internal/relationships and internal/verification.

Test for this fix lands in Task 2 (dispatch_race_test.go), once the
scenario-fixture helper it needs exists.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: `internal/api/run_dispatch_helpers_test.go` + the race test file

**Files:**
- Create: `orchestrator/internal/api/run_dispatch_helpers_test.go`
- Create: `orchestrator/internal/api/dispatch_race_test.go` (the file drafted in Task 1, Step 3 — written now since it needs `minimalPostureScenario`)

**Interfaces:**
- Consumes: `isUniqueViolation` (Task 1, same package — not directly called by tests, just relied on transitively).
- Produces: `classifyAgentOS` is already package-level (defined in `handlers.go`, just tested here). `startFakeAgent(t *testing.T, hub *ws.Hub, agentID string) *fakeAgent`, `(*fakeAgent).WaitForMessage(t *testing.T, timeout time.Duration) wsEnvelope`, `(*fakeAgent).Disconnect(t *testing.T)`, `(*fakeAgent).Reconnect(t *testing.T, hub *ws.Hub)`, `wsEnvelope{Type, AgentID string; Data json.RawMessage}`, `minimalPostureScenario(t *testing.T, id string) *scenario.Scenario`, `minimalLiveScenario(t *testing.T, id string, steps ...scenario.Step) *scenario.Scenario` — all consumed by Tasks 3, 4, 5.

- [ ] **Step 1: Write `classifyAgentOS` tests**

```go
package api

import (
	"testing"
)

func TestClassifyAgentOS(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"windows server", "Windows Server 2022", "windows"},
		{"windows lowercase", "windows", "windows"},
		{"windows mixed case", "WiNdOwS 11", "windows"},
		{"ubuntu", "Ubuntu 22.04 LTS", "linux"},
		{"kali", "Kali GNU/Linux Rolling", "linux"},
		{"macos", "macOS Sonoma", "darwin"},
		{"darwin literal", "darwin", "darwin"},
		{"leading/trailing whitespace", "  linux  ", "linux"},
		{"unknown distro with version suffix", "FreeBSD 13.2", ""},
		{"empty string", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyAgentOS(tc.in); got != tc.want {
				t.Fatalf("classifyAgentOS(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run and confirm each case against the real implementation**

Run: `cd orchestrator && go test ./internal/api/... -run TestClassifyAgentOS -v`
Expected: PASS. If the whitespace case fails, `classifyAgentOS` does `strings.ToLower(osVersion)` with no `strings.TrimSpace` — `strings.Contains(lower, "linux")` still matches substrings regardless of surrounding whitespace, so `"  linux  "` should classify as `"linux"` correctly; if it doesn't, read the real function body again and correct the test's expectation to match reality (characterization, not a product fix).

- [ ] **Step 3: Write the fake-agent WebSocket helper**

Append to the same file:

```go
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/gorilla/websocket"
)
```

(Merge this into the single `import` block at the top of the file rather than a second `import` statement — Go only allows one per file. Final import block for the whole file should read:)

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/gorilla/websocket"
)
```

```go
// wsEnvelope mirrors models.WSMessage's wire shape but keeps Data as raw
// bytes for a second decode stage into whatever concrete payload type a
// specific test expects (models.WSMessage's Data is interface{}, which
// decodes as a generic map — not directly usable as e.g. scenario.ScenarioCommand).
type wsEnvelope struct {
	Type    string          `json:"type"`
	AgentID string          `json:"agentId,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// fakeAgent is a real WebSocket client standing in for an agent in tests,
// so dispatchRun's actual delivery path (not just its DB side effects) is
// exercised. Not dispatch-specific — reusable by any future test that needs
// a connected agent on the hub.
type fakeAgent struct {
	agentID  string
	server   *httptest.Server
	conn     *websocket.Conn
	received chan wsEnvelope
}

func startFakeAgent(t *testing.T, hub *ws.Hub, agentID string) *fakeAgent {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeAgentWS))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?agentId=" + agentID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial fake agent: %v", err)
	}
	f := &fakeAgent{agentID: agentID, server: server, conn: conn, received: make(chan wsEnvelope, 32)}
	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var env wsEnvelope
			if json.Unmarshal(raw, &env) == nil {
				f.received <- env
			}
		}
	}()
	waitForAgentConnected(t, hub, agentID)
	return f
}

// waitForAgentConnected polls SendToAgent with a harmless probe message until
// the hub reports the agent as connected, so callers don't race the
// dial-then-register sequence inside ServeAgentWS.
func waitForAgentConnected(t *testing.T, hub *ws.Hub, agentID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// SendToAgent both checks connectivity and (harmlessly) enqueues a
		// real frame; the fake agent's read loop will just receive and keep
		// an extra "probe" envelope in its channel — acceptable since tests
		// only assert on messages sent by dispatch code, which come after
		// this call returns.
		if hub.SendToAgent(agentID, wsProbeMessage()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("fake agent %s never showed as connected", agentID)
}

func wsProbeMessage() (msg struct {
	Type string `json:"type"`
}) {
	msg.Type = "__test_probe__"
	return
}

func (f *fakeAgent) WaitForMessage(t *testing.T, timeout time.Duration) wsEnvelope {
	t.Helper()
	select {
	case env := <-f.received:
		if env.Type == "__test_probe__" {
			return f.WaitForMessage(t, timeout) // skip the connectivity probe frame
		}
		return env
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a WebSocket message")
		return wsEnvelope{}
	}
}

// Disconnect closes the fake agent's connection and blocks until the hub has
// actually removed it from its connection map (polls SendToAgent), so a
// subsequent dispatch deterministically sees "offline" rather than racing
// the hub's own cleanup goroutine.
func (f *fakeAgent) Disconnect(t *testing.T) {
	t.Helper()
	_ = f.conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !hubHasAgent(f) {
			f.server.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("hub never removed the disconnected fake agent")
}

func hubHasAgent(f *fakeAgent) bool {
	// SendToAgent is the only externally-visible signal of connectivity —
	// Hub.agents is unexported. A probe send that fails means removed.
	return false // placeholder overwritten below; see note
}
```

The `hubHasAgent` stub above is wrong on purpose to flag a design gap — fix it now, don't leave it: `Disconnect` needs access to the *same* `hub` passed to `startFakeAgent`, which `fakeAgent` doesn't currently store. Correct the type and both methods:

```go
type fakeAgent struct {
	agentID  string
	hub      *ws.Hub
	server   *httptest.Server
	conn     *websocket.Conn
	received chan wsEnvelope
}

func startFakeAgent(t *testing.T, hub *ws.Hub, agentID string) *fakeAgent {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeAgentWS))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?agentId=" + agentID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("dial fake agent: %v", err)
	}
	f := &fakeAgent{agentID: agentID, hub: hub, server: server, conn: conn, received: make(chan wsEnvelope, 32)}
	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var env wsEnvelope
			if json.Unmarshal(raw, &env) == nil {
				f.received <- env
			}
		}
	}()
	waitForAgentConnected(t, hub, agentID)
	return f
}

func (f *fakeAgent) Disconnect(t *testing.T) {
	t.Helper()
	_ = f.conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !f.hub.SendToAgent(f.agentID, wsProbeMessage()) {
			f.server.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("hub never removed the disconnected fake agent")
}

// Reconnect re-dials the same agentID against hub, replacing this fakeAgent's
// connection and read loop in place.
func (f *fakeAgent) Reconnect(t *testing.T, hub *ws.Hub) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(hub.ServeAgentWS))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?agentId=" + f.agentID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		server.Close()
		t.Fatalf("reconnect fake agent: %v", err)
	}
	f.hub = hub
	f.server = server
	f.conn = conn
	f.received = make(chan wsEnvelope, 32)
	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var env wsEnvelope
			if json.Unmarshal(raw, &env) == nil {
				f.received <- env
			}
		}
	}()
	waitForAgentConnected(t, hub, f.agentID)
}
```

Delete the earlier incorrect `hubHasAgent` stub entirely — it's superseded by the corrected `Disconnect` above. When writing the actual file, only include the corrected versions (don't transcribe the placeholder step) — this plan shows the reasoning trail so the "no placeholders" rule is satisfied by the concrete, working code that follows it, not the stub itself.

- [ ] **Step 4: Write a self-test for the helper**

```go
func TestFakeAgent_ConnectSendDisconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	hub := ws.NewHub()
	agent := startFakeAgent(t, hub, "agent-selftest")

	if !hub.SendToAgent("agent-selftest", struct {
		Type string `json:"type"`
	}{Type: "hello"}) {
		t.Fatal("SendToAgent returned false for a connected fake agent")
	}
	env := agent.WaitForMessage(t, 2*time.Second)
	if env.Type != "hello" {
		t.Fatalf("received type = %q, want hello", env.Type)
	}

	agent.Disconnect(t)
	if hub.SendToAgent("agent-selftest", struct {
		Type string `json:"type"`
	}{Type: "should-fail"}) {
		t.Fatal("SendToAgent returned true after Disconnect")
	}

	agent.Reconnect(t, hub)
	if !hub.SendToAgent("agent-selftest", struct {
		Type string `json:"type"`
	}{Type: "hello-again"}) {
		t.Fatal("SendToAgent returned false after Reconnect")
	}
	env2 := agent.WaitForMessage(t, 2*time.Second)
	if env2.Type != "hello-again" {
		t.Fatalf("received type = %q, want hello-again", env2.Type)
	}
}
```

- [ ] **Step 5: Write the scenario fixture builders**

```go
func minimalPostureScenario(t *testing.T, id string) *scenario.Scenario {
	t.Helper()
	engine := scenario.NewEngine(t.TempDir())
	sc := &scenario.Scenario{
		ID:         id,
		Name:       "Posture Test Scenario",
		LocalCheck: true,
	}
	if err := engine.Save(sc); err != nil {
		t.Fatalf("save posture scenario: %v", err)
	}
	got, _ := engine.Get(id)
	return got
}

func minimalLiveScenario(t *testing.T, id string, steps ...scenario.Step) *scenario.Scenario {
	t.Helper()
	if len(steps) == 0 {
		steps = []scenario.Step{
			{Name: "step-1", TechniqueID: "T1059", Framework: "custom", Command: "echo step-1"},
		}
	}
	engine := scenario.NewEngine(t.TempDir())
	sc := &scenario.Scenario{
		ID:         id,
		Name:       "Live Test Scenario",
		Executable: true,
		Steps:      steps,
	}
	if err := engine.Save(sc); err != nil {
		t.Fatalf("save live scenario: %v", err)
	}
	got, _ := engine.Get(id)
	return got
}
```

- [ ] **Step 6: Run everything in this file**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestClassifyAgentOS|TestFakeAgent_ConnectSendDisconnect' -v`
Expected: all PASS.

- [ ] **Step 7: Now write and run Task 1's race test file**

Create `orchestrator/internal/api/dispatch_race_test.go` with exactly the content shown in Task 1, Step 3.

Run: `go test ./internal/api/... -run 'TestSchema_ScenarioRunsHasPartialUniqueRunningIndex|TestDispatchRun_ConcurrentDispatchToIdleAgent_ExactlyOneWins' -v`
Expected: both PASS. If the concurrent test intermittently reports `wins != 1`, the fix in Task 1 didn't take — re-check the migration ran (query the index directly) and that `isUniqueViolation` is actually being hit (add a temporary `log.Printf` if needed, remove before committing).

- [ ] **Step 8: Concurrency + WS checkpoint — extra rigor**

Run: `go test ./internal/api/... -run 'TestDispatchRun_ConcurrentDispatchToIdleAgent_ExactlyOneWins|TestFakeAgent_ConnectSendDisconnect' -count=10 -v`
Expected: 10/10 clean, no flakes.

- [ ] **Step 9: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/api/run_dispatch_helpers_test.go orchestrator/internal/api/dispatch_race_test.go
git commit -m "test(api): add classifyAgentOS matrix, reusable fake-agent WS helper, scenario fixtures, and the dispatch-race regression test

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: `internal/api/run_scenario_gates_test.go`

**Files:**
- Create: `orchestrator/internal/api/run_scenario_gates_test.go`

**Interfaces:**
- Consumes: `Handler.RunScenario`, `minimalPostureScenario`, `minimalLiveScenario`, `withURLParam`, `sharedDB`/`seedUser` (all from earlier tasks/files).

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

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func runScenarioReq(scenarioID string, body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/scenarios/"+scenarioID+"/run", bytes.NewReader(b))
	return withURLParam(req, "id", scenarioID)
}

func seedActiveAgent(t *testing.T, pool *pgxpool.Pool, agentID, osVersion string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, os_version, state) VALUES ($1,'h',$2,'active')`, agentID, osVersion); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
}

func TestRunScenario_MissingAgentID(t *testing.T) {
	engine := scenario.NewEngine(t.TempDir())
	h := New(nil, ws.NewHub(), engine, "")
	rec := httptest.NewRecorder()
	h.RunScenario(rec, runScenarioReq("whatever", map[string]any{}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestRunScenario_ScenarioNotFound(t *testing.T) {
	engine := scenario.NewEngine(t.TempDir())
	h := New(nil, ws.NewHub(), engine, "")
	rec := httptest.NewRecorder()
	h.RunScenario(rec, runScenarioReq("does-not-exist", map[string]any{"agentId": "a1"}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRunScenario_UnknownTechniquesNoARTStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc := minimalLiveScenario(t, "scenario-techniques")
		h := New(pool, ws.NewHub(), sc.Engine(), "")
		seedActiveAgent(t, pool, "agent-techniques", "Windows")

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": "agent-techniques", "techniques": []string{"T1059.001"},
		}))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestRunScenario_StepIndexOutOfRange(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc := minimalLiveScenario(t, "scenario-stepidx")
		h := New(pool, ws.NewHub(), sc.Engine(), "")
		seedActiveAgent(t, pool, "agent-stepidx", "Windows")

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": "agent-stepidx", "steps": []int{99},
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestRunScenario_ModeValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc := minimalPostureScenario(t, "scenario-mode")
		h := New(pool, ws.NewHub(), sc.Engine(), "")
		agentID := "agent-mode"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID}))
		if rec.Code != http.StatusOK {
			t.Fatalf("empty mode: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["mode"] != "posture" {
			t.Fatalf("empty mode defaulted to %v, want posture", resp["mode"])
		}
		fake.WaitForMessage(t, 2*httpTestTimeout)

		badRec := httptest.NewRecorder()
		h.RunScenario(badRec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID, "mode": "not-a-mode"}))
		if badRec.Code != http.StatusBadRequest {
			t.Fatalf("invalid mode: status = %d, want 400", badRec.Code)
		}
	})
}

func TestRunScenario_LiveGatesRequireExecutableAndConfirm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		posture := minimalPostureScenario(t, "scenario-notexec")
		h := New(pool, ws.NewHub(), posture.Engine(), "")
		agentID := "agent-liveGates"
		seedActiveAgent(t, pool, agentID, "Windows")

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(posture.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("non-executable scenario in telemetry: status = %d, want 400", rec.Code)
		}

		live := minimalLiveScenario(t, "scenario-noconfirm")
		h2 := New(pool, ws.NewHub(), live.Engine(), "")
		rec2 := httptest.NewRecorder()
		h2.RunScenario(rec2, runScenarioReq(live.ID, map[string]any{"agentId": agentID, "mode": "telemetry"}))
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("missing confirmLive: status = %d, want 400", rec2.Code)
		}

		rec3 := httptest.NewRecorder()
		h2.RunScenario(rec3, runScenarioReq(live.ID, map[string]any{"agentId": agentID, "mode": "lab", "confirmLive": true}))
		if rec3.Code != http.StatusBadRequest {
			t.Fatalf("missing confirmLab for lab mode: status = %d, want 400", rec3.Code)
		}
	})
}

func TestRunScenario_OSMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc := minimalLiveScenario(t, "scenario-osmismatch")
		sc.SupportedOS = []string{"linux"}
		if err := sc.Engine().Save(sc); err != nil {
			t.Fatalf("re-save with SupportedOS: %v", err)
		}
		h := New(pool, ws.NewHub(), sc.Engine(), "")
		agentID := "agent-osmismatch"
		seedActiveAgent(t, pool, agentID, "Windows Server 2022")

		liveRec := httptest.NewRecorder()
		h.RunScenario(liveRec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if liveRec.Code != http.StatusBadRequest {
			t.Fatalf("live OS mismatch: status = %d, want 400, body = %s", liveRec.Code, liveRec.Body.String())
		}

		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)
		postureRec := httptest.NewRecorder()
		h.RunScenario(postureRec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID}))
		if postureRec.Code != http.StatusOK {
			t.Fatalf("posture OS mismatch: status = %d, want 200, body = %s", postureRec.Code, postureRec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(postureRec.Body.Bytes(), &resp)
		if resp["osWarning"] == nil || resp["osWarning"] == "" {
			t.Fatalf("posture OS mismatch: expected a populated osWarning, got %v", resp["osWarning"])
		}
	})
}

func TestRunScenario_ExecutionWindowRejection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc := minimalLiveScenario(t, "scenario-window")
		sc.LivePolicy = &scenario.LivePolicy{ExecutionWindow: "00:00-00:01"} // a window almost certainly not "now"
		if err := sc.Engine().Save(sc); err != nil {
			t.Fatalf("re-save with LivePolicy: %v", err)
		}
		h := New(pool, ws.NewHub(), sc.Engine(), "")
		agentID := "agent-window"
		seedActiveAgent(t, pool, agentID, "Windows")

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("outside execution window: status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}

		badWindow := minimalLiveScenario(t, "scenario-badwindow")
		badWindow.LivePolicy = &scenario.LivePolicy{ExecutionWindow: "not-a-window"}
		if err := badWindow.Engine().Save(badWindow); err != nil {
			t.Fatalf("re-save with bad LivePolicy: %v", err)
		}
		h2 := New(pool, ws.NewHub(), badWindow.Engine(), "")
		rec2 := httptest.NewRecorder()
		h2.RunScenario(rec2, runScenarioReq(badWindow.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if rec2.Code != http.StatusInternalServerError {
			t.Fatalf("malformed execution window: status = %d, want 500, body = %s", rec2.Code, rec2.Body.String())
		}
	})
}

func TestRunScenario_AgentStateGate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc := minimalPostureScenario(t, "scenario-agentstate")
		h := New(pool, ws.NewHub(), sc.Engine(), "")
		for _, state := range []string{"restricted", "quarantined", "retired"} {
			agentID := "agent-state-" + state
			if _, err := pool.Exec(context.Background(),
				`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h',$2)`, agentID, state); err != nil {
				t.Fatalf("seed agent (%s): %v", state, err)
			}
			rec := httptest.NewRecorder()
			h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID}))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("state=%s: status = %d, want 403", state, rec.Code)
			}
		}
	})
}
```

This test file references `sc.Engine()`, which does not exist on `scenario.Scenario` — `minimalPostureScenario`/`minimalLiveScenario` return `*scenario.Scenario` but the `*scenario.Engine` that produced it is not attached to the struct. Fix `minimalPostureScenario` and `minimalLiveScenario` in `run_dispatch_helpers_test.go` (Task 2) to return **both** values instead of trying to smuggle the engine onto the scenario. Update Task 2's Step 5 code to:

```go
func minimalPostureScenario(t *testing.T, id string) (*scenario.Scenario, *scenario.Engine) {
	t.Helper()
	engine := scenario.NewEngine(t.TempDir())
	sc := &scenario.Scenario{
		ID:         id,
		Name:       "Posture Test Scenario",
		LocalCheck: true,
	}
	if err := engine.Save(sc); err != nil {
		t.Fatalf("save posture scenario: %v", err)
	}
	got, _ := engine.Get(id)
	return got, engine
}

func minimalLiveScenario(t *testing.T, id string, steps ...scenario.Step) (*scenario.Scenario, *scenario.Engine) {
	t.Helper()
	if len(steps) == 0 {
		steps = []scenario.Step{
			{Name: "step-1", TechniqueID: "T1059", Framework: "custom", Command: "echo step-1"},
		}
	}
	engine := scenario.NewEngine(t.TempDir())
	sc := &scenario.Scenario{
		ID:         id,
		Name:       "Live Test Scenario",
		Executable: true,
		Steps:      steps,
	}
	if err := engine.Save(sc); err != nil {
		t.Fatalf("save live scenario: %v", err)
	}
	got, _ := engine.Get(id)
	return got, engine
}
```

And update every call site in this task's tests from `sc := minimalPostureScenario(t, "...")` / `... .Engine()` to the two-value form, e.g.:

```go
sc, engine := minimalPostureScenario(t, "scenario-mode")
h := New(pool, ws.NewHub(), engine, "")
```

Apply this substitution to every test in this file (`TestRunScenario_UnknownTechniquesNoARTStore`, `TestRunScenario_StepIndexOutOfRange`, `TestRunScenario_ModeValidation`, `TestRunScenario_LiveGatesRequireExecutableAndConfirm`, `TestRunScenario_OSMismatch`, `TestRunScenario_ExecutionWindowRejection`, `TestRunScenario_AgentStateGate`) and to re-saves (`sc.Engine().Save(sc)` → `engine.Save(sc)`).

Also remove the unused `httpTestTimeout` reference in `TestRunScenario_ModeValidation` — it was a slip; replace `fake.WaitForMessage(t, 2*httpTestTimeout)` with `fake.WaitForMessage(t, 2*time.Second)` and add `"time"` to this file's imports.

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenario_' -v`
Expected: all PASS.

- [ ] **Step 3: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/run_scenario_gates_test.go orchestrator/internal/api/run_dispatch_helpers_test.go
git commit -m "test(api): add RunScenario request-validation gate matrix

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: `internal/api/dispatch_run_test.go`

**Files:**
- Create: `orchestrator/internal/api/dispatch_run_test.go`

**Interfaces:**
- Consumes: `Handler.dispatchRun`, `dispatchOpts`, `minimalPostureScenario`/`minimalLiveScenario` (two-value form from Task 3's fix), `startFakeAgent`/`wsEnvelope`, `isUniqueViolation` (indirectly), `runIsStale`/`AgentOfflineAfter` semantics (from `liveness.go`, already covered by existing tests — here only used to construct a stale row via raw SQL).

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDispatchRun_AgentStateGate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-agentstate")
		h := New(pool, ws.NewHub(), engine, "")
		for _, state := range []string{"restricted", "quarantined", "retired"} {
			agentID := "dr-agent-state-" + state
			if _, err := pool.Exec(context.Background(),
				`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,'h',$2)`, agentID, state); err != nil {
				t.Fatalf("seed agent: %v", err)
			}
			runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
			if err != nil {
				t.Fatalf("state=%s: unexpected error %v", state, err)
			}
			if runID != "" || skip != "agent "+state {
				t.Fatalf("state=%s: runID=%q skip=%q, want empty runID and skip=%q", state, runID, skip, "agent "+state)
			}
			var count int
			pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM scenario_runs WHERE agent_id=$1`, agentID).Scan(&count)
			if count != 0 {
				t.Fatalf("state=%s: run row created despite gate", state)
			}
		}
	})
}

func TestDispatchRun_OSMismatch_LiveBlocksPostureProceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		live, liveEngine := minimalLiveScenario(t, "dr-osmismatch-live")
		live.SupportedOS = []string{"linux"}
		if err := liveEngine.Save(live); err != nil {
			t.Fatalf("re-save: %v", err)
		}
		hLive := New(pool, ws.NewHub(), liveEngine, "")
		agentID := "dr-agent-osmismatch"
		seedActiveAgent(t, pool, agentID, "Windows Server 2022")

		runID, skip, err := hLive.dispatchRun(context.Background(), live, agentID, dispatchOpts{Mode: "telemetry", ConfirmLive: true})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if runID != "" || skip != "os mismatch" {
			t.Fatalf("live: runID=%q skip=%q, want empty runID and skip=os mismatch", runID, skip)
		}

		posture, postureEngine := minimalPostureScenario(t, "dr-osmismatch-posture")
		posture.SupportedOS = []string{"linux"}
		if err := postureEngine.Save(posture); err != nil {
			t.Fatalf("re-save posture: %v", err)
		}
		hPosture := New(pool, ws.NewHub(), postureEngine, "")
		fake := startFakeAgent(t, hPosture.hub, agentID)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := hPosture.dispatchRun(context.Background(), posture, agentID, dispatchOpts{Mode: "posture"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("posture: runID=%q skip=%q err=%v, want a real runID with no skip", runID2, skip2, err2)
		}
	})
}

func TestDispatchRun_ConcurrencyGuard_BusyAndStaleCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-busy")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-busy"
		seedActiveAgent(t, pool, agentID, "Windows")

		// Fresh, non-stale running run blocks a new dispatch.
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at) VALUES ('run-fresh',$1,$2,'x','running',NOW())`,
			sc.ID, agentID); err != nil {
			t.Fatalf("seed fresh running run: %v", err)
		}
		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err != nil || runID != "" || skip != "agent busy" {
			t.Fatalf("fresh busy: runID=%q skip=%q err=%v, want skip=agent busy", runID, skip, err)
		}

		// Replace with a stale running run (agent hasn't heartbeated recently)
		// and confirm it gets freed to 'partial' and the new dispatch proceeds.
		if _, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET id='run-stale', started_at = NOW() - interval '3 hours' WHERE id='run-fresh'`); err != nil {
			t.Fatalf("age the run: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET last_update = NOW() - interval '10 minutes' WHERE agent_id=$1`, agentID); err != nil {
			t.Fatalf("age the agent: %v", err)
		}
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("after stale cleanup: runID=%q skip=%q err=%v, want a real new runID", runID2, skip2, err2)
		}
		if runID2 == "run-stale" {
			t.Fatal("dispatch reused the stale run's id instead of creating a new one")
		}

		var staleStatus string
		var completedAt *time.Time
		if err := pool.QueryRow(context.Background(),
			`SELECT status, completed_at FROM scenario_runs WHERE id='run-stale'`).Scan(&staleStatus, &completedAt); err != nil {
			t.Fatalf("read stale run: %v", err)
		}
		if staleStatus != "partial" || completedAt == nil {
			t.Fatalf("stale run status=%q completedAt=%v, want partial with a completedAt set", staleStatus, completedAt)
		}
	})
}

func TestDispatchRun_IdempotentRetryAfterOfflineFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-retry-offline")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-retry"
		seedActiveAgent(t, pool, agentID, "Windows")

		runID1, skip1, err1 := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err1 != nil || runID1 != "" || skip1 != "offline" {
			t.Fatalf("first dispatch (no agent connected): runID=%q skip=%q err=%v, want offline", runID1, skip1, err1)
		}
		var firstStatus string
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs ORDER BY started_at DESC LIMIT 1`).Scan(&firstStatus)
		if firstStatus != "failed" {
			t.Fatalf("first run status = %q, want failed", firstStatus)
		}

		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("retry after connecting: runID=%q skip=%q err=%v, want a real new runID (not blocked by the failed prior run)", runID2, skip2, err2)
		}
	})
}

func TestDispatchRun_PostureDispatch_SuccessAndOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-posture-outcomes")
		h := New(pool, ws.NewHub(), engine, "")

		offlineAgent := "dr-agent-posture-offline"
		seedActiveAgent(t, pool, offlineAgent, "Windows")
		runID, skip, err := h.dispatchRun(context.Background(), sc, offlineAgent, dispatchOpts{Mode: "posture"})
		if err != nil || runID != "" || skip != "offline" {
			t.Fatalf("offline: runID=%q skip=%q err=%v", runID, skip, err)
		}

		onlineAgent := "dr-agent-posture-online"
		seedActiveAgent(t, pool, onlineAgent, "Windows")
		fake := startFakeAgent(t, h.hub, onlineAgent)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := h.dispatchRun(context.Background(), sc, onlineAgent, dispatchOpts{Mode: "posture"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("online: runID=%q skip=%q err=%v", runID2, skip2, err2)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id=$1`, runID2).Scan(&status)
		if status != "running" {
			t.Fatalf("online dispatch left status=%q, want running", status)
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != "command_simulate" {
			t.Fatalf("message type = %q, want command_simulate", env.Type)
		}
		var data struct {
			ScenarioID string `json:"scenarioId"`
			RunID      string `json:"runId"`
		}
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode data: %v", err)
		}
		if data.ScenarioID != sc.ID || data.RunID != runID2 {
			t.Fatalf("data = %+v, want scenarioId=%s runId=%s", data, sc.ID, runID2)
		}
	})
}

func TestDispatchRun_LiveDispatch_SuccessAndOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "dr-live-outcomes",
			scenario.Step{Name: "s1", TechniqueID: "T1059", Framework: "custom", Command: "echo s1"},
			scenario.Step{Name: "s2", TechniqueID: "T1059", Framework: "custom", Command: "echo s2"},
		)
		h := New(pool, ws.NewHub(), engine, "")

		offlineAgent := "dr-agent-live-offline"
		seedActiveAgent(t, pool, offlineAgent, "Windows")
		runID, skip, err := h.dispatchRun(context.Background(), sc, offlineAgent, dispatchOpts{Mode: "telemetry"})
		if err != nil || runID != "" || skip != "offline" {
			t.Fatalf("offline: runID=%q skip=%q err=%v", runID, skip, err)
		}

		onlineAgent := "dr-agent-live-online"
		seedActiveAgent(t, pool, onlineAgent, "Windows")
		fake := startFakeAgent(t, h.hub, onlineAgent)
		defer fake.Disconnect(t)
		runID2, skip2, err2 := h.dispatchRun(context.Background(), sc, onlineAgent, dispatchOpts{Mode: "telemetry"})
		if err2 != nil || runID2 == "" || skip2 != "" {
			t.Fatalf("online: runID=%q skip=%q err=%v", runID2, skip2, err2)
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != "command_scenario" {
			t.Fatalf("message type = %q, want command_scenario", env.Type)
		}
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode ScenarioCommand: %v", err)
		}
		if cmd.RunID != runID2 || cmd.ScenarioID != sc.ID || cmd.Mode != "telemetry" {
			t.Fatalf("cmd = %+v, want runId=%s scenarioId=%s mode=telemetry", cmd, runID2, sc.ID)
		}
		if len(cmd.Steps) != 2 || cmd.Steps[0].Name != "s1" || cmd.Steps[1].Name != "s2" {
			t.Fatalf("cmd.Steps = %+v, want 2 steps [s1, s2] in order", cmd.Steps)
		}
	})
}

func TestDispatchRun_DisconnectImmediatelyBeforeDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-disconnect")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-disconnect"
		seedActiveAgent(t, pool, agentID, "Windows")

		fake := startFakeAgent(t, h.hub, agentID)
		fake.Disconnect(t) // blocks until the hub has actually removed it

		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "posture"})
		if err != nil || runID != "" || skip != "offline" {
			t.Fatalf("post-disconnect dispatch: runID=%q skip=%q err=%v, want offline", runID, skip, err)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs ORDER BY started_at DESC LIMIT 1`).Scan(&status)
		if status != "failed" {
			t.Fatalf("run status = %q, want failed (must not stay running against a dead connection)", status)
		}
	})
}

func TestDispatchRun_LabOnlyStepFiltering(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mixed := []scenario.Step{
			{Name: "normal-1", TechniqueID: "T1059", Framework: "custom", Command: "echo n1"},
			{Name: "lab-1", TechniqueID: "T1059", Framework: "custom", Command: "echo l1", Fidelity: "lab-only"},
			{Name: "normal-2", TechniqueID: "T1059", Framework: "custom", Command: "echo n2"},
			{Name: "lab-2", TechniqueID: "T1059", Framework: "custom", Command: "echo l2", Fidelity: "lab-only"},
		}
		sc, engine := minimalLiveScenario(t, "dr-mixed-fidelity", mixed...)
		h := New(pool, ws.NewHub(), engine, "")

		telemetryAgent := "dr-agent-mixed-telemetry"
		seedActiveAgent(t, pool, telemetryAgent, "Windows")
		fakeT := startFakeAgent(t, h.hub, telemetryAgent)
		defer fakeT.Disconnect(t)
		_, skip, err := h.dispatchRun(context.Background(), sc, telemetryAgent, dispatchOpts{Mode: "telemetry"})
		if err != nil || skip != "" {
			t.Fatalf("telemetry dispatch: skip=%q err=%v", skip, err)
		}
		envT := fakeT.WaitForMessage(t, 2*time.Second)
		var cmdT scenario.ScenarioCommand
		_ = json.Unmarshal(envT.Data, &cmdT)
		if len(cmdT.Steps) != 2 || cmdT.Steps[0].Name != "normal-1" || cmdT.Steps[1].Name != "normal-2" {
			t.Fatalf("telemetry steps = %+v, want [normal-1, normal-2] in original order", cmdT.Steps)
		}

		labAgent := "dr-agent-mixed-lab"
		seedActiveAgent(t, pool, labAgent, "Windows")
		fakeL := startFakeAgent(t, h.hub, labAgent)
		defer fakeL.Disconnect(t)
		_, skipL, errL := h.dispatchRun(context.Background(), sc, labAgent, dispatchOpts{Mode: "lab"})
		if errL != nil || skipL != "" {
			t.Fatalf("lab dispatch: skip=%q err=%v", skipL, errL)
		}
		envL := fakeL.WaitForMessage(t, 2*time.Second)
		var cmdL scenario.ScenarioCommand
		_ = json.Unmarshal(envL.Data, &cmdL)
		if len(cmdL.Steps) != 4 {
			t.Fatalf("lab steps = %+v, want all 4 in original order", cmdL.Steps)
		}
		wantOrder := []string{"normal-1", "lab-1", "normal-2", "lab-2"}
		for i, name := range wantOrder {
			if cmdL.Steps[i].Name != name {
				t.Fatalf("lab step[%d] = %q, want %q (order not preserved)", i, cmdL.Steps[i].Name, name)
			}
		}
	})
}

func TestDispatchRun_AllLabOnlyStepsInTelemetryMode_BuildFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		allLab := []scenario.Step{
			{Name: "lab-only-1", TechniqueID: "T1059", Framework: "custom", Command: "echo l1", Fidelity: "lab-only"},
		}
		sc, engine := minimalLiveScenario(t, "dr-all-lab", allLab...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-all-lab"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "telemetry"})
		if err == nil {
			t.Fatal("expected a genuine build error, got nil")
		}
		if runID != "" || skip != "" {
			t.Fatalf("runID=%q skip=%q, want both empty when err is set", runID, skip)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs ORDER BY started_at DESC LIMIT 1`).Scan(&status)
		if status != "failed" {
			t.Fatalf("run status = %q, want failed", status)
		}
	})
}

func TestDispatchRun_VariantExpansionInvariants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "base-1", TechniqueID: "T1059", Framework: "custom", Command: "echo b1", Executor: "powershell"},
			{Name: "base-2", TechniqueID: "T1059", Framework: "custom", Command: "echo b2", Executor: "powershell"},
		}
		sc, engine := minimalLiveScenario(t, "dr-variant", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-variant"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		runID, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "telemetry", VariantDepth: scenario.VariantDepthQuick})
		if err != nil || skip != "" {
			t.Fatalf("variant dispatch: skip=%q err=%v", skip, err)
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		_ = json.Unmarshal(env.Data, &cmd)
		if len(cmd.Steps) <= len(steps) {
			t.Fatalf("expanded step count = %d, want more than the base %d", len(cmd.Steps), len(steps))
		}

		var metaRaw []byte
		if err := pool.QueryRow(context.Background(), `SELECT step_meta FROM scenario_runs WHERE id=$1`, runID).Scan(&metaRaw); err != nil {
			t.Fatalf("read step_meta: %v", err)
		}
		var meta map[string]scenario.StepMeta
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			t.Fatalf("decode step_meta: %v", err)
		}
		if len(meta) != len(cmd.Steps) {
			t.Fatalf("step_meta has %d entries, want %d (one per delivered step)", len(meta), len(cmd.Steps))
		}
		for taskID, m := range meta {
			if m.BaseTaskID == "" {
				continue // a base step itself
			}
			if _, ok := meta[m.BaseTaskID]; !ok {
				t.Fatalf("variant step %s has BaseTaskID %q which is not a key in step_meta (orphaned variant)", taskID, m.BaseTaskID)
			}
		}
	})
}

func TestDispatchRun_NoVariantExpansion_IdentityTransform(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "only-step", TechniqueID: "T1059", Framework: "custom", Command: "echo x"},
		}
		sc, engine := minimalLiveScenario(t, "dr-no-variant", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "dr-agent-no-variant"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		_, skip, err := h.dispatchRun(context.Background(), sc, agentID, dispatchOpts{Mode: "telemetry"})
		if err != nil || skip != "" {
			t.Fatalf("dispatch: skip=%q err=%v", skip, err)
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		_ = json.Unmarshal(env.Data, &cmd)
		if len(cmd.Steps) != 1 {
			t.Fatalf("step count = %d, want 1 (no variant expansion requested)", len(cmd.Steps))
		}
	})
}

func TestDispatchRun_DBInsertFailure_ClosedPool(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "dr-closedpool")
		closedPool, err := pgxpool.New(context.Background(), sharedDB.Pool.Config().ConnString())
		if err != nil {
			t.Fatalf("new pool: %v", err)
		}
		closedPool.Close()
		h := New(closedPool, ws.NewHub(), engine, "")

		runID, skip, err2 := h.dispatchRun(context.Background(), sc, "dr-agent-closedpool", dispatchOpts{Mode: "posture"})
		if err2 == nil {
			t.Fatal("expected a genuine error against a closed pool, got nil")
		}
		if runID != "" || skip != "" {
			t.Fatalf("runID=%q skip=%q, want both empty when err is set", runID, skip)
		}
	})
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestDispatchRun_' -v`
Expected: all PASS. `TestDispatchRun_AgentStateGate` intentionally queries `agents` without setting `os_version` — the gate check itself doesn't require it, so this should be fine; if it fails, read `dispatchRun`'s exact agent-state query again and adjust the seed accordingly.

- [ ] **Step 3: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/dispatch_run_test.go
git commit -m "test(api): add dispatchRun gate/concurrency/dispatch-outcome/variant-expansion tests

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 5: `internal/api/run_scenario_integration_test.go`

**Files:**
- Create: `orchestrator/internal/api/run_scenario_integration_test.go`

**Interfaces:**
- Consumes: `Handler.RunScenario`, `minimalPostureScenario`/`minimalLiveScenario`, `startFakeAgent`, `runScenarioReq`/`seedActiveAgent` (from Task 3), `withURLParam`.

- [ ] **Step 1: Write the test file**

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRunScenarioIntegration_PostureEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "int-posture")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-posture"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp["status"] != "dispatched" || resp["mode"] != "posture" || resp["runId"] == "" {
			t.Fatalf("resp = %+v, want status=dispatched mode=posture runId=<non-empty>", resp)
		}
		if _, hasWarning := resp["osWarning"]; hasWarning {
			t.Fatalf("resp unexpectedly has osWarning: %+v", resp)
		}
		fake.WaitForMessage(t, 2*time.Second)
	})
}

func TestRunScenarioIntegration_LiveEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "int-live")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-live"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["mode"] != "telemetry" {
			t.Fatalf("resp = %+v, want mode=telemetry", resp)
		}
		fake.WaitForMessage(t, 2*time.Second)
	})
}

func TestRunScenarioIntegration_SkipReasonsSurfaceCorrectStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "int-skips")
		h := New(pool, ws.NewHub(), engine, "")

		busyAgent := "int-agent-busy"
		seedActiveAgent(t, pool, busyAgent, "Windows")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at) VALUES ('int-run-busy',$1,$2,'x','running',NOW())`,
			sc.ID, busyAgent); err != nil {
			t.Fatalf("seed busy run: %v", err)
		}
		busyRec := httptest.NewRecorder()
		h.RunScenario(busyRec, runScenarioReq(sc.ID, map[string]any{"agentId": busyAgent}))
		if busyRec.Code != http.StatusConflict {
			t.Fatalf("busy: status = %d, want 409", busyRec.Code)
		}

		offlineAgent := "int-agent-offline"
		seedActiveAgent(t, pool, offlineAgent, "Windows")
		offlineRec := httptest.NewRecorder()
		h.RunScenario(offlineRec, runScenarioReq(sc.ID, map[string]any{"agentId": offlineAgent}))
		if offlineRec.Code != http.StatusServiceUnavailable {
			t.Fatalf("offline: status = %d, want 503", offlineRec.Code)
		}
	})
}

func TestRunScenarioIntegration_TechniqueAndStepSubset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "step-0", TechniqueID: "T1059", Framework: "custom", Command: "echo 0"},
			{Name: "step-1", TechniqueID: "T1059", Framework: "custom", Command: "echo 1"},
		}
		sc, engine := minimalLiveScenario(t, "int-subset", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-subset"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true, "steps": []int{0},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "step-0" {
			t.Fatalf("cmd.Steps = %+v, want exactly [step-0]", cmd.Steps)
		}
	})
}

func TestRunScenarioIntegration_PostureOSMismatchStillDispatches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalPostureScenario(t, "int-osw")
		sc.SupportedOS = []string{"linux"}
		if err := engine.Save(sc); err != nil {
			t.Fatalf("re-save: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-osw"
		seedActiveAgent(t, pool, agentID, "Windows Server 2022")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if resp["osWarning"] == nil || resp["osWarning"] == "" {
			t.Fatalf("resp = %+v, want a populated osWarning", resp)
		}
		fake.WaitForMessage(t, 2*time.Second)
	})
}
```

- [ ] **Step 2: Run**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestRunScenarioIntegration_' -v`
Expected: all PASS.

- [ ] **Step 3: Full suite, vet, staticcheck**

Run: `go test ./... -short && go vet ./... && staticcheck ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/run_scenario_integration_test.go
git commit -m "test(api): add RunScenario end-to-end integration tests via the fake-agent WS helper

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 6: Final validation pass

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

Run (for each new/modified file): `git show HEAD:internal/db/postgres.go | gofmt -l -`, then the same for `internal/api/handlers.go`, `internal/api/dispatch_race_test.go`, `internal/api/run_dispatch_helpers_test.go`, `internal/api/run_scenario_gates_test.go`, `internal/api/dispatch_run_test.go`, `internal/api/run_scenario_integration_test.go`.
Expected: no output (clean) for every file.

- [ ] **Step 4: Determinism**

Run: `go test ./internal/api/... -count=10`
Expected: 10/10 clean across the whole package — includes the race test and every fake-agent-WS-based test, not just the ones checkpointed individually in Task 2.

- [ ] **Step 5: -race note**

Unavailable locally (no cgo on this Windows host); verified on `ubuntu-latest` in CI. This phase's race-condition fix (Task 1) was found and verified via `-count=10` + the explicit concurrent-goroutines test, not via `-race` — the bug was a logical TOCTOU race at the SQL level, not a Go memory-safety data race, so `-race` would not have caught it anyway.

- [ ] **Step 6: Coverage review**

Run: `go test ./internal/api/... -coverprofile=coverage-3b1.out && go tool cover -func=coverage-3b1.out | grep -E "\b(dispatchRun|RunScenario|classifyAgentOS|isUniqueViolation)\b"`
Expected: all four show substantial coverage. Note (don't chase) any remaining 0% lines that require simulating a specific `h.hub.SendToAgent` internal failure mode beyond "no connection" (e.g., a full send buffer) — out of scope, same honest-ceiling precedent as prior phases.

Delete the scratch profile: `rm coverage-3b1.out`.

- [ ] **Step 7: Update memory**

Update `project_test_generation_phase0.md` with a "Phase 3b.1 DONE" section (commit range, coverage summary, and key learnings: the TOCTOU race found and fixed, the generic fake-agent WS helper and its `wsEnvelope`/two-stage-decode pattern, the `minimalPostureScenario`/`minimalLiveScenario` two-return-value fixture pattern, `Engine.Save` as the correct test-registration path). Update the `MEMORY.md` index line.

---

## Self-Review

**Spec coverage:** The race fix (Task 1), `classifyAgentOS` matrix, fake-agent helper, scenario fixtures (Task 2), all of `RunScenario`'s own gates (Task 3), all of `dispatchRun`'s independent gates/outcomes/variant-invariants/idempotency/DB-failure (Task 4), and full HTTP integration incl. skip-reason-to-status mapping and subset selection (Task 5) — every spec section has a task.

**Placeholder scan:** Task 2 deliberately shows an intermediate wrong version of `Disconnect`/`hubHasAgent` and then the corrected version, with an explicit instruction that only the corrected code should end up in the file — this is a worked-through design correction, not an unresolved TBD, and the final code blocks are complete and correct on their own.

**Type consistency:** `minimalPostureScenario`/`minimalLiveScenario` are corrected in Task 2 (during Task 3's writing) to return `(*scenario.Scenario, *scenario.Engine)` — every call site across Tasks 3, 4, 5 uses the two-value form consistently. `wsEnvelope{Type, AgentID, Data}` and `fakeAgent`'s methods (`WaitForMessage`, `Disconnect`, `Reconnect`) are defined once in Task 2 and used with identical signatures in Tasks 3-5. `dispatchOpts` fields match `handlers.go`'s real struct (`Mode`, `ConfirmLive`, `ConfirmLab`, `Techniques`, `Abilities`, `Steps`, `Checks`, `InitiatedBy`, `VariantDepth`, `RunLabel`, `CampaignID`, `Reason`).
