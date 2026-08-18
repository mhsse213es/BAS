# Sweep Agent-Disconnect Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make EM Sweep and Full Variant Sweep survive an agent disconnecting mid-run: show a real "Agent Disconnected" status instead of a stale "Running", allow Stop at any time, and resume the interrupted layer/technique from scratch once the agent reconnects — instead of today's behavior, where a blind 3-minute stuck-timer force-cancels and then fails the entire sweep well before the user can reconnect.

**Architecture:** Both `internal/emsweep` and `internal/vexsweep` gain a `ConnectedFn` injected into their `Dispatcher` (mirroring the existing `DispatchFn`/`CancelFn`/`StatusFn` injection pattern), backed by a new `ws.Hub.IsAgentConnected`. `advance()` checks connectivity before its existing status/stuck-timer logic each tick: disconnect while running → pause into a new `agent_disconnected` sweep status (indefinite wait, no timer); reconnect while paused → re-dispatch the same layer/technique fresh. A sentinel error (`ErrAgentOffline`) handles the race window where the connectivity check passes but the dispatch call itself still fails. The frontend surfaces the new status with a distinct badge and adds a direct Stop action to the Live Runs row.

**Tech Stack:** Go (orchestrator backend), PostgreSQL (via pgx), vanilla JS (wwwroot/index.html), Go's `testing` package with `testcontainers-go`-backed integration tests.

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-18-sweep-disconnect-resilience-design.md`

## Global Constraints

- Scope covers **both** EM Sweep (`internal/emsweep`) and Full Variant Sweep (`internal/vexsweep`) — confirmed by the user during brainstorming, not EM-only.
- On reconnect, the interrupted layer/technique is **re-dispatched from scratch**, never skipped.
- A disconnected sweep **waits indefinitely** for reconnect — no bounded give-up timeout.
- `agent_disconnected` is a **real, persisted** status value on the sweep row, not a frontend-only display computation.
- The existing connected-but-genuinely-stuck 3-minute force-cancel behavior is **untouched** by this work.
- Every Go change follows TDD: write the failing test, confirm it fails, implement, confirm it passes.
- Run the **full** `internal/api` test suite (not just new tests) before any commit that touches `internal/api`, via `Bash` with `run_in_background: true` (it takes 8–15 minutes) — then tail the actual log file after the completion notification. Never trust a piped/truncated capture; this session hit two false "hang" alarms exactly that way.
- Commit after each task (or small group) with a message explaining root cause + fix, then `git push` immediately after every commit.
- JS syntax check convention: extract `<script>` blocks from `index.html` into a scratchpad file, run `node --check` via the PowerShell tool.

---

## File Structure

| File | Responsibility |
|---|---|
| `orchestrator/internal/ws/hub.go` | New `IsAgentConnected` read method. |
| `orchestrator/internal/ws/hub_test.go` | Unit tests for it. |
| `orchestrator/internal/emsweep/sweep.go` | New `Sweep.DisconnectedAt` field. |
| `orchestrator/internal/emsweep/store.go` | New/widened Store methods: `ListActionable`, `MarkDisconnected`, `Resume`, widened `GetActiveForAgent`. |
| `orchestrator/internal/emsweep/store_test.go` | Tests for the above. |
| `orchestrator/internal/emsweep/dispatcher.go` | `ConnectedFn` type + `SetConnected`, `ErrAgentOffline` sentinel, rewritten `advance()`, new `handleDisconnect`/`resume` helpers, `dispatchNext`'s offline-race handling. |
| `orchestrator/internal/emsweep/dispatcher_test.go` | Tests for the above. |
| `orchestrator/internal/api/em_dispatch.go` | `dispatchEMLayer` returns `emsweep.ErrAgentOffline` for the offline case instead of a generic error. |
| `orchestrator/internal/api/emsweep_handlers.go` | `CancelEMSweep`'s status guard widened; `emSweepToJSON` gains `disconnectedAt`. |
| `orchestrator/internal/api/handlers.go` | `WithEMSweep`/`WithVexSweep` wire `dispatcher.SetConnected(h.hub.IsAgentConnected)`. |
| `orchestrator/internal/api/emsweep_handlers_test.go` | Test for the widened cancel guard. |
| `orchestrator/internal/vexsweep/sweep.go`, `store.go`, `store_test.go`, `dispatcher.go`, `dispatcher_test.go` | Mirror of the emsweep changes above, adapted for vexsweep's two run-ID fields (`CurrentVariantRunID`/`CurrentScenarioRunID`) and `Techniques`/`TechniqueVariantCounts`. |
| `orchestrator/internal/api/variant_handlers.go` | `dispatchVariantForSweep` returns `vexsweep.ErrAgentOffline` for the offline case. |
| `orchestrator/internal/api/vexsweep_handlers.go` | `CancelVexSweep`'s status guard widened; `sweepToJSON` gains `disconnectedAt`. |
| `orchestrator/internal/db/postgres.go` | New migration statements: `disconnected_at` columns + widened partial unique indexes for both `em_sweeps` and `vex_sweeps`. |
| `orchestrator/wwwroot/index.html` | New `.s-agent_disconnected` CSS class, `sweepStatusLabel()` helper, Stop button in both row renderers' actions cell, drawer/list gating fixes, `pollVexSweeps()` widened to also fetch `agent_disconnected` sweeps. |

---

## Task 1: `ws.Hub.IsAgentConnected`

**Files:**
- Modify: `orchestrator/internal/ws/hub.go` (insert after `ConnectedAgents()`, currently ending at line 195)
- Test: `orchestrator/internal/ws/hub_test.go`

**Interfaces:**
- Produces: `func (h *Hub) IsAgentConnected(agentID string) bool` — used by Task 3/6's `Dispatcher.ConnectedFn` injection.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/ws/hub_test.go`:

```go
func TestIsAgentConnected_TrueForRegisteredAgent(t *testing.T) {
	h := NewHub()
	h.mu.Lock()
	h.agents["agent-connected"] = &conn{send: make(chan []byte, 1)}
	h.mu.Unlock()

	if !h.IsAgentConnected("agent-connected") {
		t.Fatal("IsAgentConnected returned false for a registered agent")
	}
}

func TestIsAgentConnected_FalseForUnknownAgent(t *testing.T) {
	h := NewHub()
	if h.IsAgentConnected("does-not-exist") {
		t.Fatal("IsAgentConnected returned true for an unregistered agent")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/ws/... -run TestIsAgentConnected -v`
Expected: FAIL with `h.IsAgentConnected undefined`

- [ ] **Step 3: Implement**

Insert into `orchestrator/internal/ws/hub.go` immediately after `ConnectedAgents()` (after its closing `}`, currently line 195):

```go

// IsAgentConnected reports whether a specific agent currently has a live
// WebSocket connection. Used by the EM Sweep and Full Variant Sweep
// dispatchers to distinguish "the agent disconnected" from "the agent is
// connected but a layer/technique is genuinely hung" -- see
// docs/superpowers/specs/2026-08-18-sweep-disconnect-resilience-design.md.
func (h *Hub) IsAgentConnected(agentID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.agents[agentID]
	return ok
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/ws/... -v`
Expected: PASS (all tests in the package, not just the new ones)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/ws/hub.go orchestrator/internal/ws/hub_test.go
git commit -m "feat(ws): add Hub.IsAgentConnected

Sweep dispatchers need a live per-agent connectivity check to distinguish
a disconnected agent from one that's connected but genuinely stuck --
first piece of the sweep agent-disconnect resilience work."
git push
```

---

## Task 2: emsweep data model — `DisconnectedAt`, store methods, migration

**Files:**
- Modify: `orchestrator/internal/emsweep/sweep.go`
- Modify: `orchestrator/internal/emsweep/store.go`
- Modify: `orchestrator/internal/db/postgres.go` (append to the `stmts := []string{...}` slice ending at line 1531)
- Test: `orchestrator/internal/emsweep/store_test.go`

**Interfaces:**
- Consumes: none new.
- Produces: `Sweep.DisconnectedAt *time.Time`; `Store.ListActionable(ctx) ([]Sweep, error)`; `Store.MarkDisconnected(ctx, id string, pendingIndex int) error`; `Store.Resume(ctx, id, scenarioRunID string) error`; widened `Store.GetActiveForAgent` (now matches `status IN ('running', 'agent_disconnected')`). All consumed by Task 3's dispatcher.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/emsweep/store_test.go` (after `TestMarkStopped_And_MarkFailed`):

```go
func TestGetActiveForAgent_TreatsDisconnectedAsActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-disc-active", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}
		got, found, err := store.GetActiveForAgent(ctx, "agent-disc-active")
		if err != nil {
			t.Fatalf("GetActiveForAgent: %v", err)
		}
		if !found || got.ID != sw.ID {
			t.Fatalf("GetActiveForAgent = (%+v, %v), want the disconnected sweep to still count as active", got, found)
		}
	})
}

func TestListActionable_IncludesRunningAndDisconnectedOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		running, err := store.Create(ctx, Sweep{AgentID: "agent-actionable-running", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create running: %v", err)
		}
		disconnected, err := store.Create(ctx, Sweep{AgentID: "agent-actionable-disc", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create disconnected: %v", err)
		}
		if err := store.MarkDisconnected(ctx, disconnected.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}
		stopped, err := store.Create(ctx, Sweep{AgentID: "agent-actionable-stopped", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create stopped: %v", err)
		}
		if err := store.MarkStopped(ctx, stopped.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}

		got, err := store.ListActionable(ctx)
		if err != nil {
			t.Fatalf("ListActionable: %v", err)
		}
		ids := map[string]bool{}
		for _, sw := range got {
			ids[sw.ID] = true
		}
		if !ids[running.ID] || !ids[disconnected.ID] {
			t.Fatalf("ListActionable() = %+v, want both the running and disconnected sweeps", got)
		}
		if ids[stopped.ID] {
			t.Fatalf("ListActionable() included a stopped sweep: %+v", got)
		}
	})
}

// TestMarkDisconnected_SetsStatusAndClearsCurrentRun proves the pause
// transition: status flips, disconnected_at is stamped, and the current run
// pointer clears since whatever was in flight has already been separately
// resolved by the caller (or never existed, in the dispatchNext race case).
// pendingIndex names the layer to re-dispatch on reconnect.
func TestMarkDisconnected_SetsStatusAndClearsCurrentRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-mark-disc", Layers: []string{"em-01", "em-02"}, TotalLayers: 2})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-mark-disc"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q, want agent_disconnected", got.Status)
		}
		if got.DisconnectedAt == nil {
			t.Fatal("DisconnectedAt should be set")
		}
		if got.CurrentScenarioRunID != "" {
			t.Fatalf("CurrentScenarioRunID = %q, want cleared", got.CurrentScenarioRunID)
		}
		if got.CurrentLayerStartedAt != nil {
			t.Fatal("CurrentLayerStartedAt should be cleared")
		}
		if got.CurrentIndex != 0 {
			t.Fatalf("CurrentIndex = %d, want 0 (pendingIndex)", got.CurrentIndex)
		}
	})
}

// TestResume_ClearsDisconnectedAtAndSetsNewRun proves the un-pause
// transition: status flips back, disconnected_at clears, and the new run
// (from re-dispatching the pending layer) becomes current.
func TestResume_ClearsDisconnectedAtAndSetsNewRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-resume", Layers: []string{"em-01"}, TotalLayers: 1})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		if err := store.Resume(ctx, sw.ID, "sr-resumed"); err != nil {
			t.Fatalf("Resume: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "running" {
			t.Fatalf("Status = %q, want running", got.Status)
		}
		if got.DisconnectedAt != nil {
			t.Fatal("DisconnectedAt should be cleared")
		}
		if got.CurrentScenarioRunID != "sr-resumed" {
			t.Fatalf("CurrentScenarioRunID = %q, want sr-resumed", got.CurrentScenarioRunID)
		}
		if got.CurrentLayerStartedAt == nil {
			t.Fatal("CurrentLayerStartedAt should be set")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/emsweep/... -run "TestGetActiveForAgent_TreatsDisconnectedAsActive|TestListActionable_IncludesRunningAndDisconnectedOnly|TestMarkDisconnected_SetsStatusAndClearsCurrentRun|TestResume_ClearsDisconnectedAtAndSetsNewRun" -v`
Expected: FAIL to compile — `store.MarkDisconnected`, `store.ListActionable`, `store.Resume` undefined, and `disconnected_at`/`DisconnectedAt` don't exist yet.

- [ ] **Step 3: Add the DB migration**

In `orchestrator/internal/db/postgres.go`, append these statements to the `stmts := []string{...}` slice, right after the existing `vex_sweeps`/`base_types` lines (currently ending at line 1530, just before the slice's closing `}` at line 1531):

```go
	// Sweep agent-disconnect resilience: a sweep whose agent drops mid-run
	// transitions to 'agent_disconnected' (a new status value -- no CHECK
	// constraint exists to update) instead of being force-failed by the old
	// blind 3-minute stuck-timer. disconnected_at records when. The partial
	// unique index enforcing "one active sweep per agent" must treat this
	// status as active too, or a second sweep could be started against an
	// agent whose first sweep is merely paused waiting on reconnect --
	// CREATE UNIQUE INDEX IF NOT EXISTS won't redefine an index under an
	// unchanged name, so this is an explicit drop+recreate. See
	// docs/superpowers/specs/2026-08-18-sweep-disconnect-resilience-design.md.
	`ALTER TABLE em_sweeps ADD COLUMN IF NOT EXISTS disconnected_at timestamptz`,
	`DROP INDEX IF EXISTS idx_em_sweeps_one_running_per_agent`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_em_sweeps_one_running_per_agent
		ON em_sweeps (agent_id) WHERE status IN ('running', 'agent_disconnected')`,
```

(vex_sweeps' equivalent statements are added in Task 5, right after these.)

- [ ] **Step 4: Add `DisconnectedAt` to the `Sweep` struct**

In `orchestrator/internal/emsweep/sweep.go`, add after `CompletedAt *time.Time` (the struct's last field):

```go
	// DisconnectedAt is when the Dispatcher last detected the agent was
	// unreachable (nil while running normally, or once resumed). See
	// dispatcher.go's advance() disconnect/resume state machine.
	DisconnectedAt *time.Time
```

- [ ] **Step 5: Update `sweepCols`/`scanSweep` and widen `GetActiveForAgent`**

In `orchestrator/internal/emsweep/store.go`:

Replace the `sweepCols` const:

```go
const sweepCols = `id, agent_id, layers, current_index, current_scenario_run_id,
	current_layer_started_at, completed_layers, total_layers, status, error,
	created_by, started_at, completed_at, disconnected_at`
```

Replace `scanSweep`'s `Scan` call to add the new column at the end:

```go
	err := row.Scan(&sw.ID, &sw.AgentID, &sw.Layers, &sw.CurrentIndex, &sw.CurrentScenarioRunID,
		&sw.CurrentLayerStartedAt, &sw.CompletedLayers, &sw.TotalLayers, &sw.Status, &sw.Error,
		&sw.CreatedBy, &sw.StartedAt, &sw.CompletedAt, &sw.DisconnectedAt)
```

Replace `GetActiveForAgent`'s query:

```go
func (s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+sweepCols+` FROM em_sweeps WHERE agent_id = $1 AND status IN ('running', 'agent_disconnected')`, agentID)
```

- [ ] **Step 6: Add `ListActionable`, `MarkDisconnected`, `Resume`**

In `orchestrator/internal/emsweep/store.go`, add after `ListByStatus` (right before `AdvanceToNext`):

```go
// ListActionable returns every sweep the Dispatcher must keep ticking:
// actively running, or paused waiting for its agent to reconnect. Distinct
// from ListRunning (status='running' only), which existing tests and the
// Dispatcher's pre-disconnect-awareness callers relied on meaning "actively
// dispatching right now".
func (s *Store) ListActionable(ctx context.Context) ([]Sweep, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+sweepCols+` FROM em_sweeps WHERE status IN ('running', 'agent_disconnected') ORDER BY started_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sweep
	for rows.Next() {
		sw, err := scanSweep(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	return out, rows.Err()
}
```

And after `AdvanceToNext` (right before `MarkStopped`):

```go
// MarkDisconnected pauses a sweep whose agent is no longer reachable.
// pendingIndex is the layer index to re-dispatch on reconnect -- either the
// layer already in flight when the disconnect was detected (index
// unchanged), or, when the offline failure instead surfaces from
// dispatchNext's own dispatch attempt (the ErrAgentOffline race case), the
// layer that attempt was trying to reach (current_index has not advanced to
// it in the DB yet in that case). Always clears the current run pointer:
// any in-flight run has already been separately resolved (cancelled to
// 'partial') by the caller before this is called, or never existed.
func (s *Store) MarkDisconnected(ctx context.Context, id string, pendingIndex int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps
		    SET status = 'agent_disconnected', disconnected_at = NOW(),
		        current_index = $2, current_scenario_run_id = '', current_layer_started_at = NULL
		  WHERE id = $1`,
		id, pendingIndex)
	return err
}

// Resume un-pauses a sweep after its agent reconnects. The caller has
// already re-dispatched Layers[current_index] as a fresh run and passes its
// ID here; current_index itself is left unchanged -- the sweep is
// continuing the same layer it was on, not advancing past it.
func (s *Store) Resume(ctx context.Context, id, scenarioRunID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE em_sweeps
		    SET status = 'running', disconnected_at = NULL,
		        current_scenario_run_id = $2, current_layer_started_at = NOW()
		  WHERE id = $1`,
		id, scenarioRunID)
	return err
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/emsweep/... -v`
Expected: PASS (every test in the package, including the pre-existing ones — confirms the `sweepCols`/`scanSweep` change didn't break round-tripping)

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/emsweep/sweep.go orchestrator/internal/emsweep/store.go orchestrator/internal/emsweep/store_test.go orchestrator/internal/db/postgres.go
git commit -m "feat(emsweep): add agent_disconnected data model

New disconnected_at column, ListActionable/MarkDisconnected/Resume store
methods, and a widened one-active-sweep-per-agent index that treats
agent_disconnected as active alongside running. Groundwork for the
Dispatcher's disconnect/resume state machine (next commit)."
git push
```

---

## Task 3: emsweep dispatcher — disconnect/resume state machine

**Files:**
- Modify: `orchestrator/internal/emsweep/dispatcher.go`
- Test: `orchestrator/internal/emsweep/dispatcher_test.go`

**Interfaces:**
- Consumes: `Store.ListActionable`, `Store.MarkDisconnected`, `Store.Resume` (Task 2).
- Produces: `type ConnectedFn func(agentID string) bool`; `func (d *Dispatcher) SetConnected(fn ConnectedFn)`; `var ErrAgentOffline = errors.New(...)`. Consumed by Task 4 (`em_dispatch.go`, `handlers.go`'s `WithEMSweep`).

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/emsweep/dispatcher_test.go` (after the existing `TestDispatcher_Tick_IgnoresStoppedAndFailedSweeps` — check that test's exact name first with `grep -n "^func Test" orchestrator/internal/emsweep/dispatcher_test.go`, matching this file's existing structure):

```go
// TestDispatcher_Tick_PausesOnDisconnectAndCancelsInFlightRun is the
// regression test for the actual bug reported: an agent that disconnects
// mid-layer used to sit "running" for a full 3 minutes, then get force-
// cancelled and the WHOLE SWEEP marked failed on the next dispatch attempt
// (since the agent was still offline) -- typically well before the user
// could reconnect. The Dispatcher must instead detect the disconnect
// immediately (via ConnectedFn) and pause, not fail.
func TestDispatcher_Tick_PausesOnDisconnectAndCancelsInFlightRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-disc-1", Layers: []string{"em-01", "em-02"}, TotalLayers: 2,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "sr-disc-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var cancelledRunIDs []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil // the layer never gets a chance to finish -- agent went offline
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			t.Fatal("dispatch should not be called -- the sweep must pause, not advance")
			return "", nil
		})
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelledRunIDs = append(cancelledRunIDs, scenarioRunID)
			return "agent-disc-1", "partial", nil
		})
		d.SetConnected(func(agentID string) bool { return false }) // agent is offline

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q, want agent_disconnected", got.Status)
		}
		if got.DisconnectedAt == nil {
			t.Fatal("DisconnectedAt should be set")
		}
		if len(cancelledRunIDs) != 1 || cancelledRunIDs[0] != "sr-disc-1" {
			t.Fatalf("cancelledRunIDs = %v, want exactly [sr-disc-1] (the in-flight layer must be cancelled, not left dangling)", cancelledRunIDs)
		}
		if got.CurrentIndex != 0 {
			t.Fatalf("CurrentIndex = %d, want 0 (the interrupted layer, unchanged, ready to re-dispatch on reconnect)", got.CurrentIndex)
		}
	})
}

// TestDispatcher_Tick_WaitsIndefinitelyWhileDisconnected proves the
// no-timeout decision: unlike the connected-but-stuck path, a disconnected
// sweep never force-advances or fails on its own, no matter how much time
// passes -- it just waits for reconnect or an explicit Stop.
func TestDispatcher_Tick_WaitsIndefinitelyWhileDisconnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-disc-2", Layers: []string{"em-01"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			t.Fatal("status should not be checked -- no run is in flight while disconnected")
			return "", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			t.Fatal("dispatch should not be called -- agent is still offline")
			return "", nil
		})
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			t.Fatal("cancel should not be called -- nothing is in flight while disconnected")
			return "", "", nil
		})
		d.stuckThreshold = time.Millisecond // would force-fail almost instantly if the old timer still applied here
		d.SetConnected(func(agentID string) bool { return false })

		time.Sleep(5 * time.Millisecond)

		for i := 0; i < 3; i++ {
			if err := d.Tick(ctx); err != nil {
				t.Fatalf("Tick %d: %v", i, err)
			}
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q after 3 ticks while still offline, want agent_disconnected (must not time out)", got.Status)
		}
	})
}

// TestDispatcher_Tick_ResumesInterruptedLayerOnReconnect proves the resume
// behavior the user explicitly asked for: the interrupted layer is
// re-dispatched from scratch, not skipped, once the agent reconnects.
func TestDispatcher_Tick_ResumesInterruptedLayerOnReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-disc-3", Layers: []string{"em-01", "em-02"}, TotalLayers: 2,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 1); err != nil { // was mid-layer 1 (0-indexed second layer) when it disconnected
			t.Fatalf("MarkDisconnected: %v", err)
		}

		var dispatchedLayers []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			t.Fatal("status should not be checked this tick -- no run was in flight before resuming")
			return "", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			dispatchedLayers = append(dispatchedLayers, scenarioID)
			if layerIndex != 1 {
				t.Fatalf("layerIndex = %d, want 1 (the interrupted layer)", layerIndex)
			}
			return "sr-resumed", nil
		})
		d.SetConnected(func(agentID string) bool { return true }) // agent is back

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedLayers) != 1 || dispatchedLayers[0] != "em-02" {
			t.Fatalf("dispatchedLayers = %v, want [em-02] (the interrupted layer, re-dispatched from scratch)", dispatchedLayers)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "running" {
			t.Fatalf("Status = %q, want running", got.Status)
		}
		if got.DisconnectedAt != nil {
			t.Fatal("DisconnectedAt should be cleared")
		}
		if got.CurrentScenarioRunID != "sr-resumed" {
			t.Fatalf("CurrentScenarioRunID = %q, want sr-resumed", got.CurrentScenarioRunID)
		}
		if got.CurrentIndex != 1 {
			t.Fatalf("CurrentIndex = %d, want unchanged at 1", got.CurrentIndex)
		}
	})
}

// TestDispatcher_Tick_ExistingBehaviorUnaffectedWhenConnectedFnNotSet proves
// backward compatibility: every dispatcher_test.go test written before this
// change never calls SetConnected, so d.connected stays nil. Those tests
// must keep passing unmodified -- a nil ConnectedFn must mean "connectivity
// awareness is off", not "treat every agent as disconnected".
func TestDispatcher_Tick_ExistingBehaviorUnaffectedWhenConnectedFnNotSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-no-connected-fn", Layers: []string{"em-01"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		var dispatchedLayers []string
		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			dispatchedLayers = append(dispatchedLayers, scenarioID)
			return "sr-1", nil
		})
		// Deliberately no SetConnected call.

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedLayers) != 1 {
			t.Fatalf("dispatchedLayers = %v, want exactly 1 dispatch (nil ConnectedFn must not block normal dispatch)", dispatchedLayers)
		}
	})
}

// TestDispatcher_Tick_PausesInsteadOfFailingOnOfflineRaceDuringDispatch
// covers the narrow race window: ConnectedFn said the agent was reachable,
// but the dispatch call itself still failed because the agent dropped in
// between. dispatchNext must special-case ErrAgentOffline into a pause
// (same as a proactively-detected disconnect), not the ordinary
// MarkFailed/hard-fail path every other dispatch error still takes.
func TestDispatcher_Tick_PausesInsteadOfFailingOnOfflineRaceDuringDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-race-1", Layers: []string{"em-01"}, TotalLayers: 1,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, scenarioRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, scenarioID string, layerIndex, totalLayers int) (string, error) {
			return "", ErrAgentOffline
		})
		d.SetConnected(func(agentID string) bool { return true }) // said reachable, but dispatch itself then fails

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q, want agent_disconnected (not failed)", got.Status)
		}
		if got.CurrentIndex != 0 {
			t.Fatalf("CurrentIndex = %d, want 0 (the layer the failed dispatch was trying to reach)", got.CurrentIndex)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/emsweep/... -run "TestDispatcher_Tick_PausesOnDisconnect|TestDispatcher_Tick_WaitsIndefinitely|TestDispatcher_Tick_ResumesInterrupted|TestDispatcher_Tick_ExistingBehaviorUnaffected|TestDispatcher_Tick_PausesInsteadOfFailing" -v`
Expected: FAIL to compile — `SetConnected`, `ErrAgentOffline` undefined.

- [ ] **Step 3: Implement the sentinel and `SetConnected`**

In `orchestrator/internal/emsweep/dispatcher.go`, add `"errors"` to the import block:

```go
import (
	"context"
	"errors"
	"log"
	"time"
)
```

Add after the `CancelFn` type definition (before `defaultStuckThreshold`):

```go
// ConnectedFn reports whether a specific agent currently has a live
// connection. Injected after construction (SetConnected), same
// import-cycle-avoidance pattern as DispatchFn/CancelFn. A nil ConnectedFn
// (SetConnected never called) means connectivity-awareness is off --
// advance() falls back to its pre-existing behavior entirely, so callers
// that never opt in (and every dispatcher_test.go case written before this
// change) are unaffected.
type ConnectedFn func(agentID string) bool

// ErrAgentOffline is the sentinel a DispatchFn implementation returns when
// a layer failed to dispatch specifically because its agent is
// unreachable -- distinguished from any other dispatch failure so
// dispatchNext can pause the sweep (agent_disconnected) instead of
// force-failing it outright. Covers the race window between advance()'s
// proactive connectivity check and the dispatch call actually going out.
var ErrAgentOffline = errors.New("emsweep: agent offline")
```

Add `connected ConnectedFn` to the `Dispatcher` struct (alongside `dispatch`/`cancel`):

```go
type Dispatcher struct {
	store     *Store
	status    StatusFn
	dispatch  DispatchFn
	cancel    CancelFn
	connected ConnectedFn

	stuckThreshold time.Duration
	cancelTriggeredForRun map[string]bool
}
```

Add the setter after `SetCancel`:

```go
func (d *Dispatcher) SetConnected(fn ConnectedFn) { d.connected = fn }
```

- [ ] **Step 4: Rewrite `Tick` to use `ListActionable`**

Replace:

```go
func (d *Dispatcher) Tick(ctx context.Context) error {
	sweeps, err := d.store.ListRunning(ctx)
```

with:

```go
func (d *Dispatcher) Tick(ctx context.Context) error {
	// ListActionable, not ListRunning -- a paused (agent_disconnected)
	// sweep must keep being visited every tick, or a reconnect would never
	// be noticed.
	sweeps, err := d.store.ListActionable(ctx)
```

- [ ] **Step 5: Rewrite `advance()`**

Replace the whole `advance` function with:

```go
func (d *Dispatcher) advance(ctx context.Context, sw Sweep) {
	if d.connected != nil && !d.connected(sw.AgentID) {
		if sw.Status == "running" {
			d.handleDisconnect(ctx, sw)
		}
		// Already agent_disconnected and still offline: no-op. Waits
		// indefinitely -- no stuck-timer applies in this state, since
		// "disconnected" is a known condition now, not an unexplained stall.
		return
	}
	if sw.Status == "agent_disconnected" {
		d.resume(ctx, sw)
		return
	}

	if sw.CurrentScenarioRunID != "" {
		status, err := d.status(ctx, sw.CurrentScenarioRunID)
		if err != nil {
			log.Printf("[emsweep] status check failed for sweep %s run %s: %v", sw.ID, sw.CurrentScenarioRunID, err)
			// A persistent status-check failure must not permanently block
			// stuck-recovery -- see internal/vexsweep/dispatcher.go's
			// identical fix.
			d.maybeForceCancelStuck(ctx, sw)
			return
		}
		if status == "running" {
			d.maybeForceCancelStuck(ctx, sw)
			return // nothing to do this tick
		}
		delete(d.cancelTriggeredForRun, sw.CurrentScenarioRunID)
		// Layer finished (completed/failed/partial) -- credit it and advance.
		d.dispatchNext(ctx, sw, 1)
		return
	}
	// No layer in flight yet -- this is the sweep's very first tick.
	d.dispatchNext(ctx, sw, 0)
}

// handleDisconnect pauses a running sweep once its agent is found
// unreachable: best-effort-cancels the in-flight layer (cancelScenarioRun,
// the production CancelFn, resolves this immediately to 'partial' when the
// agent is offline -- no grace-period wait) and pauses the sweep at its
// current layer, ready to re-dispatch on reconnect. Not gated on the
// cancel call succeeding: detecting and recording the disconnect matters
// more than that best-effort cleanup, and a failed cancel here doesn't
// block anything -- there's no dedup flag to desync, unlike
// maybeForceCancelStuck's cancel.
func (d *Dispatcher) handleDisconnect(ctx context.Context, sw Sweep) {
	if sw.CurrentScenarioRunID != "" && d.cancel != nil {
		if _, _, err := d.cancel(ctx, sw.CurrentScenarioRunID); err != nil {
			log.Printf("[emsweep] cancel in-flight run %s for disconnected sweep %s: %v", sw.CurrentScenarioRunID, sw.ID, err)
		}
	}
	if err := d.store.MarkDisconnected(ctx, sw.ID, sw.CurrentIndex); err != nil {
		log.Printf("[emsweep] mark sweep %s agent_disconnected: %v", sw.ID, err)
		return
	}
	log.Printf("[emsweep] sweep %s paused: agent %s disconnected", sw.ID, sw.AgentID)
}

// resume re-dispatches the pending layer (sw.CurrentIndex, left unchanged
// by MarkDisconnected/a prior resume attempt) once the agent is reachable
// again. A dispatch failure here can legitimately mean the agent dropped
// again in the instant between advance()'s connectivity check and this
// call -- ErrAgentOffline re-pauses rather than failing the sweep; any
// other error still hard-fails it, matching dispatchNext's existing
// semantics for a genuine dispatch problem.
func (d *Dispatcher) resume(ctx context.Context, sw Sweep) {
	if d.dispatch == nil {
		return
	}
	scenarioRunID, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Layers[sw.CurrentIndex], sw.CurrentIndex, len(sw.Layers))
	if err != nil {
		if errors.Is(err, ErrAgentOffline) {
			if merr := d.store.MarkDisconnected(ctx, sw.ID, sw.CurrentIndex); merr != nil {
				log.Printf("[emsweep] re-mark sweep %s agent_disconnected after failed resume: %v", sw.ID, merr)
			}
			return
		}
		if merr := d.store.MarkFailed(ctx, sw.ID, err.Error()); merr != nil {
			log.Printf("[emsweep] mark sweep %s failed after resume attempt: %v", sw.ID, merr)
		}
		return
	}
	if err := d.store.Resume(ctx, sw.ID, scenarioRunID); err != nil {
		log.Printf("[emsweep] resume sweep %s: %v", sw.ID, err)
		return
	}
	log.Printf("[emsweep] sweep %s resumed: agent %s reconnected, re-dispatched layer %s", sw.ID, sw.AgentID, sw.Layers[sw.CurrentIndex])
}
```

- [ ] **Step 6: Handle the offline-race case in `dispatchNext`**

In `dispatchNext`, replace:

```go
	scenarioRunID, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Layers[nextIdx], nextIdx, len(sw.Layers))
	if err != nil {
		// Deliberately does not fall through to the next layer -- a
		// silently-skipped layer in a security-validation sweep is worse
		// than a sweep that stops and says why. Matches vexsweep's identical
		// choice.
		if merr := d.store.MarkFailed(ctx, sw.ID, err.Error()); merr != nil {
			log.Printf("[emsweep] mark sweep %s failed: %v", sw.ID, merr)
		}
		return
	}
```

with:

```go
	scenarioRunID, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Layers[nextIdx], nextIdx, len(sw.Layers))
	if err != nil {
		if errors.Is(err, ErrAgentOffline) {
			// The agent dropped in the window between this tick's
			// connectivity check (or the lack of one) and this dispatch
			// call actually going out. Pause at nextIdx -- the layer this
			// attempt was trying to reach, which current_index has not
			// advanced to yet in the DB -- rather than failing the sweep.
			if merr := d.store.MarkDisconnected(ctx, sw.ID, nextIdx); merr != nil {
				log.Printf("[emsweep] mark sweep %s agent_disconnected (offline race): %v", sw.ID, merr)
			}
			return
		}
		// Deliberately does not fall through to the next layer -- a
		// silently-skipped layer in a security-validation sweep is worse
		// than a sweep that stops and says why. Matches vexsweep's identical
		// choice.
		if merr := d.store.MarkFailed(ctx, sw.ID, err.Error()); merr != nil {
			log.Printf("[emsweep] mark sweep %s failed: %v", sw.ID, merr)
		}
		return
	}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/emsweep/... -v`
Expected: PASS — every test in the package, including all pre-existing dispatcher/store tests (confirms the nil-`ConnectedFn` backward-compat path and the `ListRunning`→`ListActionable` swap didn't regress anything).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/emsweep/dispatcher.go orchestrator/internal/emsweep/dispatcher_test.go
git commit -m "feat(emsweep): dispatcher pauses on disconnect, resumes on reconnect

advance() now checks live agent connectivity before its existing
status/stuck-timer logic. A disconnect while running pauses the sweep
(agent_disconnected, indefinite wait, in-flight layer cancelled) instead
of the old blind 3-minute-then-fail-the-whole-sweep behavior. A reconnect
while paused re-dispatches the interrupted layer from scratch. The
connected-but-genuinely-stuck 3-minute force-cancel path is untouched.

Root cause: the dispatcher had no concept of agent connectivity at all --
it only had a wall-clock stuck-timer that treated a disconnected agent and
a connected-but-hung layer identically, force-cancelling and then failing
the entire sweep well before a user could realistically reconnect."
git push
```

---

## Task 4: emsweep integration — `dispatchEMLayer`, `CancelEMSweep`, wiring

**Files:**
- Modify: `orchestrator/internal/api/em_dispatch.go`
- Modify: `orchestrator/internal/api/emsweep_handlers.go`
- Modify: `orchestrator/internal/api/handlers.go` (`WithEMSweep`, lines 427-435)
- Test: `orchestrator/internal/api/emsweep_handlers_test.go`

**Interfaces:**
- Consumes: `emsweep.ErrAgentOffline`, `Dispatcher.SetConnected` (Task 3); `h.hub.IsAgentConnected` (Task 1).
- Produces: nothing new consumed elsewhere — this task closes the loop for EM Sweep.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/emsweep_handlers_test.go`, right after `TestCancelEMSweep_StopsSweepAndCancelsCurrentRun` (mirrors its exact setup, verified against the file's real content):

```go
// TestCancelEMSweep_SucceedsWhenAgentDisconnected is the regression test
// for the "no option of Stop after the agent disconnected" report: once a
// sweep is paused (agent_disconnected), it must still be cancellable --
// disconnection can be the user's own intentional action (they stopped the
// agent service on purpose) and they must be able to definitively stop the
// sweep rather than being stuck waiting for a reconnect that may never come.
func TestCancelEMSweep_SucceedsWhenAgentDisconnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, engine := minimalPostureScenario(t, "em-01-control-validation")
		store := emsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), engine, testJWTSecret).WithEMSweep(store, testEMSweepDispatcher(store))
		agentID := "em-cancel-disc-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		uid := seedUser(t, pool, "em-cancel-disc-user", "pw-Password1!", "admin", true)

		body, _ := json.Marshal(map[string]any{"agentId": agentID})
		createReq := authedRequest(t, http.MethodPost, "/api/em/sweeps", bytes.NewReader(body), auth.RoleAdmin, uid)
		createRec := callAuthed(h.CreateEMSweep, createReq)
		var created map[string]any
		json.Unmarshal(createRec.Body.Bytes(), &created)
		sweepID, _ := created["id"].(string)
		if sweepID == "" {
			t.Fatalf("no sweep id in create response: %s", createRec.Body.String())
		}
		if err := store.MarkDisconnected(context.Background(), sweepID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		cancelReq := withURLParam(authedRequest(t, http.MethodPost, "/api/em/sweeps/"+sweepID+"/cancel", nil, auth.RoleAdmin, uid), "id", sweepID)
		cancelRec := callAuthed(h.CancelEMSweep, cancelReq)
		if cancelRec.Code != http.StatusOK {
			t.Fatalf("cancel status = %d, want 200 (agent_disconnected must still be cancellable), body = %s", cancelRec.Code, cancelRec.Body.String())
		}

		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM em_sweeps WHERE id = $1`, sweepID).Scan(&status); err != nil {
			t.Fatalf("query status: %v", err)
		}
		if status != "stopped" {
			t.Fatalf("status = %q, want stopped", status)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestCancelEMSweep_SucceedsWhenAgentDisconnected -v`
Expected: FAIL (409 instead of 200, since the guard hasn't been widened yet)

- [ ] **Step 3: `dispatchEMLayer` returns the sentinel for the offline case**

In `orchestrator/internal/api/em_dispatch.go`, add the import:

```go
import (
	"context"
	"fmt"
	"log"
	"regexp"

	"github.com/audspect/bas/internal/emsweep"
)
```

Replace:

```go
	if skip != "" {
		return "", fmt.Errorf("layer skipped: %s", skip)
	}
```

with:

```go
	if skip == "offline" {
		return "", emsweep.ErrAgentOffline
	}
	if skip != "" {
		return "", fmt.Errorf("layer skipped: %s", skip)
	}
```

- [ ] **Step 4: Widen `CancelEMSweep`'s guard, add `disconnectedAt` to the JSON**

In `orchestrator/internal/api/emsweep_handlers.go`, replace:

```go
	if sw.Status != "running" {
		jsonError(w, "sweep is not running (status: "+sw.Status+")", http.StatusConflict)
		return
	}
```

with:

```go
	if sw.Status != "running" && sw.Status != "agent_disconnected" {
		jsonError(w, "sweep is not running (status: "+sw.Status+")", http.StatusConflict)
		return
	}
```

Replace `emSweepToJSON`:

```go
func emSweepToJSON(sw emsweep.Sweep) map[string]any {
	return map[string]any{
		"id": sw.ID, "agentId": sw.AgentID, "layers": sw.Layers, "currentIndex": sw.CurrentIndex,
		"currentLayer": currentEMLayer(sw), "currentScenarioRunId": sw.CurrentScenarioRunID,
		"completedLayers": sw.CompletedLayers, "totalLayers": sw.TotalLayers,
		"status": sw.Status, "error": sw.Error, "createdBy": sw.CreatedBy,
		"startedAt": sw.StartedAt, "completedAt": sw.CompletedAt, "disconnectedAt": sw.DisconnectedAt,
	}
}
```

- [ ] **Step 5: Wire `SetConnected` in `WithEMSweep`**

In `orchestrator/internal/api/handlers.go`, replace:

```go
func (h *Handler) WithEMSweep(store *emsweep.Store, dispatcher *emsweep.Dispatcher) *Handler {
	h.emSweep = store
	dispatcher.SetDispatch(h.dispatchEMLayer)
	// Reuses cancelScenarioRun's existing agent-notify + grace-period +
	// variant_runs-sync behavior for the Dispatcher's stuck-layer backstop,
	// rather than duplicating any of that inside emsweep.
	dispatcher.SetCancel(h.cancelScenarioRun)
	return h
}
```

with:

```go
func (h *Handler) WithEMSweep(store *emsweep.Store, dispatcher *emsweep.Dispatcher) *Handler {
	h.emSweep = store
	dispatcher.SetDispatch(h.dispatchEMLayer)
	// Reuses cancelScenarioRun's existing agent-notify + grace-period +
	// variant_runs-sync behavior for the Dispatcher's stuck-layer backstop,
	// rather than duplicating any of that inside emsweep.
	dispatcher.SetCancel(h.cancelScenarioRun)
	// Lets advance() distinguish "agent disconnected" from "agent connected
	// but genuinely stuck" -- see the Dispatcher's disconnect/resume state
	// machine.
	dispatcher.SetConnected(h.hub.IsAgentConnected)
	return h
}
```

- [ ] **Step 6: Run the full `internal/api` test suite**

Run in background (takes 8–15 minutes):

```bash
cd orchestrator && go test ./internal/api/... -v > /tmp_or_scratchpad/emsweep_task4_full.log 2>&1
```

(Use the session scratchpad path, not `/tmp`, per this session's environment.) Wait for the background completion notification, then read the actual log file in full (not piped/truncated) and confirm `PASS`/`ok` for the package with zero failures.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/em_dispatch.go orchestrator/internal/api/emsweep_handlers.go orchestrator/internal/api/handlers.go orchestrator/internal/api/emsweep_handlers_test.go
git commit -m "feat(emsweep): wire disconnect-awareness into API layer

dispatchEMLayer now returns emsweep.ErrAgentOffline (not a generic error)
when the agent is unreachable, so the dispatcher pauses instead of failing
the sweep. CancelEMSweep now accepts agent_disconnected sweeps too -- Stop
must work regardless of connectivity, since disconnection can be the
user's own intentional action. WithEMSweep wires the dispatcher's new
ConnectedFn to the WS hub's live connectivity check."
git push
```

---

## Task 5: vexsweep data model — mirror of Task 2

**Files:**
- Modify: `orchestrator/internal/vexsweep/sweep.go`
- Modify: `orchestrator/internal/vexsweep/store.go`
- Modify: `orchestrator/internal/db/postgres.go` (append immediately after Task 2's em_sweeps statements)
- Test: `orchestrator/internal/vexsweep/store_test.go`

**Interfaces:**
- Produces: `Sweep.DisconnectedAt *time.Time`; `Store.ListActionable(ctx) ([]Sweep, error)`; `Store.MarkDisconnected(ctx, id string, pendingIndex int) error`; `Store.Resume(ctx, id, variantRunID, scenarioRunID string) error` (two run-ID fields, unlike emsweep's one); widened `Store.GetActiveForAgent`.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/vexsweep/store_test.go`, mirroring Task 2's four new emsweep tests exactly but adapted to vexsweep's shape. Read the existing `internal/vexsweep/store_test.go` first to match its exact `Create`/`AdvanceToNext` call shapes (5-arg `AdvanceToNext(ctx, id, justCompletedVariants, nextIndex, variantRunID, scenarioRunID)` per `dispatcher_test.go`'s usage already confirmed this session), then write:

```go
func TestGetActiveForAgent_TreatsDisconnectedAsActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-disc-active", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{5}, TotalVariants: 5})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}
		got, found, err := store.GetActiveForAgent(ctx, "agent-disc-active")
		if err != nil {
			t.Fatalf("GetActiveForAgent: %v", err)
		}
		if !found || got.ID != sw.ID {
			t.Fatalf("GetActiveForAgent = (%+v, %v), want the disconnected sweep to still count as active", got, found)
		}
	})
}

func TestListActionable_IncludesRunningAndDisconnectedOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		running, err := store.Create(ctx, Sweep{AgentID: "agent-actionable-running", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{5}, TotalVariants: 5})
		if err != nil {
			t.Fatalf("Create running: %v", err)
		}
		disconnected, err := store.Create(ctx, Sweep{AgentID: "agent-actionable-disc", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{5}, TotalVariants: 5})
		if err != nil {
			t.Fatalf("Create disconnected: %v", err)
		}
		if err := store.MarkDisconnected(ctx, disconnected.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}
		stopped, err := store.Create(ctx, Sweep{AgentID: "agent-actionable-stopped", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{5}, TotalVariants: 5})
		if err != nil {
			t.Fatalf("Create stopped: %v", err)
		}
		if err := store.MarkStopped(ctx, stopped.ID); err != nil {
			t.Fatalf("MarkStopped: %v", err)
		}

		got, err := store.ListActionable(ctx)
		if err != nil {
			t.Fatalf("ListActionable: %v", err)
		}
		ids := map[string]bool{}
		for _, sw := range got {
			ids[sw.ID] = true
		}
		if !ids[running.ID] || !ids[disconnected.ID] {
			t.Fatalf("ListActionable() = %+v, want both the running and disconnected sweeps", got)
		}
		if ids[stopped.ID] {
			t.Fatalf("ListActionable() included a stopped sweep: %+v", got)
		}
	})
}

func TestMarkDisconnected_SetsStatusAndClearsCurrentRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-mark-disc", Mode: "sequential", Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{5, 3}, TotalVariants: 8})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-mark-disc", "sr-mark-disc"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q, want agent_disconnected", got.Status)
		}
		if got.DisconnectedAt == nil {
			t.Fatal("DisconnectedAt should be set")
		}
		if got.CurrentScenarioRunID != "" || got.CurrentVariantRunID != "" {
			t.Fatalf("current run IDs = (%q, %q), want both cleared", got.CurrentScenarioRunID, got.CurrentVariantRunID)
		}
		if got.CurrentTechniqueStartedAt != nil {
			t.Fatal("CurrentTechniqueStartedAt should be cleared")
		}
	})
}

func TestResume_ClearsDisconnectedAtAndSetsNewRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{AgentID: "agent-resume", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{5}, TotalVariants: 5})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		if err := store.Resume(ctx, sw.ID, "vr-resumed", "sr-resumed"); err != nil {
			t.Fatalf("Resume: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "running" {
			t.Fatalf("Status = %q, want running", got.Status)
		}
		if got.DisconnectedAt != nil {
			t.Fatal("DisconnectedAt should be cleared")
		}
		if got.CurrentVariantRunID != "vr-resumed" || got.CurrentScenarioRunID != "sr-resumed" {
			t.Fatalf("current run IDs = (%q, %q), want (vr-resumed, sr-resumed)", got.CurrentVariantRunID, got.CurrentScenarioRunID)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/vexsweep/... -run "TestGetActiveForAgent_TreatsDisconnectedAsActive|TestListActionable_IncludesRunningAndDisconnectedOnly|TestMarkDisconnected_SetsStatusAndClearsCurrentRun|TestResume_ClearsDisconnectedAtAndSetsNewRun" -v`
Expected: FAIL to compile.

- [ ] **Step 3: Add the vex_sweeps DB migration**

In `orchestrator/internal/db/postgres.go`, append immediately after Task 2's `em_sweeps` migration statements:

```go
	`ALTER TABLE vex_sweeps ADD COLUMN IF NOT EXISTS disconnected_at timestamptz`,
	`DROP INDEX IF EXISTS idx_vex_sweeps_one_running_per_agent`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_vex_sweeps_one_running_per_agent
		ON vex_sweeps (agent_id) WHERE status IN ('running', 'agent_disconnected')`,
```

- [ ] **Step 4: Add `DisconnectedAt` to the vexsweep `Sweep` struct**

In `orchestrator/internal/vexsweep/sweep.go`, add after `CompletedAt *time.Time`:

```go
	// DisconnectedAt is when the Dispatcher last detected the agent was
	// unreachable (nil while running normally, or once resumed). See
	// dispatcher.go's advance() disconnect/resume state machine.
	DisconnectedAt *time.Time
```

- [ ] **Step 5: Update `sweepCols`/`scanSweep`, widen `GetActiveForAgent`**

In `orchestrator/internal/vexsweep/store.go`, replace `sweepCols`:

```go
const sweepCols = `id, agent_id, mode, include_advanced, techniques, technique_variant_counts, base_types,
	current_index, current_variant_run_id, current_scenario_run_id, current_technique_started_at,
	completed_variants, total_variants, status, error, created_by, started_at, completed_at, disconnected_at`
```

Replace `scanSweep`'s `Scan` call, adding the new field at the end:

```go
	err := row.Scan(&sw.ID, &sw.AgentID, &sw.Mode, &sw.IncludeAdvanced, &sw.Techniques, &sw.TechniqueVariantCounts, &sw.BaseTypes,
		&sw.CurrentIndex, &sw.CurrentVariantRunID, &sw.CurrentScenarioRunID, &sw.CurrentTechniqueStartedAt,
		&sw.CompletedVariants, &sw.TotalVariants, &sw.Status, &sw.Error, &sw.CreatedBy, &sw.StartedAt, &sw.CompletedAt, &sw.DisconnectedAt)
```

Replace `GetActiveForAgent`'s query:

```go
func (s *Store) GetActiveForAgent(ctx context.Context, agentID string) (Sweep, bool, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+sweepCols+` FROM vex_sweeps WHERE agent_id = $1 AND status IN ('running', 'agent_disconnected')`, agentID)
```

- [ ] **Step 6: Add `ListActionable`, `MarkDisconnected`, `Resume`**

In `orchestrator/internal/vexsweep/store.go`, add after `ListByStatus`:

```go
// ListActionable returns every sweep the Dispatcher must keep ticking:
// actively running, or paused waiting for its agent to reconnect. Distinct
// from ListRunning (status='running' only).
func (s *Store) ListActionable(ctx context.Context) ([]Sweep, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+sweepCols+` FROM vex_sweeps WHERE status IN ('running', 'agent_disconnected') ORDER BY started_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sweep
	for rows.Next() {
		sw, err := scanSweep(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	return out, rows.Err()
}
```

Add after `AdvanceToNext`:

```go
// MarkDisconnected pauses a sweep whose agent is no longer reachable.
// pendingIndex is the technique index to re-dispatch on reconnect -- see
// internal/emsweep/store.go's identical method for the full rationale.
func (s *Store) MarkDisconnected(ctx context.Context, id string, pendingIndex int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps
		    SET status = 'agent_disconnected', disconnected_at = NOW(),
		        current_index = $2, current_variant_run_id = '', current_scenario_run_id = '', current_technique_started_at = NULL
		  WHERE id = $1`,
		id, pendingIndex)
	return err
}

// Resume un-pauses a sweep after its agent reconnects. The caller has
// already re-dispatched Techniques[current_index] as a fresh run and passes
// both resulting IDs here; current_index itself is left unchanged.
func (s *Store) Resume(ctx context.Context, id, variantRunID, scenarioRunID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE vex_sweeps
		    SET status = 'running', disconnected_at = NULL,
		        current_variant_run_id = $2, current_scenario_run_id = $3, current_technique_started_at = NOW()
		  WHERE id = $1`,
		id, variantRunID, scenarioRunID)
	return err
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/vexsweep/... -v`
Expected: PASS — every test in the package.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/vexsweep/sweep.go orchestrator/internal/vexsweep/store.go orchestrator/internal/vexsweep/store_test.go orchestrator/internal/db/postgres.go
git commit -m "feat(vexsweep): add agent_disconnected data model

Mirrors the emsweep change from the same session: new disconnected_at
column, ListActionable/MarkDisconnected/Resume store methods, and a
widened one-active-sweep-per-agent index -- adapted for vexsweep's two
run-ID fields (variant + scenario)."
git push
```

---

## Task 6: vexsweep dispatcher — mirror of Task 3

**Files:**
- Modify: `orchestrator/internal/vexsweep/dispatcher.go`
- Test: `orchestrator/internal/vexsweep/dispatcher_test.go`

**Interfaces:**
- Consumes: `Store.ListActionable`, `Store.MarkDisconnected`, `Store.Resume` (Task 5).
- Produces: `type ConnectedFn func(agentID string) bool`; `func (d *Dispatcher) SetConnected(fn ConnectedFn)`; `var ErrAgentOffline = errors.New(...)`. Consumed by Task 7.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/vexsweep/dispatcher_test.go`, mirroring Task 3's five new emsweep dispatcher tests, adapted for vexsweep's `DispatchFn` signature (`func(ctx, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (scenarioRunID, variantRunID string, totalVariants int, err error)`) and `CancelFn`/`StatusFn` shapes already shown in the existing file:

```go
// TestDispatcher_Tick_PausesOnDisconnectAndCancelsInFlightRun mirrors
// internal/emsweep/dispatcher_test.go's identical test -- see there for the
// full rationale (this is the regression test for the actual bug report).
func TestDispatcher_Tick_PausesOnDisconnectAndCancelsInFlightRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-disc-1", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-disc-1", "sr-disc-1"); err != nil {
			t.Fatalf("seed AdvanceToNext: %v", err)
		}

		var cancelledRunIDs []string
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			t.Fatal("dispatch should not be called -- the sweep must pause, not advance")
			return "", "", 0, nil
		})
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			cancelledRunIDs = append(cancelledRunIDs, scenarioRunID)
			return "agent-disc-1", "partial", nil
		})
		d.SetConnected(func(agentID string) bool { return false })

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q, want agent_disconnected", got.Status)
		}
		if len(cancelledRunIDs) != 1 || cancelledRunIDs[0] != "sr-disc-1" {
			t.Fatalf("cancelledRunIDs = %v, want exactly [sr-disc-1]", cancelledRunIDs)
		}
		if got.CurrentIndex != 0 {
			t.Fatalf("CurrentIndex = %d, want 0", got.CurrentIndex)
		}
	})
}

func TestDispatcher_Tick_WaitsIndefinitelyWhileDisconnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-disc-2", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{5}, TotalVariants: 5,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			t.Fatal("status should not be checked -- no run is in flight while disconnected")
			return "", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			t.Fatal("dispatch should not be called -- agent is still offline")
			return "", "", 0, nil
		})
		d.SetCancel(func(ctx context.Context, scenarioRunID string) (string, string, error) {
			t.Fatal("cancel should not be called -- nothing is in flight while disconnected")
			return "", "", nil
		})
		d.stuckThreshold = time.Millisecond
		d.SetConnected(func(agentID string) bool { return false })

		time.Sleep(5 * time.Millisecond)

		for i := 0; i < 3; i++ {
			if err := d.Tick(ctx); err != nil {
				t.Fatalf("Tick %d: %v", i, err)
			}
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q after 3 ticks while still offline, want agent_disconnected", got.Status)
		}
	})
}

func TestDispatcher_Tick_ResumesInterruptedTechniqueOnReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-disc-3", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{33, 12}, TotalVariants: 45,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 1); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		var dispatchedTechniques []string
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			t.Fatal("status should not be checked this tick")
			return "", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			dispatchedTechniques = append(dispatchedTechniques, techniqueID)
			if techniqueIndex != 1 {
				t.Fatalf("techniqueIndex = %d, want 1", techniqueIndex)
			}
			return "sr-resumed", "vr-resumed", 12, nil
		})
		d.SetConnected(func(agentID string) bool { return true })

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatchedTechniques) != 1 || dispatchedTechniques[0] != "T1059.003" {
			t.Fatalf("dispatchedTechniques = %v, want [T1059.003]", dispatchedTechniques)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "running" {
			t.Fatalf("Status = %q, want running", got.Status)
		}
		if got.CurrentVariantRunID != "vr-resumed" || got.CurrentScenarioRunID != "sr-resumed" {
			t.Fatalf("current run IDs = (%q, %q), want (vr-resumed, sr-resumed)", got.CurrentVariantRunID, got.CurrentScenarioRunID)
		}
	})
}

func TestDispatcher_Tick_ExistingBehaviorUnaffectedWhenConnectedFnNotSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-no-connected-fn", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{5}, TotalVariants: 5,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		var dispatched []string
		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			dispatched = append(dispatched, techniqueID)
			return "sr-1", "vr-1", 5, nil
		})

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		if len(dispatched) != 1 {
			t.Fatalf("dispatched = %v, want exactly 1 dispatch", dispatched)
		}
	})
}

func TestDispatcher_Tick_PausesInsteadOfFailingOnOfflineRaceDuringDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		sw, err := store.Create(ctx, Sweep{
			AgentID: "agent-race-1", Mode: "sequential", Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{5}, TotalVariants: 5,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		d := NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
			return "running", nil
		})
		d.SetDispatch(func(ctx context.Context, sweepID, agentID, techniqueID, baseType, mode string, includeAdvanced bool, techniqueIndex, totalTechniques int) (string, string, int, error) {
			return "", "", 0, ErrAgentOffline
		})
		d.SetConnected(func(agentID string) bool { return true })

		if err := d.Tick(ctx); err != nil {
			t.Fatalf("Tick: %v", err)
		}
		got, _ := store.Get(ctx, sw.ID)
		if got.Status != "agent_disconnected" {
			t.Fatalf("Status = %q, want agent_disconnected (not failed)", got.Status)
		}
		if got.CurrentIndex != 0 {
			t.Fatalf("CurrentIndex = %d, want 0", got.CurrentIndex)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/vexsweep/... -run "TestDispatcher_Tick_PausesOnDisconnect|TestDispatcher_Tick_WaitsIndefinitely|TestDispatcher_Tick_ResumesInterrupted|TestDispatcher_Tick_ExistingBehaviorUnaffected|TestDispatcher_Tick_PausesInsteadOfFailing" -v`
Expected: FAIL to compile.

- [ ] **Step 3: Implement, mirroring Task 3 exactly**

In `orchestrator/internal/vexsweep/dispatcher.go`:

Add `"errors"` to imports.

Add after the `CancelFn` type:

```go
// ConnectedFn reports whether a specific agent currently has a live
// connection. See internal/emsweep/dispatcher.go's identical type for the
// full rationale.
type ConnectedFn func(agentID string) bool

// ErrAgentOffline is the sentinel a DispatchFn implementation returns when
// a technique failed to dispatch specifically because its agent is
// unreachable. See internal/emsweep/dispatcher.go's identical sentinel.
var ErrAgentOffline = errors.New("vexsweep: agent offline")
```

Add `connected ConnectedFn` to the `Dispatcher` struct, and:

```go
func (d *Dispatcher) SetConnected(fn ConnectedFn) { d.connected = fn }
```

Replace `Tick`'s `d.store.ListRunning(ctx)` with `d.store.ListActionable(ctx)` (comment identical to Task 3's).

Replace `advance()` with:

```go
func (d *Dispatcher) advance(ctx context.Context, sw Sweep) {
	if d.connected != nil && !d.connected(sw.AgentID) {
		if sw.Status == "running" {
			d.handleDisconnect(ctx, sw)
		}
		return
	}
	if sw.Status == "agent_disconnected" {
		d.resume(ctx, sw)
		return
	}

	if sw.CurrentVariantRunID != "" {
		status, err := d.status(ctx, sw.CurrentVariantRunID)
		if err != nil {
			log.Printf("[vexsweep] status check failed for sweep %s variant_run %s: %v", sw.ID, sw.CurrentVariantRunID, err)
			d.maybeForceCancelStuck(ctx, sw)
			return
		}
		if status == "running" {
			d.maybeForceCancelStuck(ctx, sw)
			return
		}
		delete(d.cancelTriggeredForRun, sw.CurrentScenarioRunID)
		d.dispatchNext(ctx, sw, sw.TechniqueVariantCounts[sw.CurrentIndex])
		return
	}
	d.dispatchNext(ctx, sw, 0)
}

// handleDisconnect pauses a running sweep once its agent is found
// unreachable. See internal/emsweep/dispatcher.go's identical method for
// the full rationale.
func (d *Dispatcher) handleDisconnect(ctx context.Context, sw Sweep) {
	if sw.CurrentScenarioRunID != "" && d.cancel != nil {
		if _, _, err := d.cancel(ctx, sw.CurrentScenarioRunID); err != nil {
			log.Printf("[vexsweep] cancel in-flight run %s for disconnected sweep %s: %v", sw.CurrentScenarioRunID, sw.ID, err)
		}
	}
	if err := d.store.MarkDisconnected(ctx, sw.ID, sw.CurrentIndex); err != nil {
		log.Printf("[vexsweep] mark sweep %s agent_disconnected: %v", sw.ID, err)
		return
	}
	log.Printf("[vexsweep] sweep %s paused: agent %s disconnected", sw.ID, sw.AgentID)
}

// resume re-dispatches the pending technique once the agent is reachable
// again. See internal/emsweep/dispatcher.go's identical method for the
// full rationale.
func (d *Dispatcher) resume(ctx context.Context, sw Sweep) {
	if d.dispatch == nil {
		return
	}
	baseType := "art"
	if sw.CurrentIndex < len(sw.BaseTypes) && sw.BaseTypes[sw.CurrentIndex] != "" {
		baseType = sw.BaseTypes[sw.CurrentIndex]
	}
	scenarioRunID, variantRunID, _, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Techniques[sw.CurrentIndex], baseType, sw.Mode, sw.IncludeAdvanced, sw.CurrentIndex, len(sw.Techniques))
	if err != nil {
		if errors.Is(err, ErrAgentOffline) {
			if merr := d.store.MarkDisconnected(ctx, sw.ID, sw.CurrentIndex); merr != nil {
				log.Printf("[vexsweep] re-mark sweep %s agent_disconnected after failed resume: %v", sw.ID, merr)
			}
			return
		}
		if merr := d.store.MarkFailed(ctx, sw.ID, err.Error()); merr != nil {
			log.Printf("[vexsweep] mark sweep %s failed after resume attempt: %v", sw.ID, merr)
		}
		return
	}
	if err := d.store.Resume(ctx, sw.ID, variantRunID, scenarioRunID); err != nil {
		log.Printf("[vexsweep] resume sweep %s: %v", sw.ID, err)
		return
	}
	log.Printf("[vexsweep] sweep %s resumed: agent %s reconnected, re-dispatched technique %s", sw.ID, sw.AgentID, sw.Techniques[sw.CurrentIndex])
}
```

In `dispatchNext`, replace the dispatch-error block:

```go
	baseType := "art"
	if nextIdx < len(sw.BaseTypes) && sw.BaseTypes[nextIdx] != "" {
		baseType = sw.BaseTypes[nextIdx]
	}
	scenarioRunID, variantRunID, _, err := d.dispatch(ctx, sw.ID, sw.AgentID, sw.Techniques[nextIdx], baseType, sw.Mode, sw.IncludeAdvanced, nextIdx, len(sw.Techniques))
	if err != nil {
		if errors.Is(err, ErrAgentOffline) {
			if merr := d.store.MarkDisconnected(ctx, sw.ID, nextIdx); merr != nil {
				log.Printf("[vexsweep] mark sweep %s agent_disconnected (offline race): %v", sw.ID, merr)
			}
			return
		}
		// Deliberately does not fall through to the next technique -- a
		// silently-skipped technique in a security-validation sweep is
		// worse than a sweep that stops and says why. See design spec
		// Architecture §2.
		if merr := d.store.MarkFailed(ctx, sw.ID, err.Error()); merr != nil {
			log.Printf("[vexsweep] mark sweep %s failed: %v", sw.ID, merr)
		}
		return
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/vexsweep/... -v`
Expected: PASS — every test in the package.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/vexsweep/dispatcher.go orchestrator/internal/vexsweep/dispatcher_test.go
git commit -m "feat(vexsweep): dispatcher pauses on disconnect, resumes on reconnect

Mirrors the emsweep dispatcher change from the same session -- see that
commit for the full root-cause rationale, identical in both packages."
git push
```

---

## Task 7: vexsweep integration — mirror of Task 4

**Files:**
- Modify: `orchestrator/internal/api/variant_handlers.go` (`dispatchVariantForSweep`, line 687)
- Modify: `orchestrator/internal/api/vexsweep_handlers.go`
- Modify: `orchestrator/internal/api/handlers.go` (`WithVexSweep`, lines 414-422)
- Test: `orchestrator/internal/api/vexsweep_handlers_test.go` (or wherever `CancelVexSweep`'s existing test lives — locate it first with `grep -rn "func TestCancelVexSweep" orchestrator/internal/api/`)

**Interfaces:**
- Consumes: `vexsweep.ErrAgentOffline`, `Dispatcher.SetConnected` (Task 6); `h.hub.IsAgentConnected` (Task 1).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/vexsweep_handlers_test.go`, right after `TestCancelVexSweep_StopsSweepAndCancelsCurrentRun` (mirrors its exact setup, verified against the file's real content — note this file builds the sweep directly via `store.Create`/`AdvanceToNext` and a manual `scenario_runs` insert, unlike the EM test which goes through the `CreateEMSweep` HTTP handler):

```go
// TestCancelVexSweep_SucceedsWhenAgentDisconnected mirrors
// TestCancelEMSweep_SucceedsWhenAgentDisconnected -- see there for the full
// rationale (the "no option of Stop after the agent disconnected" report).
func TestCancelVexSweep_SucceedsWhenAgentDisconnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-cancel-disc')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-cancel-disc", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
		userID := seedUser(t, pool, "sweep-cancel-disc-user", "password123", "admin", true)
		req := authedRequest(t, http.MethodPost, "/api/vex/sweeps/"+sw.ID+"/cancel", nil, auth.RoleAdmin, userID)
		req = withURLParam(req, "id", sw.ID)
		rec := callAuthed(h.CancelVexSweep, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (agent_disconnected must still be cancellable), body: %s", rec.Code, rec.Body.String())
		}

		got, err := store.Get(ctx, sw.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Status != "stopped" {
			t.Errorf("Status = %q, want %q", got.Status, "stopped")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestCancelVexSweep_SucceedsWhenAgentDisconnected -v`
Expected: FAIL (409 instead of 200)

- [ ] **Step 3: `dispatchVariantForSweep` returns the sentinel for the offline case**

Read `orchestrator/internal/api/variant_handlers.go` around line 687 (`dispatchVariantForSweep`) in full first to find its exact offline/skip handling (this session's earlier summary notes it's "structurally analogous to dispatchEMLayer but much simpler" and delegates to `h.dispatchRun` the same way — locate the equivalent `if skip != ""` block and apply the identical `if skip == "offline" { return "", "", 0, vexsweep.ErrAgentOffline }` change, adjusted for this function's 4-return-value signature). Add the `"github.com/audspect/bas/internal/vexsweep"` import if not already present in this file (check first — `vexsweep_handlers.go` already imports it, but `variant_handlers.go` may not).

- [ ] **Step 4: Widen `CancelVexSweep`'s guard, add `disconnectedAt` to `sweepToJSON`**

In `orchestrator/internal/api/vexsweep_handlers.go`, replace:

```go
	if sw.Status != "running" {
		jsonError(w, "sweep is not running (status: "+sw.Status+")", http.StatusConflict)
		return
	}
```

with:

```go
	if sw.Status != "running" && sw.Status != "agent_disconnected" {
		jsonError(w, "sweep is not running (status: "+sw.Status+")", http.StatusConflict)
		return
	}
```

Add `"disconnectedAt": sw.DisconnectedAt,` to `sweepToJSON`'s returned map (find its `map[string]any{...}` literal, read the function in full first since only its opening lines were seen this session, and add the field alongside the existing `startedAt`/`completedAt` entries).

- [ ] **Step 5: Wire `SetConnected` in `WithVexSweep`**

In `orchestrator/internal/api/handlers.go`, replace:

```go
func (h *Handler) WithVexSweep(store *vexsweep.Store, dispatcher *vexsweep.Dispatcher) *Handler {
	h.vexSweep = store
	dispatcher.SetDispatch(h.dispatchVariantForSweep)
	// Reuses cancelScenarioRun's existing agent-notify + grace-period +
	// variant_runs-sync behavior for the Dispatcher's stuck-technique
	// backstop, rather than duplicating any of that inside vexsweep.
	dispatcher.SetCancel(h.cancelScenarioRun)
	return h
}
```

with:

```go
func (h *Handler) WithVexSweep(store *vexsweep.Store, dispatcher *vexsweep.Dispatcher) *Handler {
	h.vexSweep = store
	dispatcher.SetDispatch(h.dispatchVariantForSweep)
	// Reuses cancelScenarioRun's existing agent-notify + grace-period +
	// variant_runs-sync behavior for the Dispatcher's stuck-technique
	// backstop, rather than duplicating any of that inside vexsweep.
	dispatcher.SetCancel(h.cancelScenarioRun)
	// Lets advance() distinguish "agent disconnected" from "agent connected
	// but genuinely stuck" -- see the Dispatcher's disconnect/resume state
	// machine.
	dispatcher.SetConnected(h.hub.IsAgentConnected)
	return h
}
```

- [ ] **Step 6: Run the full `internal/api` test suite**

Same background + full-log-tail procedure as Task 4 Step 6.

- [ ] **Step 7: Run `TestRBACMatrix_NoDrift` explicitly**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS — no routes were added or removed in this plan (only `CancelEMSweep`/`CancelVexSweep`'s internal status guard changed), so the matrix should need no updates. If this fails, something touched a route unexpectedly — stop and investigate before continuing.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/variant_handlers.go orchestrator/internal/api/vexsweep_handlers.go orchestrator/internal/api/handlers.go orchestrator/internal/api/vexsweep_handlers_test.go
git commit -m "feat(vexsweep): wire disconnect-awareness into API layer

Mirrors the emsweep integration from the same session: dispatchVariantForSweep
returns vexsweep.ErrAgentOffline for the offline case, CancelVexSweep
accepts agent_disconnected sweeps, WithVexSweep wires SetConnected."
git push
```

---

## Task 8: Frontend — status display and Stop actions

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `disconnectedAt` field on both sweep JSON responses (Tasks 4, 7); `agent_disconnected` as a possible `sw.status` value everywhere sweep status is read.

- [ ] **Step 1: Add the CSS class**

Add after the existing `.s-stopped::before` rule (index.html:538, in the `/* ── Status badges ─────────────────────────────────────────── */` block):

```css
.s-agent_disconnected { background: var(--warning-dim); color: #fbbf24; border: 1px solid var(--warning-border); }
.s-agent_disconnected::before { background: #fbbf24; }
```

(Reuses the exact same warning palette `.s-partial`/`.s-stopped` already use — no new color introduced.)

- [ ] **Step 2: Add a shared status-label helper**

Add immediately before `renderSweepRow` (index.html:11149):

```js
// sweepStatusLabel maps a sweep's raw status to display text. Every status
// except agent_disconnected already reads fine verbatim (CSS capitalizes
// the first letter) -- agent_disconnected needs an explicit mapping since
// its underscore would otherwise render literally ("Agent_disconnected").
function sweepStatusLabel(status) {
  return status === 'agent_disconnected' ? 'Agent Disconnected' : status;
}
```

- [ ] **Step 3: Update `renderSweepRow` (Full Variant Sweep's Live Runs row)**

Replace:

```js
    '<td><span class="sbadge s-' + x(sw.status) + '">' + x(sw.status) + '</span></td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + x(sw.createdBy || '—') + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(sw.startedAt) + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + (sw.completedAt ? fmtDate(sw.completedAt) : '—') + '</td>' +
    '<td><button class="btn btn-outline btn-sm" onclick="openSweepDrilldown(\'' + x(sw.id) + '\')" title="View every technique this sweep dispatched">' +
        x(progressLabel) + ' — ' + badge + '</button></td>' +
    '<td>—</td></tr>';
```

with:

```js
    '<td><span class="sbadge s-' + x(sw.status) + '">' + x(sweepStatusLabel(sw.status)) + '</span></td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + x(sw.createdBy || '—') + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(sw.startedAt) + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + (sw.completedAt ? fmtDate(sw.completedAt) : '—') + '</td>' +
    '<td><button class="btn btn-outline btn-sm" onclick="openSweepDrilldown(\'' + x(sw.id) + '\')" title="View every technique this sweep dispatched">' +
        x(progressLabel) + ' — ' + badge + '</button></td>' +
    '<td>' + ((sw.status === 'running' || sw.status === 'agent_disconnected')
      ? '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)" onclick="stopVexSweep(\'' + x(sw.id) + '\')">&#9632; Stop</button>'
      : '—') + '</td></tr>';
```

- [ ] **Step 4: Update `renderEMSweepRow`**

First, refactor `stopEMSweep()` (index.html:19569) to accept an explicit sweep ID, since the row-level Stop button needs to work without the progress drawer being open (the drawer's own global `_emSweepCurrentId` isn't set unless the drawer is currently open):

Replace:

```js
function stopEMSweep() {
  if (!_emSweepCurrentId) return;
  if (!confirm('Stop this EM sweep? The current layer keeps running to completion but no further layers will be dispatched.')) return;
  apicall('/api/em/sweeps/' + encodeURIComponent(_emSweepCurrentId) + '/cancel', { method: 'POST' }).then(function() {
    pollEMSweepProgress();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

with:

```js
function stopEMSweep(sweepId) {
  sweepId = sweepId || _emSweepCurrentId;
  if (!sweepId) return;
  if (!confirm('Stop this EM sweep? The current layer keeps running to completion but no further layers will be dispatched.')) return;
  apicall('/api/em/sweeps/' + encodeURIComponent(sweepId) + '/cancel', { method: 'POST' }).then(function() {
    if (sweepId === _emSweepCurrentId) pollEMSweepProgress();
    loadRuns();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

Update the drawer's own Stop button call site (index.html:4700) to keep passing the drawer's current sweep explicitly:

```html
<button class="btn btn-outline-red btn-sm" id="em-sweep-stop-btn" onclick="stopEMSweep(_emSweepCurrentId)">&#9632; Stop Sweep</button>
```

Now update `renderEMSweepRow` — replace:

```js
    '<td><span class="sbadge s-' + x(sw.status) + '">' + x(sw.status) + '</span></td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + x(sw.createdBy || '—') + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(sw.startedAt) + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + (sw.completedAt ? fmtDate(sw.completedAt) : '—') + '</td>' +
    '<td><button class="btn btn-outline btn-sm" onclick="openEMSweepProgress(\'' + x(sw.id) + '\')" title="View every EM layer this sweep dispatched">' +
        x(sw.completedLayers + '/' + sw.totalLayers + ' layers') + ' — ' + badge + '</button></td>' +
    '<td>—</td></tr>';
```

with:

```js
    '<td><span class="sbadge s-' + x(sw.status) + '">' + x(sweepStatusLabel(sw.status)) + '</span></td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + x(sw.createdBy || '—') + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + fmtDate(sw.startedAt) + '</td>' +
    '<td style="color:var(--muted);font-size:0.78rem">' + (sw.completedAt ? fmtDate(sw.completedAt) : '—') + '</td>' +
    '<td><button class="btn btn-outline btn-sm" onclick="openEMSweepProgress(\'' + x(sw.id) + '\')" title="View every EM layer this sweep dispatched">' +
        x(sw.completedLayers + '/' + sw.totalLayers + ' layers') + ' — ' + badge + '</button></td>' +
    '<td>' + ((sw.status === 'running' || sw.status === 'agent_disconnected')
      ? '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger)" onclick="stopEMSweep(\'' + x(sw.id) + '\')">&#9632; Stop</button>'
      : '—') + '</td></tr>';
```

- [ ] **Step 5: Fix the EM drawer's own Stop button visibility gate and status line**

Replace (index.html:19566):

```js
  var stopBtn = document.getElementById('em-sweep-stop-btn');
  stopBtn.style.display = sw.status === 'running' ? '' : 'none';
```

with:

```js
  var stopBtn = document.getElementById('em-sweep-stop-btn');
  stopBtn.style.display = (sw.status === 'running' || sw.status === 'agent_disconnected') ? '' : 'none';
```

Replace the status line in `renderEMSweepProgress` (index.html:19528):

```js
    '<strong>' + sw.completedLayers + '/' + sw.totalLayers + '</strong> layers complete &middot; status: ' + x(sw.status) +
```

with:

```js
    '<strong>' + sw.completedLayers + '/' + sw.totalLayers + '</strong> layers complete &middot; status: ' + x(sweepStatusLabel(sw.status)) +
```

- [ ] **Step 6: Widen `pollEMSweepProgress`'s stop-polling condition**

Replace (index.html:19518):

```js
    if (sw.status !== 'running' && _emSweepPollTimer) {
```

with:

```js
    if (sw.status !== 'running' && sw.status !== 'agent_disconnected' && _emSweepPollTimer) {
```

(Otherwise the drawer would stop polling entirely once paused, and never notice a reconnect while it's open.)

- [ ] **Step 7: Widen `pollVexSweeps` to also fetch disconnected sweeps**

Replace:

```js
function pollVexSweeps() {
  apicall('/api/vex/sweeps?status=running').then(function(sweeps) {
    sweeps = sweeps || [];
```

with:

```js
function pollVexSweeps() {
  // Also fetch agent_disconnected sweeps -- otherwise a paused sweep
  // vanishes from this list entirely (the endpoint only ever returns one
  // status per call) and reportVexSweepFinished's completion-detection
  // logic below would misreport it as finished.
  Promise.all([
    apicall('/api/vex/sweeps?status=running'),
    apicall('/api/vex/sweeps?status=agent_disconnected')
  ]).then(function(results) {
    var sweeps = (results[0] || []).concat(results[1] || []);
```

Update the function's closing `}).catch(...)` line if needed to match the new `Promise.all([...]).then(...)` structure (the rest of the function body — `currentIds`, the completion-detection loop, `renderVexSweepList(sweeps)` — stays unchanged, just re-indent if the diff tool requires it).

- [ ] **Step 8: Add a disconnected indicator to `renderVexSweepList`'s card**

In `renderVexSweepList` (index.html:18119), replace the percent/technique line:

```js
    return '<div class="card" style="margin-top:0.5rem;padding:0.75rem 1rem" id="vex-sweep-card-' + x(sw.id) + '">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;font-size:0.78rem;margin-bottom:0.3rem">' +
        '<span style="font-weight:600">' + x(sw.agentId) + '</span>' +
        '<span style="display:flex;align-items:center;gap:0.6rem">' +
          '<span style="font-weight:700;color:var(--accent)">' + pct + '%</span>' +
          '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger);padding:2px 8px;font-size:0.7rem" onclick="stopVexSweep(\'' + x(sw.id) + '\')">&#9632; Stop</button>' +
        '</span>' +
      '</div>' +
```

with:

```js
    var disconnected = sw.status === 'agent_disconnected';
    return '<div class="card" style="margin-top:0.5rem;padding:0.75rem 1rem" id="vex-sweep-card-' + x(sw.id) + '">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;font-size:0.78rem;margin-bottom:0.3rem">' +
        '<span style="font-weight:600">' + x(sw.agentId) +
          (disconnected ? ' <span class="sbadge s-agent_disconnected">Agent Disconnected</span>' : '') + '</span>' +
        '<span style="display:flex;align-items:center;gap:0.6rem">' +
          (disconnected ? '' : '<span style="font-weight:700;color:var(--accent)">' + pct + '%</span>') +
          '<button class="btn btn-outline btn-sm" style="color:var(--danger);border-color:var(--danger);padding:2px 8px;font-size:0.7rem" onclick="stopVexSweep(\'' + x(sw.id) + '\')">&#9632; Stop</button>' +
        '</span>' +
      '</div>' +
```

- [ ] **Step 9: JS syntax check**

Extract every `<script>` block from `orchestrator/wwwroot/index.html` into a scratchpad file and run `node --check` on it via the PowerShell tool, per this session's established convention. Expected: no syntax errors.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(ui): surface agent-disconnected sweeps in Live Runs

Both sweep row renderers now show a distinct 'Agent Disconnected' badge
instead of a stale 'Running', and both gain a direct Stop button in the
actions cell -- previously the only way to stop a sweep was to open its
progress drawer first, and the drawer's own Stop button was itself hidden
whenever status wasn't exactly 'running' (so it disappeared right when a
disconnected user needed it most). pollVexSweeps now also fetches
agent_disconnected sweeps, which the old single-status query would have
made simply vanish from the Full Variant Sweep panel."
git push
```

---

## Task 9: Full verification and handoff

**Files:** none (verification only)

- [ ] **Step 1: Run the full `internal/api`, `internal/emsweep`, and `internal/vexsweep` test suites together**

Run in background (8–15 minutes):

```bash
cd orchestrator && go test ./internal/api/... ./internal/emsweep/... ./internal/vexsweep/... ./internal/ws/... -v > <scratchpad>/sweep_disconnect_final.log 2>&1
```

Wait for the background completion notification, then read the actual full log file (never a piped/truncated capture) and confirm every package reports `ok`.

- [ ] **Step 2: Run the broader build to catch any compile-time regression elsewhere**

Run: `cd orchestrator && go build ./...`
Expected: no errors (confirms nothing outside the touched packages references the old `ListRunning`-only `Tick` behavior, old `stopEMSweep()` no-arg call sites, etc.)

- [ ] **Step 3: Announce completion and hand off**

Report to the user: both sweep types now pause (not fail) on disconnect, show "Agent Disconnected" in Live Runs with a direct Stop button, and resume the interrupted layer/technique from scratch on reconnect. Then use the **finishing-a-development-branch** skill to verify tests one more time, detect the environment, and present the standard merge/PR/keep-as-is menu — per this session's established preference for **inline execution**, this plan is expected to run directly on `main` in the working tree shown in this session's git status (not an isolated worktree), so the "normal repo" 3-option menu applies unless the user has since switched branches.
