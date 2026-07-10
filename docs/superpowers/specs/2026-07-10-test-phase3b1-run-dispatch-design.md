# Phase 3b.1: Run Dispatch — Test Design

## Goal

Build a regression suite for `dispatchRun` (the shared per-agent dispatch core) and `RunScenario` (its HTTP entry point) in `internal/api` — the decision engine that determines whether an agent is eligible to run a scenario, what actually gets sent to it, and under what guardrails. Per the user-directed risk ordering, this is the first sub-phase of "Scenario & Run Lifecycle" (3b) tackled, ahead of Result Ingestion (3b.2) and Scenario Authoring (3b.3), because a regression here can cause campaigns to fail silently or execute incorrectly.

## A genuine bug found and fixed as part of this phase

Tracing the concurrency guard closely revealed a real TOCTOU race: `dispatchRun`'s "one scenario at a time per agent" check is a plain `SELECT` for an existing `'running'` row, with no row lock and no DB-level uniqueness constraint, followed by an unconditional `INSERT`. Two concurrent dispatch requests to the same *idle* agent can both pass the `SELECT` (neither sees a running row yet) and both `INSERT` a `'running'` row — violating the documented one-at-a-time invariant and potentially double-executing a scenario on one endpoint.

**Fix** (matches an existing pattern already used twice in this codebase, in `internal/relationships` and `internal/verification`, for the identical class of problem):
1. `internal/db/postgres.go`: add `CREATE UNIQUE INDEX IF NOT EXISTS idx_scenario_runs_agent_running ON scenario_runs(agent_id) WHERE status = 'running'` to `EnsureSchema`'s migration list, right after the existing `scenario_runs` migrations.
2. `internal/api/handlers.go`: add an `isUniqueViolation(err error) bool` helper (identical to `relationships`/`verification`'s copy: `errors.As` to `interface{ SQLState() string }`, check `== "23505"`). In `dispatchRun`, when the `INSERT INTO scenario_runs` fails, check `isUniqueViolation(err)` first — if true, return `("", "agent busy", nil)` (the losing side of the race reports the same outcome a pre-existing running row would) instead of surfacing a raw error.

This is a minimal, precedented fix — not a redesign of the concurrency guard.

## Scope

**In scope:** `dispatchRun`, `RunScenario`, `classifyAgentOS`, plus the schema/handler fix above.

**Out of scope:** Scenario CRUD (3b.3), `SubmitScenarioResult`/`ListScenarioRuns`/`CancelRun` (3b.2), `internal/scenario`'s own ART/Caldera catalog validation (`UnknownTechniques` — a different package's future test phase; here we only test the `artStore == nil` → 503 branch, which is this handler's own logic), Caldera-ability/adversary step building (requires a live Caldera connection — test scenarios use plain `Command`-based steps, which `scenario.BuildSteps` resolves without `calderaURL`/`artStore`).

## Test infrastructure

### Generic fake-agent WebSocket helper
Not dispatch-specific — a small reusable type any future `internal/api` test touching `ws.Hub` can use:

```go
type fakeAgent struct {
    agentID  string
    conn     *websocket.Conn
    received chan models.WSMessage
    done     chan struct{}
}

func startFakeAgent(t *testing.T, hub *ws.Hub, agentID string) *fakeAgent
func (f *fakeAgent) WaitForMessage(t *testing.T, timeout time.Duration) models.WSMessage
func (f *fakeAgent) Disconnect()
func (f *fakeAgent) Reconnect(t *testing.T, hub *ws.Hub)
```

`startFakeAgent` wraps `hub.ServeAgentWS` in an `httptest.Server`, dials it with a real `gorilla/websocket` client using `?agentId=<id>`, and runs a background goroutine that reads every incoming frame, unmarshals it as `models.WSMessage`, and pushes it onto `received`. `WaitForMessage` reads from that channel with a timeout (fails the test, doesn't hang forever). `Disconnect` closes the connection and blocks (via a done-signal) until `hub`'s internal `ServeAgentWS` goroutine has actually removed the agent from its connection map — needed for the disconnect-before-dispatch test to be deterministic rather than racing the hub's own cleanup.

### Scenario fixtures
`scenario.NewEngine(t.TempDir())` + `engine.Save(&scenario.Scenario{...})` — the real, exported, validated registration path. Two builders: a minimal posture-only scenario (`LocalCheck: true`) and a minimal live-executable scenario (`Executable: true`, one or two plain `Command`-based `Step`s, no ART/Caldera).

## Test files

### 1. `internal/db/postgres_test.go` (new) + `internal/api/handlers.go` fix
- Schema migration test: after `EnsureSchema`, confirm the partial unique index exists (`SELECT indexname FROM pg_indexes WHERE tablename='scenario_runs' AND indexname='idx_scenario_runs_agent_running'`).
- `dispatchRun` race test: seed an agent with no existing run, fire N concurrent `dispatchRun` calls (posture mode, no WS connection needed since we're isolating the DB-level race, not the WS path) for that same agent; assert exactly one call returns a real `runID` with no skip, every other call returns `skip == "agent busy"` with `err == nil`, and the DB ends up with exactly one `'running'` row for the agent. Run with `-count=10` at this task's checkpoint to confirm the fix is deterministic (not "usually works").

### 2. `internal/api/run_dispatch_helpers_test.go`
- `classifyAgentOS` table-driven matrix: `"Windows Server 2022"`, `"windows"` lowercase, `"Ubuntu 22.04 LTS"`, `"kali"`, `"macOS Sonoma"`, `"darwin"`, mixed case (`"WiNdOwS"`), leading/trailing whitespace (`"  linux  "` — characterizes whatever `strings.Contains` on the untrimmed lowered string actually does), a version-suffixed unknown string (`"FreeBSD 13.2"` → unclassified `""`), and an empty string → `""`.
- `startFakeAgent`/`WaitForMessage`/`Disconnect`/`Reconnect` implementation, plus a self-test proving the helper itself works (connect, send a message via `hub.SendToAgent`, confirm `WaitForMessage` receives it; disconnect, confirm a subsequent `hub.SendToAgent` returns `false`).
- `minimalPostureScenario`/`minimalLiveScenario` builders.

### 3. `internal/api/run_scenario_gates_test.go`
`RunScenario`'s own request-validation matrix — all pure 400/403/503 responses before `dispatchRun` is reached, asserting both status code and response body where the message content is part of the contract:
- Missing `agentId` → 400.
- Scenario not found → 404.
- Unknown ART techniques requested with `artStore == nil` → 503, exact message.
- Step index out of range → 400 naming the bad index and the scenario's real step count.
- Mode validation: empty → defaults to posture (verify via the response body's `mode` field); `"execute"` → treated as `"telemetry"`; an invalid string → 400.
- `live && !sc.Executable` → 400.
- `live && !confirmLive` → 400.
- `mode == "lab" && !confirmLab` → 400.
- OS mismatch: posture → 200 with a populated `osWarning` field (not an error); live → 400 hard-block, exact message naming both the scenario's supported OS list and the agent's classified OS.
- Execution-window rejection: outside window → 400; malformed window string in `sc.LivePolicy.ExecutionWindow` → 500.
- Agent-state gate (via `RunScenario`'s own pre-check, not `dispatchRun`'s): each non-active state (`restricted`/`quarantined`/`retired`) → 403 naming the state.

### 4. `internal/api/dispatch_run_test.go`
`dispatchRun`'s own independent gates, exercised as the campaign fan-out would call it (bypassing `RunScenario`'s pre-checks entirely):
- Agent-state gate: each non-active state → skip `"agent <state>"`, `err == nil`, no run row created.
- OS mismatch for a **live** dispatch → skip `"os mismatch"`, no run row. For **posture**, mismatch does not block (posture always proceeds; warning is `RunScenario`'s concern, not `dispatchRun`'s).
- Concurrency guard (sequential, deterministic cases — the race itself is Task 1): a fresh non-stale running run on the agent → `"agent busy"`. A **stale** running run (agent's `last_update` far enough in the past that `runIsStale` returns true) → freed to `'partial'` with `completed_at` set, and the new dispatch proceeds; assert both the freed run's final `status`/`completed_at` and that the new run gets a genuinely new `id`.
- **Idempotent retry semantics**: dispatch to an agent with no WS connection (the run fails/offline) → run row ends `'failed'`; a second dispatch immediately after does **not** hit the busy gate (since the prior run's status isn't `'running'`) and creates a fresh run. Dispatch to an agent with a stale running run → after the stale-cleanup path frees it, a second immediate dispatch attempt no longer sees a blocking run.
- **Posture dispatch, both outcomes** via the fake-agent helper: connected → run stays `'running'`, the delivered message has `Type == MsgCommandSimulate`, `AgentID` matches, and `Data` carries the right `scenarioId`/`runId`/`checks`; not connected → run flips to `'failed'`, skip `"offline"`.
- **Live dispatch, both outcomes** via the fake-agent helper: connected → run stays `'running'`, delivered message is `Type == MsgCommandScenario` with a `scenario.ScenarioCommand` payload whose `RunID`/`ScenarioID`/`Mode` match and whose `Steps` count and ordering match the scenario's configured steps exactly; not connected → `'failed'`/`"offline"`.
- **WS disconnect immediately before dispatch**: connect the fake agent, call `Disconnect()` (which blocks until the hub's connection map no longer has the agent), then dispatch → must behave identically to "never connected" (`'failed'`/`"offline"`), proving the run never gets stuck `'running'` against a dead connection.
- **Lab-only step filtering**: a scenario with steps in order `[normal, lab-only, normal, lab-only]` dispatched in telemetry mode → the delivered step list is `[normal, normal]` with original relative order preserved (not just the right count); dispatched in lab mode → all 4 steps delivered in original order. A scenario where every step is `lab-only`, dispatched in telemetry mode → build error, run marked `'failed'`, `dispatchRun` returns a genuine `err` (not a skip).
- **Variant expansion invariants** (not just a count): dispatch with `VariantDepth: quick` on a 2-step scenario → every expanded step's `TaskID` is unique across the whole delivered list (no collisions), and cross-referencing `persistStepMeta`'s written `step_meta` column, every non-base variant step's metadata resolves back to one of the 2 original steps' `TechniqueID`/`Name` (proving variants aren't orphaned from their parent). Depth `none`/`""` → step count unchanged (identity transform).
- **DB-insert-failure path** (closed-pool pattern, matching Phase 1/3a precedent): a `dispatchRun` call against a closed pool returns a genuine non-nil `err` (not a skip, not a panic).

### 5. `internal/api/run_scenario_integration_test.go`
End-to-end through the real HTTP entry point via the fake-agent helper, asserting full response payloads (not just status codes):
- A full posture run dispatches end-to-end: response body is exactly `{"runId": "<id>", "status": "dispatched", "mode": "posture"}` (no `osWarning` key when OS matches), and the fake agent actually receives the simulate command.
- A full live run dispatches end-to-end with `confirmLive: true`: response body includes `mode: "telemetry"`, fake agent receives the scenario command.
- Each `dispatchRun` skip reason surfaces as the documented specific status through `RunScenario`'s translation switch: `"agent busy"` → 409 with a human-readable body; `"offline"` → 503; `"agent <state>"` → 403; an unrecognized skip string → 503 (the `default` branch).
- An operator-selected technique/step subset narrows the delivered step list end-to-end (request `steps: [0]` on a 2-step scenario → fake agent receives exactly 1 step, matching index 0's content).
- Posture dispatch against an OS-mismatched agent → 200 with `osWarning` populated in the body, and the fake agent still receives the dispatch (posture never hard-blocks on OS).

## Coverage target

Same tier as 3a/3c: every gate branch, every skip reason, and both terminal dispatch outcomes (success via the fake agent, offline/failed without one) exercised at least once, plus the concurrency-race fix verified deterministic at `-count=10`.
