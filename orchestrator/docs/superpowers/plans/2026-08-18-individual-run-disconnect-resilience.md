# Individual/Campaign/Scheduled Run Disconnect Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show "Agent Disconnected" instead of a stale "Running" badge for any individual/campaign/scheduled-assessment run whose agent has gone offline mid-run, and proactively resolve a run whose agent never comes back — without touching sweeps (already fixed) or the agent's own self-healing watchdog (already correct).

**Architecture:** `ListScenarioRuns` gains one lightweight follow-up query after its existing `scanRunRows` call, setting a new `AgentDisconnected` response field for any `running` row whose agent's heartbeat is stale — no DB schema change. A new `ReapAbandonedRuns` function in `internal/api/liveness.go`, wired into the existing 30s dispatch watchdog scheduler alongside `ReapNeverStartedRuns`, force-marks a `running` row `partial` once its agent has been offline past 5 minutes. The frontend's `runRowHtml` renders the new badge state.

**Tech Stack:** Go (orchestrator backend), PostgreSQL (via pgx), vanilla JS (wwwroot/index.html), Go's `testing` package with `testcontainers-go`-backed integration tests.

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-18-individual-run-disconnect-resilience-design.md`

## Global Constraints

- Reuse `agents.last_update` + `models.AgentOfflineAfter` (90s) as the connectivity signal — not the sweep work's `Hub.IsAgentConnected`.
- Reap threshold for force-marking an abandoned run `partial`: **5 minutes** of agent offline time.
- Do **not** modify `scanRunRows` or its documented column-order contract (shared by `ListScenarioRuns`, `GetVexSweepRuns`, `GetEMSweepRuns`) — the new field is added as a follow-up query in `ListScenarioRuns` only.
- Do **not** touch `cancelScenarioRun`, the Stop button, `runIsStale`'s connected-but-stuck 2-hour path, or Full Variant Sweep's per-variant dispatch — all explicitly out of scope per the spec.
- Every Go change follows TDD: write the failing test, confirm it fails, implement, confirm it passes.
- Run the **full** `internal/api` test suite before any commit that touches `internal/api`, via `Bash` with `run_in_background: true` (10-17 minutes observed this session across runs), watched with `Monitor` (not a blocking sleep) grepping the log file for the `ok`/`FAIL` line, then reading the actual full log file after the notification — never trust a piped/truncated capture. If a run times out, retry once cleanly with `-timeout 20m` before concluding anything is broken (this session confirmed one such timeout was transient Docker/Postgres contention, not a real bug).
- Commit after each task with a message explaining root cause + fix, then `git push` immediately after every commit.
- JS syntax check convention: extract `<script>` blocks from `index.html` into a scratchpad file, run `node --check` via the Bash tool.

---

## File Structure

| File | Responsibility |
|---|---|
| `orchestrator/internal/api/handlers.go` | New `runRow.AgentDisconnected` field; `ListScenarioRuns` gains a follow-up connectivity query. |
| `orchestrator/internal/api/list_scenario_runs_test.go` | Test for the new field. |
| `orchestrator/internal/api/liveness.go` | New `abandonedRunGuard` const + `ReapAbandonedRuns` function. |
| `orchestrator/internal/api/liveness_test.go` | Tests for the above. |
| `orchestrator/cmd/server/main.go` | Wires `ReapAbandonedRuns` into the existing 30s dispatch watchdog scheduler callback. |
| `orchestrator/wwwroot/index.html` | `runRowHtml`'s status badge shows "Agent Disconnected" when applicable. |

---

## Task 1: `ListScenarioRuns` — live "Agent Disconnected" display field

**Files:**
- Modify: `orchestrator/internal/api/handlers.go` (`runRow` struct at line 2374, `ListScenarioRuns` at line 2426)
- Test: `orchestrator/internal/api/list_scenario_runs_test.go`

**Interfaces:**
- Consumes: `models.AgentOfflineAfter` (already imported in `handlers.go`).
- Produces: `runRow.AgentDisconnected bool` (JSON key `agentDisconnected`, `omitempty`) — consumed by Task 3's frontend change.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/list_scenario_runs_test.go`, after `TestListScenarioRuns_PausedProjection` (the file's last test, mirroring that test's exact "projection" shape — seed two rows, one triggering the new field, one not, assert both):

```go
func TestListScenarioRuns_AgentDisconnectedProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		// Agent offline (stale heartbeat) + running row -> agentDisconnected true.
		seedRunRow(t, pool, "run-disc", "sc-disc", "agent-disc", "running")
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET last_update = NOW() - interval '10 minutes' WHERE agent_id='agent-disc'`); err != nil {
			t.Fatalf("age the agent: %v", err)
		}

		// Agent alive + running row -> agentDisconnected false/absent.
		seedRunRow(t, pool, "run-alive", "sc-disc", "agent-alive", "running")

		// Agent offline but the RUN is not 'running' (terminal) -> agentDisconnected
		// must not apply retroactively to a completed run.
		seedRunRow(t, pool, "run-done-offline-agent", "sc-disc", "agent-done-offline", "completed")
		if _, err := pool.Exec(context.Background(),
			`UPDATE agents SET last_update = NOW() - interval '10 minutes' WHERE agent_id='agent-done-offline'`); err != nil {
			t.Fatalf("age the agent: %v", err)
		}

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?scenarioId=sc-disc", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		var got []struct {
			ID                string `json:"id"`
			AgentDisconnected bool   `json:"agentDisconnected"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		byID := map[string]bool{}
		for _, r := range got {
			byID[r.ID] = r.AgentDisconnected
		}
		if !byID["run-disc"] {
			t.Error("run-disc: agentDisconnected = false, want true (agent heartbeat is stale)")
		}
		if byID["run-alive"] {
			t.Error("run-alive: agentDisconnected = true, want false (agent heartbeat is fresh)")
		}
		if byID["run-done-offline-agent"] {
			t.Error("run-done-offline-agent: agentDisconnected = true, want false (run is not 'running')")
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestListScenarioRuns_AgentDisconnectedProjection -v`
Expected: FAIL — `byID["run-disc"]` is `false` (the field doesn't exist yet, so it always decodes to the zero value).

- [ ] **Step 3: Add the `AgentDisconnected` field to `runRow`**

In `orchestrator/internal/api/handlers.go`, replace:

```go
type runRow struct {
	models.ScenarioRun
	InitiatedBy *string `json:"initiatedBy"`
	// DetectedTechs is the set of technique ids whose FAIL the blue team still
	// caught (from the run's detection_summary, with the coarse event-token
	// fallback) — same classification the campaign rollup and kill-chain use.
	// Lets the dashboard split fails into "detected" vs "missed" honestly.
	DetectedTechs map[string]bool `json:"detectedTechs,omitempty"`
}
```

with:

```go
type runRow struct {
	models.ScenarioRun
	InitiatedBy *string `json:"initiatedBy"`
	// DetectedTechs is the set of technique ids whose FAIL the blue team still
	// caught (from the run's detection_summary, with the coarse event-token
	// fallback) — same classification the campaign rollup and kill-chain use.
	// Lets the dashboard split fails into "detected" vs "missed" honestly.
	DetectedTechs map[string]bool `json:"detectedTechs,omitempty"`
	// AgentDisconnected is set by ListScenarioRuns' own follow-up query (not
	// scanRunRows -- this field has no backing column) for any 'running' row
	// whose agent's heartbeat is stale. Distinct from sweeps' real, persisted
	// agent_disconnected status: an individual run has no dispatcher to pause
	// on this, so it stays a display-only overlay. See
	// docs/superpowers/specs/2026-08-18-individual-run-disconnect-resilience-design.md.
	AgentDisconnected bool `json:"agentDisconnected,omitempty"`
}
```

- [ ] **Step 4: Add the follow-up connectivity query to `ListScenarioRuns`**

In `orchestrator/internal/api/handlers.go`, replace:

```go
	runs, err := scanRunRows(rows)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []runRow{}
	}
	respond(w, runs)
}
```

(the version inside `ListScenarioRuns`, immediately preceding its closing `}` at line 2455) with:

```go
	runs, err := scanRunRows(rows)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []runRow{}
	}

	// Live "Agent Disconnected" overlay: for every running row, check whether
	// its agent's heartbeat has gone stale. A separate follow-up query rather
	// than joining agents into the SELECT above -- scanRunRows' column order
	// is a documented contract shared with GetVexSweepRuns/GetEMSweepRuns,
	// neither of which needs this field (sweep rows already carry their own
	// real agent_disconnected status from the sweep-level fix).
	var runningAgentIDs []string
	seen := map[string]bool{}
	for _, run := range runs {
		if run.Status == "running" && !seen[run.AgentID] {
			seen[run.AgentID] = true
			runningAgentIDs = append(runningAgentIDs, run.AgentID)
		}
	}
	if len(runningAgentIDs) > 0 {
		offlineRows, err := h.db.Query(r.Context(),
			`SELECT agent_id FROM agents WHERE agent_id = ANY($1) AND last_update < NOW() - make_interval(secs => $2)`,
			runningAgentIDs, int(models.AgentOfflineAfter.Seconds()),
		)
		if err == nil {
			offline := map[string]bool{}
			for offlineRows.Next() {
				var id string
				if err := offlineRows.Scan(&id); err == nil {
					offline[id] = true
				}
			}
			offlineRows.Close()
			for i := range runs {
				if runs[i].Status == "running" && offline[runs[i].AgentID] {
					runs[i].AgentDisconnected = true
				}
			}
		}
	}

	respond(w, runs)
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run TestListScenarioRuns -v`
Expected: PASS — every `TestListScenarioRuns_*` test in the file, including all pre-existing ones (confirms the new query doesn't break any existing response shape).

- [ ] **Step 6: Run the full `internal/api` test suite**

Run in background (10-17 minutes observed this session):

```bash
cd orchestrator && go test ./internal/api/... -v -timeout 20m > <scratchpad>/individual_run_task1_full.log 2>&1
```

Use `Monitor` to watch for the `ok`/`FAIL` line (grep the log for `^(ok|FAIL)[[:space:]]+github.com/audspect/bas/internal/api`), then read the actual full log file after the notification and confirm zero `--- FAIL` lines. If it times out, retry once cleanly with the same `-timeout 20m` before concluding anything is broken.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/list_scenario_runs_test.go
git commit -m "$(cat <<'EOF'
feat(api): live Agent Disconnected overlay for individual run listing

Root cause: ListScenarioRuns showed a raw 'running' status for every
individual/campaign/scheduled-assessment run with zero live connectivity
awareness -- unlike the just-fixed sweep types, there was no signal at all
telling the user their agent had actually gone offline mid-run. Adds a
response-only agentDisconnected field, computed via a follow-up query
against agents.last_update (the same staleness definition dispatchRun's
own concurrency guard already uses), for any 'running' row whose agent
hasn't heartbeated within AgentOfflineAfter (90s). Deliberately does not
touch scanRunRows' shared column-order contract -- GetVexSweepRuns and
GetEMSweepRuns don't need this field, since sweep rows already carry
their own real, persisted agent_disconnected status.
EOF
)"
git push
```

---

## Task 2: `ReapAbandonedRuns` — proactive reaper for permanently-dead agents

**Files:**
- Modify: `orchestrator/internal/api/liveness.go`
- Modify: `orchestrator/cmd/server/main.go` (dispatch watchdog scheduler callback, lines 563-575)
- Test: `orchestrator/internal/api/liveness_test.go`

**Interfaces:**
- Consumes: nothing new (plain `h.db` queries, mirrors `ReapNeverStartedRuns`'s existing shape in the same file).
- Produces: `func (h *Handler) ReapAbandonedRuns(ctx context.Context) error` — wired into `cmd/server/main.go`'s existing 30s scheduler.

- [ ] **Step 1: Write the failing test**

`orchestrator/internal/api/liveness_test.go` currently imports only `"testing"` and `"time"` (its sole existing test, `TestRunIsStale`, needs nothing else). The new tests need more. Replace the import block:

```go
import (
	"testing"
	"time"
)
```

with:

```go
import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)
```

Then add the following tests to the file. `internal/api`'s package-wide `TestMain` (`testmain_test.go:22`) already provides `sharedDB` for the whole package, so these use the same `sharedDB.RunWithPool` convention every other container-backed test in this package already follows:

```go
func TestReapAbandonedRuns_MarksPartialAfterThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		ctx := context.Background()

		// Agent offline well past abandonedRunGuard (5 min) -- must be reaped.
		seedRunRow(t, pool, "run-abandoned", "sc-reap", "agent-abandoned", "running")
		if _, err := pool.Exec(ctx,
			`UPDATE agents SET last_update = NOW() - interval '10 minutes' WHERE agent_id='agent-abandoned'`); err != nil {
			t.Fatalf("age the agent: %v", err)
		}

		// Agent offline but within the grace window -- must NOT be reaped yet
		// (give the agent's own 90s watchdog + reconnect a fair chance first).
		seedRunRow(t, pool, "run-recent-disc", "sc-reap", "agent-recent-disc", "running")
		if _, err := pool.Exec(ctx,
			`UPDATE agents SET last_update = NOW() - interval '2 minutes' WHERE agent_id='agent-recent-disc'`); err != nil {
			t.Fatalf("age the agent: %v", err)
		}

		// Agent alive, run long-running -- must NOT be reaped (that's
		// staleRunGuard's job, not this reaper's; this reaper only ever
		// fires on the agent-offline condition).
		seedRunRow(t, pool, "run-alive-agent", "sc-reap", "agent-alive-reap", "running")

		if err := h.ReapAbandonedRuns(ctx); err != nil {
			t.Fatalf("ReapAbandonedRuns: %v", err)
		}

		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT status, completed_at FROM scenario_runs WHERE id = 'run-abandoned'`).Scan(&status, &completedAt); err != nil {
			t.Fatalf("query run-abandoned: %v", err)
		}
		if status != "partial" || completedAt == nil {
			t.Fatalf("run-abandoned status = %q completedAt = %v, want partial with completedAt set", status, completedAt)
		}

		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'run-recent-disc'`).Scan(&status); err != nil {
			t.Fatalf("query run-recent-disc: %v", err)
		}
		if status != "running" {
			t.Fatalf("run-recent-disc status = %q, want still running (within grace window)", status)
		}

		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'run-alive-agent'`).Scan(&status); err != nil {
			t.Fatalf("query run-alive-agent: %v", err)
		}
		if status != "running" {
			t.Fatalf("run-alive-agent status = %q, want still running (agent is connected)", status)
		}
	})
}

// TestReapAbandonedRuns_DoesNotConflictWithLateResultSubmission proves the
// race-safety property the spec calls out: SubmitScenarioResult has no
// status guard, so a late submission from an agent that reconnects moments
// after the reaper already marked its run 'partial' must still reconcile
// correctly rather than erroring or being silently dropped. Uses the
// existing submitResultOK helper (submit_scenario_result_test.go) rather
// than constructing the request by hand -- SubmitScenarioResult requires
// agent auth + a result MAC that helper already sets up correctly via
// validSubmitResultReq/rawResultBody.
func TestReapAbandonedRuns_DoesNotConflictWithLateResultSubmission(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		ctx := context.Background()

		seedRunRow(t, pool, "run-late-submit", "sc-reap-race", "agent-late-submit", "running")
		if _, err := pool.Exec(ctx,
			`UPDATE agents SET last_update = NOW() - interval '10 minutes' WHERE agent_id='agent-late-submit'`); err != nil {
			t.Fatalf("age the agent: %v", err)
		}

		if err := h.ReapAbandonedRuns(ctx); err != nil {
			t.Fatalf("ReapAbandonedRuns: %v", err)
		}
		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'run-late-submit'`).Scan(&status); err != nil {
			t.Fatalf("query after reap: %v", err)
		}
		if status != "partial" {
			t.Fatalf("status after reap = %q, want partial", status)
		}

		// submitResultOK itself asserts 200 (t.Fatalf on anything else) --
		// this is the assertion that the late submission still reconciles
		// despite the reaper's earlier UPDATE.
		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "run-late-submit", ScenarioID: "sc-reap-race", AgentID: "agent-late-submit",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: late"}},
		})
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestReapAbandonedRuns_MarksPartialAfterThreshold|TestReapAbandonedRuns_DoesNotConflictWithLateResultSubmission" -v`
Expected: FAIL to compile — `h.ReapAbandonedRuns` undefined.

- [ ] **Step 3: Implement `ReapAbandonedRuns`**

In `orchestrator/internal/api/liveness.go`, add after the `neverStartedGuard` const block (before `ReapNeverStartedRuns`):

```go
// abandonedRunGuard is how long a 'running' scenario_run's agent may sit
// offline (stale heartbeat) before ReapAbandonedRuns force-marks the run
// 'partial' on the server's own initiative. Deliberately longer than the
// agent's own runDisconnectWatchdog (agent/agent.go: disconnectGracePeriod
// = 90s, matched to AgentOfflineAfter) plus a fair reconnect-and-submit
// window -- an agent that's merely had a brief network blip should get the
// chance to resolve its own run first via its spooled Partial submission.
// This reaper exists only for the agent that never comes back at all
// (crashed, uninstalled, decommissioned): without it, that run would sit
// "Running" until the unrelated, purely-reactive staleRunGuard (2h) in
// dispatchRun's concurrency guard happens to fire -- which requires another
// dispatch attempt to that exact agent, something that may never happen for
// a dead one. See
// docs/superpowers/specs/2026-08-18-individual-run-disconnect-resilience-design.md.
const abandonedRunGuard = 5 * time.Minute
```

Add after `ReapNeverStartedRuns` (end of file):

```go

// ReapAbandonedRuns marks any 'running' scenario_run 'partial' once its
// agent has been offline (stale heartbeat) past abandonedRunGuard. Called
// on the same poll tick as ReapNeverStartedRuns (see cmd/server/main.go).
// Mirrors that function's structure: match rows first, then UPDATE each
// with its own "AND status = 'running'" re-check in the WHERE clause so a
// run that started progressing (or was independently resolved by the
// agent's own watchdog + late submission) between the SELECT and the
// UPDATE is never clobbered.
func (h *Handler) ReapAbandonedRuns(ctx context.Context) error {
	rows, err := h.db.Query(ctx,
		`SELECT sr.id, sr.agent_id
		   FROM scenario_runs sr
		   JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.status = 'running'
		    AND a.last_update < NOW() - make_interval(secs => $1)`,
		int(abandonedRunGuard.Seconds()),
	)
	if err != nil {
		return err
	}
	type abandonedRun struct{ id, agentID string }
	var abandoned []abandonedRun
	for rows.Next() {
		var a abandonedRun
		if err := rows.Scan(&a.id, &a.agentID); err != nil {
			continue
		}
		abandoned = append(abandoned, a)
	}
	rows.Close()

	for _, a := range abandoned {
		tag, err := h.db.Exec(ctx,
			`UPDATE scenario_runs SET status = 'partial', completed_at = NOW()
			  WHERE id = $1 AND status = 'running'`,
			a.id,
		)
		if err != nil {
			log.Printf("[dispatch] reap abandoned run %s: %v", a.id, err)
			continue
		}
		if tag.RowsAffected() > 0 {
			log.Printf("[dispatch] run %s on agent %s abandoned (agent offline beyond %s) — marked partial", a.id, a.agentID, abandonedRunGuard)
		}
	}
	return nil
}
```

- [ ] **Step 4: Wire it into the existing dispatch watchdog scheduler**

In `orchestrator/cmd/server/main.go`, replace:

```go
	dispatchWatchdogScheduler := exercise.NewPollScheduler(30 * time.Second)
	dispatchWatchdogScheduler.Start(func(ctx context.Context) {
		if err := handler.ReapNeverStartedRuns(ctx); err != nil {
			log.Printf("[dispatch] never-started watchdog: %v", err)
		}
	})
	defer dispatchWatchdogScheduler.Stop()
```

with:

```go
	dispatchWatchdogScheduler := exercise.NewPollScheduler(30 * time.Second)
	dispatchWatchdogScheduler.Start(func(ctx context.Context) {
		if err := handler.ReapNeverStartedRuns(ctx); err != nil {
			log.Printf("[dispatch] never-started watchdog: %v", err)
		}
		// Runs the same tick, independently -- one failing must not skip
		// the other. See ReapAbandonedRuns for why this exists: an agent
		// that never reconnects at all (vs. a brief blip its own
		// disconnectGracePeriod watchdog already self-heals) would
		// otherwise leave its run "Running" until the unrelated, purely
		// reactive 2h staleRunGuard happens to fire.
		if err := handler.ReapAbandonedRuns(ctx); err != nil {
			log.Printf("[dispatch] abandoned-run watchdog: %v", err)
		}
	})
	defer dispatchWatchdogScheduler.Stop()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestReapAbandonedRuns|TestRunIsStale|TestListScenarioRuns" -v`
Expected: PASS — all matched tests, including the pre-existing `TestRunIsStale` and every `TestListScenarioRuns_*` from Task 1.

Also confirm `cmd/server` still builds (this file isn't covered by `internal/api`'s test suite):

Run: `cd orchestrator && go build ./...`
Expected: no errors.

- [ ] **Step 6: Run the full `internal/api` test suite**

Same background + `Monitor` + full-log-read procedure as Task 1 Step 6.

- [ ] **Step 7: Run `TestRBACMatrix_NoDrift` explicitly**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS — no HTTP routes were added or changed in this plan (`ReapAbandonedRuns` is an internal scheduler callback, not a route), so the matrix should need no updates. If this fails, something touched routing unexpectedly — stop and investigate before continuing.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/liveness.go orchestrator/internal/api/liveness_test.go orchestrator/cmd/server/main.go
git commit -m "$(cat <<'EOF'
feat(api): proactive reaper for permanently-abandoned runs

Root cause: a 'running' scenario_run whose agent never reconnects at all
(crashed, uninstalled, decommissioned) had nothing watching it -- the
agent's own runDisconnectWatchdog only fires if the agent process is
still alive, and the server's existing staleRunGuard (2h) is purely
reactive, triggered only by the next dispatch attempt to that exact
agent, which may never come for a dead one. ReapAbandonedRuns runs on the
existing 30s dispatch watchdog tick and force-marks a run 'partial' once
its agent has been offline past 5 minutes -- comfortably longer than the
agent's own 90s watchdog + reconnect-and-submit window, so a merely
blipped agent is never raced ahead of. Reuses 'partial', the same
terminal status the agent's own watchdog already produces for this exact
scenario, rather than inventing a second status.
EOF
)"
git push
```

---

## Task 3: Frontend — "Agent Disconnected" badge in Live Runs

**Files:**
- Modify: `orchestrator/wwwroot/index.html`

**Interfaces:**
- Consumes: `r.agentDisconnected` (Task 1) on individual run objects from `GET /api/scenarios/runs`.

- [ ] **Step 1: Update `runRowHtml`'s status badge**

In `orchestrator/wwwroot/index.html`, find `runRowHtml` (currently starting at line 11066) and replace its status-badge line:

```js
    '<td><span class="sbadge s-' + x(r.status) + '">' + x(r.status) + '</span></td>' +
```

with:

```js
    '<td><span class="sbadge ' + (r.agentDisconnected && r.status === 'running' ? 's-agent_disconnected' : 's-' + x(r.status)) + '">' +
        (r.agentDisconnected && r.status === 'running' ? 'Agent Disconnected' : x(r.status)) + '</span></td>' +
```

(Unlike sweeps' `sweepStatusLabel`, this isn't a raw status-value mapping — `agentDisconnected` is a separate boolean overlay on top of `status === 'running'`, not a distinct enum value, so it's handled as a conditional here rather than a reusable label function. The `.s-agent_disconnected` CSS class already exists from the sweep work, near `.s-stopped` in the "Status badges" block — reused as-is, not recreated.)

- [ ] **Step 2: JS syntax check**

Extract every `<script>` block from `orchestrator/wwwroot/index.html` into a scratchpad file and run `node --check` on it via the Bash tool:

```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('orchestrator/wwwroot/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
fs.writeFileSync('<scratchpad>/extracted_task3.js', scripts.join('\n;\n'));
"
node --check "<scratchpad>/extracted_task3.js"
```

Expected: no syntax errors.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "$(cat <<'EOF'
feat(ui): show Agent Disconnected for individual runs in Live Runs

runRowHtml now overlays the new agentDisconnected field onto the status
badge for any row still showing 'running' -- previously an individual/
campaign/scheduled-assessment run gave zero visual indication its agent
had gone offline mid-run, unlike the just-fixed sweep types. Reuses the
existing .s-agent_disconnected CSS class from the sweep work.
EOF
)"
git push
```

---

## Task 4: Full verification and handoff

**Files:** none (verification only)

- [ ] **Step 1: Run the full `internal/api` test suite one more time on the complete tree**

Run in background (10-17 minutes):

```bash
cd orchestrator && go test ./internal/api/... -v -timeout 20m > <scratchpad>/individual_run_disconnect_final.log 2>&1
```

Use `Monitor` to watch for completion, then read the actual full log file and confirm every test passes with zero `--- FAIL` lines.

- [ ] **Step 2: Run the broader build to catch any compile-time regression elsewhere**

Run: `cd orchestrator && go build ./...`
Expected: no errors.

- [ ] **Step 3: Announce completion and hand off**

Report to the user: individual/campaign/scheduled-assessment runs now show "Agent Disconnected" in Live Runs the moment their agent's heartbeat goes stale, and any run whose agent never comes back is proactively resolved to `partial` after 5 minutes instead of sitting "Running" indefinitely. Then use the **finishing-a-development-branch** skill to verify tests one more time, detect the environment, and present the standard merge/PR/keep-as-is menu — per this session's established pattern, this plan is expected to run directly on `main` in the current working tree (no worktree), matching every prior task this session.
