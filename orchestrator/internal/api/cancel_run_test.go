package api

// CancelRun's h.auditLog call is fire-and-forget (dispatches its DB insert in
// a goroutine — see audit.go), so it falls under the same async-fan-out
// exclusion as SubmitScenarioResult's background subsystems; no test here
// asserts on the audit-log row. Audit logging's own correctness is Phase 3a
// territory.

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
				seedRunRow(t, pool, runID, "sc-cancel-terminal", "agent-cancel-terminal-"+status, status)

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
		seedRunRow(t, pool, runID, "sc-cancel-online", agentID, "running")
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

// TestCancelRun_Running_AgentOnline_ForcesPartialAfterGracePeriod is the
// regression test for the "Stop click confirmed, run stays Running forever"
// bug: an agent that's reachable but never calls SubmitScenarioResult back
// (stuck, or doesn't honor command_cancel promptly) left the run stuck in
// 'running' with no ceiling tighter than the 2-hour staleRunGuard. The
// force-cancel goroutine must flip it to 'partial' once cancelGracePeriod
// elapses, and broadcast the same scenario_result event a normal completion
// sends so the frontend's existing live-refresh path picks it up.
func TestCancelRun_Running_AgentOnline_ForcesPartialAfterGracePeriod(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		h.cancelGracePeriod = 10 * time.Millisecond
		agentID := "agent-cancel-grace"
		runID := "cancel-grace-run"
		seedRunRow(t, pool, runID, "sc-cancel-grace", agentID, "running")
		fakeAgent := startFakeAgent(t, h.hub, agentID)
		defer fakeAgent.Disconnect(t)
		browser := startFakeBrowser(t, h.hub)
		defer browser.Disconnect(t)

		rec := httptest.NewRecorder()
		h.CancelRun(rec, cancelRunReq(runID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		// The agent is online and receives the cancel command, but (simulating
		// a stuck/unresponsive agent) never calls SubmitScenarioResult back.
		env := browser.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgScenarioResult {
			t.Fatalf("message type = %q, want %q", env.Type, models.MsgScenarioResult)
		}
		var data map[string]string
		if err := json.Unmarshal(env.Data, &data); err != nil {
			t.Fatalf("decode broadcast data: %v", err)
		}
		if data["runId"] != runID || data["status"] != "partial" {
			t.Fatalf("broadcast data = %+v, want runId=%s status=partial", data, runID)
		}

		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(context.Background(), `SELECT status, completed_at FROM scenario_runs WHERE id=$1`, runID).Scan(&status, &completedAt); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "partial" {
			t.Fatalf("run status = %q, want partial (force-cancelled after grace period)", status)
		}
		if completedAt == nil {
			t.Fatal("completed_at = nil, want set")
		}
	})
}

// TestCancelRun_Running_AgentRespondsBeforeGracePeriod_NoForcedOverride
// proves the force-cancel goroutine is safe when the agent DOES respond in
// time: its UPDATE carries "WHERE status = 'running'", so once the agent's
// own completion has already moved the row to a terminal status, the
// grace-period goroutine's later check simply affects zero rows and does
// nothing -- it must never clobber a run that finished normally.
func TestCancelRun_Running_AgentRespondsBeforeGracePeriod_NoForcedOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		h.cancelGracePeriod = 50 * time.Millisecond
		agentID := "agent-cancel-fast"
		runID := "cancel-fast-run"
		seedRunRow(t, pool, runID, "sc-cancel-fast", agentID, "running")
		fakeAgent := startFakeAgent(t, h.hub, agentID)
		defer fakeAgent.Disconnect(t)

		rec := httptest.NewRecorder()
		h.CancelRun(rec, cancelRunReq(runID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		fakeAgent.WaitForMessage(t, 2*time.Second) // the command_cancel itself

		// Agent responds on its own, before the grace period elapses.
		if _, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET status='completed', completed_at=NOW() WHERE id=$1`, runID); err != nil {
			t.Fatalf("simulate agent completion: %v", err)
		}

		time.Sleep(h.cancelGracePeriod + 100*time.Millisecond)

		var status string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id=$1`, runID).Scan(&status); err != nil {
			t.Fatalf("read run: %v", err)
		}
		if status != "completed" {
			t.Fatalf("run status = %q, want completed (grace-period goroutine must not override a run the agent already finished)", status)
		}
	})
}

// TestCancelRun_Running_AgentOffline_SyncsVariantRunStatus is the
// regression test for a distinct bug from the grace-period one above: a
// Full Variant Sweep tracks per-technique progress in a SEPARATE table,
// variant_runs, keyed by scenario_run_id. vexsweep.Dispatcher polls
// variant_runs.status (not scenario_runs.status) to decide whether to
// advance the sweep -- so cancelling the underlying scenario_run must also
// mirror the terminal status onto its variant_runs row, or the Dispatcher
// polls forever and the sweep never advances, even though the individual
// run correctly shows Partial.
func TestCancelRun_Running_AgentOffline_SyncsVariantRunStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		agentID := "agent-cancel-offline-variant"
		runID := "cancel-offline-variant-run"
		seedRunRow(t, pool, runID, "sc-cancel-offline-variant", agentID, "running")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO variant_runs (id, agent_id, technique_id, scenario_run_id, total_variants, status)
			 VALUES ('vr-cancel-offline', $1, 'T1059.001', $2, 10, 'running')`, agentID, runID); err != nil {
			t.Fatalf("seed variant_run: %v", err)
		}

		rec := httptest.NewRecorder()
		h.CancelRun(rec, cancelRunReq(runID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		var vrStatus string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM variant_runs WHERE id = 'vr-cancel-offline'`).Scan(&vrStatus); err != nil {
			t.Fatalf("read variant_run: %v", err)
		}
		if vrStatus != "partial" {
			t.Fatalf("variant_run status = %q, want partial (must sync so vexsweep.Dispatcher notices the technique is no longer in flight)", vrStatus)
		}
	})
}

// TestCancelRun_Running_AgentOnline_ForcesPartialAfterGracePeriod_SyncsVariantRunStatus
// is the same regression, via the grace-period force-cancel path instead of
// the agent-offline immediate path.
func TestCancelRun_Running_AgentOnline_ForcesPartialAfterGracePeriod_SyncsVariantRunStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		h.cancelGracePeriod = 10 * time.Millisecond
		agentID := "agent-cancel-grace-variant"
		runID := "cancel-grace-variant-run"
		seedRunRow(t, pool, runID, "sc-cancel-grace-variant", agentID, "running")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO variant_runs (id, agent_id, technique_id, scenario_run_id, total_variants, status)
			 VALUES ('vr-cancel-grace', $1, 'T1059.001', $2, 10, 'running')`, agentID, runID); err != nil {
			t.Fatalf("seed variant_run: %v", err)
		}
		fakeAgent := startFakeAgent(t, h.hub, agentID)
		defer fakeAgent.Disconnect(t)
		browser := startFakeBrowser(t, h.hub)
		defer browser.Disconnect(t)

		rec := httptest.NewRecorder()
		h.CancelRun(rec, cancelRunReq(runID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		browser.WaitForMessage(t, 2*time.Second) // the scenario_result broadcast

		var vrStatus string
		if err := pool.QueryRow(context.Background(), `SELECT status FROM variant_runs WHERE id = 'vr-cancel-grace'`).Scan(&vrStatus); err != nil {
			t.Fatalf("read variant_run: %v", err)
		}
		if vrStatus != "partial" {
			t.Fatalf("variant_run status = %q, want partial (must sync so vexsweep.Dispatcher notices the technique is no longer in flight)", vrStatus)
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
		seedRunRow(t, pool, runID, "sc-cancel-offline", agentID, "running")

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
