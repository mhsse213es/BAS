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
