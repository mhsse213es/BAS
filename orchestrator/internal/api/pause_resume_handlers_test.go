package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPauseRun_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		rec := httptest.NewRecorder()
		h.PauseRun(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/does-not-exist/pause", nil), "runId", "does-not-exist"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestPauseRun_NotRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		seedActiveAgent(t, pool, "agent-pause-notrun", "Windows")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
			 VALUES ('run-pause-notrun','sc','agent-pause-notrun','x','completed',NOW())`,
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
		rec := httptest.NewRecorder()
		h.PauseRun(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/run-pause-notrun/pause", nil), "runId", "run-pause-notrun"))
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
	})
}

func TestPauseRun_SendsCommandPauseOverWS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, engine := minimalLiveScenario(t, "int-pause-cmd")
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "int-agent-pause-cmd"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("dispatch status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		runID, _ := resp["runId"].(string)
		if runID == "" {
			t.Fatalf("resp = %+v, want a non-empty runId", resp)
		}
		fake.WaitForMessage(t, 2*time.Second) // drain the command_scenario dispatch

		pauseRec := httptest.NewRecorder()
		h.PauseRun(pauseRec, withURLParam(httptest.NewRequest(http.MethodPost, "/api/scenarios/runs/"+runID+"/pause", nil), "runId", runID))
		if pauseRec.Code != http.StatusOK {
			t.Fatalf("pause status = %d, body = %s", pauseRec.Code, pauseRec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandPause {
			t.Fatalf("WS message type = %q, want %q", env.Type, models.MsgCommandPause)
		}
	})
}
