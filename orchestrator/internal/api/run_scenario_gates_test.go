package api

import (
	"bytes"
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
		sc, engine := minimalLiveScenario(t, "scenario-techniques")
		h := New(pool, ws.NewHub(), engine, "")
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
		sc, engine := minimalLiveScenario(t, "scenario-stepidx")
		h := New(pool, ws.NewHub(), engine, "")
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
		sc, engine := minimalPostureScenario(t, "scenario-mode")
		h := New(pool, ws.NewHub(), engine, "")
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
		fake.WaitForMessage(t, 2*time.Second)

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
		posture, postureEngine := minimalPostureScenario(t, "scenario-notexec")
		h := New(pool, ws.NewHub(), postureEngine, "")
		agentID := "agent-liveGates"
		seedActiveAgent(t, pool, agentID, "Windows")

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(posture.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("non-executable scenario in telemetry: status = %d, want 400", rec.Code)
		}

		live, liveEngine := minimalLiveScenario(t, "scenario-noconfirm")
		h2 := New(pool, ws.NewHub(), liveEngine, "")
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
		sc, engine := minimalLiveScenario(t, "scenario-osmismatch")
		sc.SupportedOS = []string{"linux"}
		if err := engine.SaveAs(context.Background(), sc, "user:test"); err != nil {
			t.Fatalf("re-save with SupportedOS: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")
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
		sc, engine := minimalLiveScenario(t, "scenario-window")
		sc.LivePolicy = &scenario.LivePolicy{ExecutionWindow: "00:00-00:01"} // a window almost certainly not "now"
		if err := engine.SaveAs(context.Background(), sc, "user:test"); err != nil {
			t.Fatalf("re-save with LivePolicy: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "agent-window"
		seedActiveAgent(t, pool, agentID, "Windows")

		rec := httptest.NewRecorder()
		h.RunScenario(rec, runScenarioReq(sc.ID, map[string]any{"agentId": agentID, "mode": "telemetry", "confirmLive": true}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("outside execution window: status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}

		badWindow, badWindowEngine := minimalLiveScenario(t, "scenario-badwindow")
		badWindow.LivePolicy = &scenario.LivePolicy{ExecutionWindow: "not-a-window"}
		if err := badWindowEngine.SaveAs(context.Background(), badWindow, "user:test"); err != nil {
			t.Fatalf("re-save with bad LivePolicy: %v", err)
		}
		h2 := New(pool, ws.NewHub(), badWindowEngine, "")
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
		sc, engine := minimalPostureScenario(t, "scenario-agentstate")
		h := New(pool, ws.NewHub(), engine, "")
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
