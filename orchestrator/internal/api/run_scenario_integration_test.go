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
