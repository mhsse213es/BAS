package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedRunForVerification inserts a minimal scenario_runs + agents row pair so
// loadRunForVerification/runDetectionVerification have something to load.
func seedRunForVerification(t *testing.T, pool *pgxpool.Pool, runID, scenarioID, agentID, hostname string, results []models.SimulationResult) {
	t.Helper()
	resultsJSON, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	_, err = pool.Exec(context.Background(),
		`INSERT INTO agents (agent_id, hostname, ip_address) VALUES ($1,$2,'10.0.0.9')
		 ON CONFLICT (agent_id) DO NOTHING`, agentID, hostname)
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	_, err = pool.Exec(context.Background(),
		`INSERT INTO scenario_runs (id, scenario_id, agent_id, status, started_at, results)
		 VALUES ($1,$2,$3,'completed',NOW(),$4)`, runID, scenarioID, agentID, resultsJSON)
	if err != nil {
		t.Fatalf("seed run: %v", err)
	}
}

// TestTriggerDetectionVerification_EndToEnd seeds a scenario with one
// api-verified expectation, a completed run, and a fake Detected connector,
// then drives the whole path — manual trigger -> DB load -> VerifyRun ->
// Attest -> verification_history row — via runDetectionVerification directly
// (the HTTP handler only dispatches this in a goroutine; the dispatch logic
// itself is exercised in orchestrate_test.go).
func TestTriggerDetectionVerification_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		h.detectVerifyConnector = func(cfg detectverify.Config) (detectverify.Connector, error) {
			return &fakeDetectConnector{result: detectverify.VerifyResult{
				Verdict:       detectverify.VerdictDetected,
				MatchedAlerts: []detectverify.MatchedAlert{{AlertID: "a1"}},
			}}, nil
		}

		sc := &scenario.Scenario{
			ID: "sc-trigger-1", Name: "Trigger Test Scenario",
			Steps: []scenario.Step{
				{
					Name: "step1", TechniqueID: "T1059.001",
					ExpectedDetections: []scenario.ExpectedDetection{
						{ID: "exp-1", Provider: "microsoft_sentinel", Verification: scenario.VerificationAPI, Confidence: scenario.ConfidenceRequired},
					},
				},
			},
		}
		if err := h.engine.SaveAs(context.Background(), sc, "user:test"); err != nil {
			t.Fatalf("seed scenario: %v", err)
		}

		createRec := httptest.NewRecorder()
		h.CreateDetectionConnector(createRec, detectverifyConfigReq(map[string]any{
			"name": "trig", "provider": "microsoft_sentinel", "enabled": true,
		}))

		runStart := time.Now()
		results := []models.SimulationResult{
			{Technique: models.AttackTechnique{ID: "T1059.001"}, Result: models.ResultFail, ExecutedAt: runStart, DurationMs: 1000},
		}
		seedRunForVerification(t, pool, "run-trigger-1", "sc-trigger-1", "agent-trigger-1", "HOST1", results)

		rec := httptest.NewRecorder()
		h.TriggerDetectionVerification(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "runId", "run-trigger-1"))
		if rec.Code != http.StatusOK {
			t.Fatalf("trigger: status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}

		deadline := time.Now().Add(5 * time.Second)
		var n int
		for time.Now().Before(deadline) {
			pool.QueryRow(context.Background(),
				`SELECT COUNT(*) FROM verification_history WHERE run_id='run-trigger-1' AND expectation_id='exp-1'`).Scan(&n)
			if n > 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if n != 1 {
			t.Fatalf("verification_history rows for run-trigger-1/exp-1 = %d, want 1", n)
		}
		var result, source string
		pool.QueryRow(context.Background(),
			`SELECT result, verification_source FROM verification_history WHERE run_id='run-trigger-1' AND expectation_id='exp-1' AND active`,
		).Scan(&result, &source)
		if result != "Detected" || source != "api" {
			t.Fatalf("result=%q source=%q, want Detected/api", result, source)
		}
	})
}

// TestAutoVerifyDetection_OnlyDispatchesAutoVerifyConnectors pins the filter:
// AutoVerifyDetection only fires for connectors with enabled=true AND
// auto_verify=true — mirrors TestAutoCorrelateSIEM_OnlyDispatchesEnabledAutoCorrelateConfigs.
func TestAutoVerifyDetection_OnlyDispatchesAutoVerifyConnectors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := detectverifyHandler(t, pool)
		h.detectVerifyConnector = func(cfg detectverify.Config) (detectverify.Connector, error) {
			return &fakeDetectConnector{}, nil
		}

		sc := &scenario.Scenario{
			ID: "sc-auto-1", Name: "Auto Verify Test Scenario",
			Steps: []scenario.Step{
				{
					Name: "step1", TechniqueID: "T1059.001",
					ExpectedDetections: []scenario.ExpectedDetection{
						{ID: "exp-auto-1", Provider: "microsoft_sentinel", Verification: scenario.VerificationAPI, Confidence: scenario.ConfidenceRequired},
					},
				},
			},
		}
		if err := h.engine.SaveAs(context.Background(), sc, "user:test"); err != nil {
			t.Fatalf("seed scenario: %v", err)
		}

		mustCreateConnector := func(name string, enabled, autoVerify bool) {
			rec := httptest.NewRecorder()
			h.CreateDetectionConnector(rec, detectverifyConfigReq(map[string]any{
				"name": name, "provider": "microsoft_sentinel", "enabled": enabled, "autoVerify": autoVerify,
				"verifyDelaySeconds": 1,
			}))
			if rec.Code != http.StatusOK {
				t.Fatalf("create %s: status = %d", name, rec.Code)
			}
		}
		mustCreateConnector("auto-on", true, true)   // should fire
		mustCreateConnector("auto-off", true, false) // manual only — skipped
		mustCreateConnector("disabled", false, true) // disabled — skipped

		results := []models.SimulationResult{
			{Technique: models.AttackTechnique{ID: "T1059.001"}, Result: models.ResultFail, ExecutedAt: time.Now(), DurationMs: 1000},
		}
		seedRunForVerification(t, pool, "run-auto-1", "sc-auto-1", "agent-auto-1", "HOST1", results)

		h.AutoVerifyDetection("run-auto-1")

		deadline := time.Now().Add(8 * time.Second)
		var n int
		for time.Now().Before(deadline) {
			pool.QueryRow(context.Background(),
				`SELECT COUNT(*) FROM verification_history WHERE run_id='run-auto-1'`).Scan(&n)
			if n > 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if n != 1 {
			t.Fatalf("verification_history rows for run-auto-1 = %d, want exactly 1 (only auto-on should fire)", n)
		}
	})
}
