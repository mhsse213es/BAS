package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

type coverageAnalyticsResponse struct {
	RunsAnalyzed int `json:"runsAnalyzed"`
	Summary      struct {
		Prevented int `json:"prevented"`
	} `json:"summary"`
}

func TestGetCoverageAnalytics_ReturnsTalliedResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'Test Run', 'a1', 'completed',
				'[{"technique":{"id":"T1059","name":"Command and Scripting Interpreter","tactic":"execution"},"result":"pass"}]', NOW())`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetCoverageAnalytics(rec, httptest.NewRequest(http.MethodGet, "/api/coverage/analytics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got coverageAnalyticsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if got.RunsAnalyzed != 1 || got.Summary.Prevented != 1 {
			t.Errorf("response = %+v, want RunsAnalyzed=1 Summary.Prevented=1", got)
		}
	})
}

func TestGetCoverageAnalytics_ScenarioIDQueryParamFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-1', 'scn-1', 'Run 1', 'a1', 'completed',
				'[{"technique":{"id":"T1059","name":"x","tactic":"execution"},"result":"pass"}]', NOW())`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('run-2', 'scn-2', 'Run 2', 'a1', 'completed',
				'[{"technique":{"id":"T1078","name":"y","tactic":"defense-evasion"},"result":"pass"}]', NOW())`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetCoverageAnalytics(rec, httptest.NewRequest(http.MethodGet, "/api/coverage/analytics?scenarioId=scn-1", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got coverageAnalyticsResponse
		json.Unmarshal(rec.Body.Bytes(), &got)
		if got.RunsAnalyzed != 1 {
			t.Errorf("RunsAnalyzed = %d, want 1 (scenarioId=scn-1 query param filtered out run-2)", got.RunsAnalyzed)
		}
	})
}
