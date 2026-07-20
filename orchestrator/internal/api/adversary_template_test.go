package api

import (
	"bytes"
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

func runAdversaryTemplateReq(id string, body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return withURLParam(httptest.NewRequest(http.MethodPost, "/api/adversary-templates/"+id+"/run", bytes.NewReader(b)), "id", id)
}

// TestRunAdversaryTemplate_ExecutionPolicyFiltersStep uses the built-in
// "apt29-quick" template, whose BASScenarioID is "apt29-kill-chain" — a
// scenario is registered under that exact ID so the template's BAS branch
// resolves it via h.engine.Get, without needing a real ART store or Caldera.
func TestRunAdversaryTemplate_ExecutionPolicyFiltersStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		steps := []scenario.Step{
			{Name: "user-step", TechniqueID: "T1059", Framework: "custom", Command: "echo user",
				RequiresPriv: scenario.PrivSpec{Minimum: "user"}},
			{Name: "admin-step", TechniqueID: "T1548", Framework: "custom", Command: "echo admin",
				RequiresPriv: scenario.PrivSpec{Minimum: "admin"}},
		}
		_, engine := minimalLiveScenario(t, "apt29-kill-chain", steps...)
		h := New(pool, ws.NewHub(), engine, "")
		agentID := "rat-execpolicy-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunAdversaryTemplate(rec, runAdversaryTemplateReq("apt29-quick", map[string]any{
			"agentId": agentID, "mode": "telemetry", "useBas": true,
			"executionPolicy": map[string]any{"maxPrivilege": "user"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		var cmd scenario.ScenarioCommand
		if err := json.Unmarshal(env.Data, &cmd); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "user-step" {
			t.Fatalf("cmd.Steps = %+v, want exactly [user-step] (admin-step must be filtered)", cmd.Steps)
		}

		var out struct {
			Dispatched []struct {
				Source string `json:"source"`
				RunID  string `json:"runId"`
			} `json:"dispatched"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Dispatched) != 1 || out.Dispatched[0].RunID == "" {
			t.Fatalf("out = %+v, want exactly 1 dispatched entry with a runId", out)
		}

		var skippedJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT policy_skipped_results FROM scenario_runs WHERE id=$1`, out.Dispatched[0].RunID,
		).Scan(&skippedJSON); err != nil {
			t.Fatalf("query policy_skipped_results: %v", err)
		}
		var skipped []models.SimulationResult
		if err := json.Unmarshal(skippedJSON, &skipped); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(skipped) != 1 || skipped[0].SkipReason != models.SkipReasonPolicyPrivilege {
			t.Fatalf("policy_skipped_results = %+v, want 1 policy-privilege skip", skipped)
		}
	})
}
