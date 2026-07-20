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

// fakeCalderaServer stubs the two Caldera endpoints buildCalderaAdversarySteps
// needs: GET /api/v2/adversaries/{id} (atomic_ordering) and
// GET /api/v2/abilities/{id} (per-ability detail, including privilege).
func fakeCalderaServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v2/adversaries/adv-1":
			_, _ = w.Write([]byte(`{"adversary_id":"adv-1","name":"Test Adversary","atomic_ordering":["a1","a2"]}`))
		case "/api/v2/abilities/a1":
			_, _ = w.Write([]byte(`{"ability_id":"a1","name":"user-ability","technique_id":"T1059","tactic":"execution","privilege":"",
				"executors":[{"platform":"windows","name":"psh","command":"echo user"}]}`))
		case "/api/v2/abilities/a2":
			_, _ = w.Write([]byte(`{"ability_id":"a2","name":"admin-ability","technique_id":"T1548","tactic":"privilege-escalation","privilege":"Elevated",
				"executors":[{"platform":"windows","name":"psh","command":"echo admin"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func runCalderaAdversaryReq(adversaryID string, body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return withURLParam(httptest.NewRequest(http.MethodPost, "/api/caldera/adversaries/"+adversaryID+"/run", bytes.NewReader(b)), "adversaryId", adversaryID)
}

func TestRunCalderaAdversary_ExecutionPolicyFiltersStep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := fakeCalderaServer(t)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithCaldera(srv.URL, "")
		agentID := "rca-execpolicy-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunCalderaAdversary(rec, runCalderaAdversaryReq("adv-1", map[string]any{
			"agentId": agentID, "mode": "telemetry", "confirmLive": true,
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
		if len(cmd.Steps) != 1 || cmd.Steps[0].Name != "user-ability" {
			t.Fatalf("cmd.Steps = %+v, want exactly [user-ability] (admin-ability must be filtered)", cmd.Steps)
		}

		var out struct {
			RunID string `json:"runId"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.RunID == "" {
			t.Fatal("response missing runId")
		}

		var skippedJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT policy_skipped_results FROM scenario_runs WHERE id=$1`, out.RunID,
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
