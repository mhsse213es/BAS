package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// The run list returns each run's results. A credential-access step's raw
// output must not appear there either, same as on the export path.
func TestListScenarioRuns_CredentialAccessOutputWithheld(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		results := []models.SimulationResult{
			{ID: "cred", Technique: models.AttackTechnique{ID: "T1003.001", Tactic: "credential-access"},
				RawOutput: "Administrator:500:" + exportTestNTLMHash + ":::"},
			{ID: "exec", Technique: models.AttackTechnique{ID: "T1059.001", Tactic: "execution"},
				RawOutput: "list-exec-marker"},
		}
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatalf("marshal results: %v", err)
		}
		seedAgent(t, pool, "agent-list-redact")
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results)
			 VALUES ('list-redact-run', 'scn-list-redact', 'agent-list-redact', 'List Redaction Run', 'completed', $1)`, raw,
		); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, exportTestNTLMHash) {
			t.Fatal("run list leaked a credential-access hash")
		}
		if !strings.Contains(body, "list-exec-marker") {
			t.Fatal("run list dropped non-credential step output")
		}
		if !strings.Contains(body, models.CredentialOutputWithheld) {
			t.Fatal("run list did not mark the withheld credential output")
		}
	})
}
