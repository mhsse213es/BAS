package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
)

const exportTestNTLMHash = "aad3b435b51404eeaad3b435b51404ee"

// A credential-dump step's raw output must not reach any export, even for
// a role that may read the run. Other steps' output is unaffected.
func TestExportRunJSON_CredentialAccessOutputWithheld(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		results := []models.SimulationResult{
			{ID: "cred", Technique: models.AttackTechnique{ID: "T1003.001", Tactic: "credential-access"},
				RawOutput: "Administrator:500:" + exportTestNTLMHash + ":::"},
			{ID: "exec", Technique: models.AttackTechnique{ID: "T1059.001", Tactic: "execution"},
				RawOutput: "exec-output-marker"},
		}
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatalf("marshal results: %v", err)
		}
		seedAgent(t, pool, "agent-export")
		var runID string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scenario_runs (scenario_id, agent_id, name, status, results)
			 VALUES ('scn-export', 'agent-export', 'Export Redaction Run', 'completed', $1) RETURNING id`, raw,
		).Scan(&runID); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		router := mountTestRouter(t)
		tenantID := "default"
		tok, err := auth.GenerateTenantToken("export-analyst", auth.RoleAnalyst, &tenantID, false, testJWTSecret, time.Hour)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/export", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, exportTestNTLMHash) {
			t.Fatal("export leaked a credential-access hash")
		}
		if !strings.Contains(body, "exec-output-marker") {
			t.Fatal("export dropped non-credential step output")
		}
		if !strings.Contains(body, models.CredentialOutputWithheld) {
			t.Fatal("export did not mark the withheld credential output")
		}
	})
}
