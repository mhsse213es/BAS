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

const exportTestBearerToken = "eyJhbGciOiJIUzI1NiJ9.payload.sig"

// A secret printed by an ordinary step must not reach the run export, while
// the rest of that step's output is kept.
func TestExportRunJSON_OrdinaryStepSecretWithheld(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		results := []models.SimulationResult{
			{ID: "exec", Technique: models.AttackTechnique{ID: "T1059.001", Tactic: "execution"},
				RawOutput: "Authorization: Bearer " + exportTestBearerToken + " status=ok"},
		}
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatalf("marshal results: %v", err)
		}
		seedAgent(t, pool, "agent-secret-export")
		var runID string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scenario_runs (scenario_id, agent_id, name, status, results)
			 VALUES ('scn-secret', 'agent-secret-export', 'Secret Export Run', 'completed', $1) RETURNING id`, raw,
		).Scan(&runID); err != nil {
			t.Fatalf("seed scenario_run: %v", err)
		}

		router := mountTestRouter(t)
		tenantID := "default"
		tok, err := auth.GenerateTenantToken("secret-analyst", auth.RoleAnalyst, &tenantID, false, testJWTSecret, time.Hour)
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
		if strings.Contains(body, exportTestBearerToken) {
			t.Fatal("export leaked a bearer token from an ordinary step")
		}
		if !strings.Contains(body, "status=ok") {
			t.Fatal("export dropped non-secret output of an ordinary step")
		}
	})
}
