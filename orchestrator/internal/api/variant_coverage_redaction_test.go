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

// A bypass (ALLOWED) on a credential-access step reports that step's details
// as FirstBypass in variant coverage. Those details must not leak the hash.
func TestGetVariantCoverage_CredentialAccessBypassDetailWithheld(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agentID := "vc-redact-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		h := variantHandler(t, pool)
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunVariants(rec, variantsRunReq(map[string]any{
			"agentId": agentID, "techniqueId": "T1003.001", "command": "mimikatz", "executor": "powershell",
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("RunVariants status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			VariantRunID  string `json:"variantRunId"`
			ScenarioRunID string `json:"scenarioRunId"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var taskID string
		if err := pool.QueryRow(t.Context(),
			`SELECT task_id FROM variant_run_steps WHERE variant_run_id = $1 ORDER BY id LIMIT 1`, out.VariantRunID,
		).Scan(&taskID); err != nil {
			t.Fatalf("read variant step: %v", err)
		}

		results := []models.SimulationResult{{
			ID:        taskID,
			Technique: models.AttackTechnique{ID: "T1003.001", Tactic: "credential-access"},
			Result:    models.CheckResult("fail"),
			Details:   "dumped NTLM " + exportTestNTLMHash,
		}}
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := pool.Exec(t.Context(),
			`UPDATE scenario_runs SET results = $1, status = 'completed' WHERE id = $2`, raw, out.ScenarioRunID); err != nil {
			t.Fatalf("seed results: %v", err)
		}
		if _, err := pool.Exec(t.Context(),
			`UPDATE variant_runs SET status = 'completed' WHERE id = $1`, out.VariantRunID); err != nil {
			t.Fatalf("complete variant run: %v", err)
		}

		router := mountTestRouter(t)
		tenantID := "default"
		tok, err := auth.GenerateTenantToken("vc-admin", auth.RoleAdmin, &tenantID, false, testJWTSecret, time.Hour)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/variants/coverage", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET coverage status = %d, body = %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), exportTestNTLMHash) {
			t.Fatal("variant coverage leaked a credential-access hash via FirstBypass")
		}
	})
}
