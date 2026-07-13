package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
)

func variantsGenerateReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/variants/generate", bytes.NewReader(b))
}

func variantsRunReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/variants/run", bytes.NewReader(b))
}

func TestGenerateVariants_MissingTechniqueId(t *testing.T) {
	h := variantHandler(t, nil)
	rec := httptest.NewRecorder()
	h.GenerateVariants(rec, variantsGenerateReq(map[string]any{}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestGenerateVariants_MalformedJSON(t *testing.T) {
	h := variantHandler(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/variants/generate", bytes.NewReader([]byte(`{"techniqueId":`)))
	rec := httptest.NewRecorder()
	h.GenerateVariants(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestGenerateVariants_NoFamiliesNoARTStore pins resolveTemplates' final
// fallback: with no command override, no payload families for the
// technique, and no ART store loaded, the handler reports a clean 400
// rather than panicking on the nil artStore.
func TestGenerateVariants_NoFamiliesNoARTStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool) // no WithART
		rec := httptest.NewRecorder()
		h.GenerateVariants(rec, variantsGenerateReq(map[string]any{"techniqueId": "T1055.012"}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestGenerateVariants_CommandOverride pins the first resolveTemplates path:
// an explicit command+executor generates from that script directly, no DB
// lookups needed.
func TestGenerateVariants_CommandOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GenerateVariants(rec, variantsGenerateReq(map[string]any{
			"techniqueId": "T1059.001", "command": "whoami /all", "executor": "powershell",
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Count     int              `json:"count"`
			BaseID    string           `json:"baseId"`
			Templates []map[string]any `json:"templates"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Count == 0 || len(out.Templates) != out.Count {
			t.Fatalf("out = %+v, want count>0 matching len(templates)", out)
		}
		if out.BaseID != "custom" {
			t.Errorf("baseId = %q, want custom (no baseId supplied with an override)", out.BaseID)
		}
	})
}

// TestGenerateVariants_FromARTStoreFallback pins resolveTemplates' third and
// final path (resolveBaseCommand): with no override and no payload families
// for the technique, it falls back to the first ART atomic step loaded for
// that technique. Builds a real ARTStore from the DB (NewARTStoreFromDB) —
// the same constructor production uses — rather than mocking it.
func TestGenerateVariants_FromARTStoreFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO techniques (technique_id, name, tactic) VALUES ('T1055.012','Process Hollowing','defense-evasion')
			 ON CONFLICT (technique_id) DO NOTHING`); err != nil {
			t.Fatalf("seed technique: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command)
			 VALUES ('T1055.012', 0, 'art-fallback-step', 'powershell', 'Get-Process')`); err != nil {
			t.Fatalf("seed art_atomic_tests: %v", err)
		}
		store, err := scenario.NewARTStoreFromDB(context.Background(), pool, nil)
		if err != nil {
			t.Fatalf("NewARTStoreFromDB: %v", err)
		}

		h := variantHandler(t, pool).WithART(store)
		rec := httptest.NewRecorder()
		h.GenerateVariants(rec, variantsGenerateReq(map[string]any{"techniqueId": "T1055.012"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Count  int    `json:"count"`
			BaseID string `json:"baseId"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Count == 0 {
			t.Fatal("expected templates generated from the ART-fallback step")
		}
		if out.BaseID != "art-fallback-step" {
			t.Errorf("baseId = %q, want art-fallback-step (the ART step's name)", out.BaseID)
		}
	})
}

// TestGenerateVariants_ARTStoreNoStepsForTechnique pins resolveBaseCommand's
// "no ART steps found" error branch: an ART store is loaded, but has no
// entries for the requested technique.
func TestGenerateVariants_ARTStoreNoStepsForTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store, err := scenario.NewARTStoreFromDB(context.Background(), pool, nil)
		if err != nil {
			t.Fatalf("NewARTStoreFromDB: %v", err)
		}
		h := variantHandler(t, pool).WithART(store)
		rec := httptest.NewRecorder()
		h.GenerateVariants(rec, variantsGenerateReq(map[string]any{"techniqueId": "T1499.999"}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestGenerateVariants_FromPayloadFamilies pins the second resolveTemplates
// path: when families exist for the technique (and no override given),
// templates are generated per-family.
func TestGenerateVariants_FromPayloadFamilies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		h.CreatePayloadFamily(httptest.NewRecorder(), createFamilyReq(map[string]any{
			"techniqueId": "T1003.001", "name": "gv-family", "payload": "Get-Process lsass",
		}))

		rec := httptest.NewRecorder()
		h.GenerateVariants(rec, variantsGenerateReq(map[string]any{"techniqueId": "T1003.001"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Count  int    `json:"count"`
			BaseID string `json:"baseId"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Count == 0 {
			t.Fatal("expected templates generated from the payload family")
		}
		if out.BaseID != "T1003.001" {
			t.Errorf("baseId = %q, want the technique id (family path)", out.BaseID)
		}
	})
}

// TestGenerateVariants_IncludeAdvancedFlag pins that includeAdvanced grows
// the template count relative to the default set (generator.go's own advanced
// pack behavior is unit-tested; this only checks the flag reaches it).
func TestGenerateVariants_IncludeAdvancedFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		base := httptest.NewRecorder()
		h.GenerateVariants(base, variantsGenerateReq(map[string]any{
			"techniqueId": "T1059.001", "command": "whoami", "executor": "powershell",
		}))
		var baseOut struct {
			Count int `json:"count"`
		}
		json.Unmarshal(base.Body.Bytes(), &baseOut)

		adv := httptest.NewRecorder()
		h.GenerateVariants(adv, variantsGenerateReq(map[string]any{
			"techniqueId": "T1059.001", "command": "whoami", "executor": "powershell", "includeAdvanced": true,
		}))
		var advOut struct {
			Count           int  `json:"count"`
			IncludeAdvanced bool `json:"includeAdvanced"`
		}
		json.Unmarshal(adv.Body.Bytes(), &advOut)
		if !advOut.IncludeAdvanced {
			t.Error("includeAdvanced flag not echoed back")
		}
		if advOut.Count <= baseOut.Count {
			t.Errorf("advanced count (%d) should exceed default count (%d)", advOut.Count, baseOut.Count)
		}
	})
}

func TestRunVariants_ValidationErrors(t *testing.T) {
	h := variantHandler(t, nil)
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing agentId", map[string]any{"techniqueId": "T1059.001"}},
		{"missing techniqueId", map[string]any{"agentId": "a1"}},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.RunVariants(rec, variantsRunReq(c.body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
		}
	}
}

// TestRunVariants_NoVariantsGenerated pins the 422 branch: a non-PowerShell
// executor with an override produces zero templates (variant.Generate
// returns nil for a "bash" executor — see internal/variant's own
// TestGenerateReturnsNilForNonPSExecutor). This returns before
// dispatchVariantRun's DB writes, so no agent needs to be seeded.
func TestRunVariants_NoVariantsGenerated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.RunVariants(rec, variantsRunReq(map[string]any{
			"agentId": "a1", "techniqueId": "T1059.003", "command": "whoami", "executor": "bash",
		}))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status = %d, want 422, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestRunVariants_AgentOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedActiveAgent(t, pool, "rv-offline-agent", "Windows")
		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.RunVariants(rec, variantsRunReq(map[string]any{
			"agentId": "rv-offline-agent", "techniqueId": "T1059.001", "command": "whoami", "executor": "powershell",
		}))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (agent not connected), body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestRunVariants_SuccessDispatchesAndPersists is the core end-to-end
// contract: a connected agent receives a command_scenario WS message, and
// scenario_runs/variant_runs/variant_run_steps rows are all created
// consistently.
func TestRunVariants_SuccessDispatchesAndPersists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agentID := "rv-ok-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		h := variantHandler(t, pool)
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.RunVariants(rec, variantsRunReq(map[string]any{
			"agentId": agentID, "techniqueId": "T1059.001", "command": "whoami", "executor": "powershell",
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			VariantRunID  string `json:"variantRunId"`
			ScenarioRunID string `json:"scenarioRunId"`
			TotalVariants int    `json:"totalVariants"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.VariantRunID == "" || out.ScenarioRunID == "" || out.TotalVariants == 0 {
			t.Fatalf("out = %+v, want all non-empty/non-zero", out)
		}

		env := fake.WaitForMessage(t, 2*time.Second)
		if env.Type != "command_scenario" {
			t.Fatalf("message type = %q, want command_scenario", env.Type)
		}

		var stepCount int
		if err := pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM variant_run_steps WHERE variant_run_id = $1`, out.VariantRunID,
		).Scan(&stepCount); err != nil {
			t.Fatalf("query variant_run_steps: %v", err)
		}
		if stepCount != out.TotalVariants {
			t.Errorf("variant_run_steps count = %d, want %d (totalVariants)", stepCount, out.TotalVariants)
		}

		var runStatus, vrStatus string
		pool.QueryRow(context.Background(), `SELECT status FROM scenario_runs WHERE id=$1`, out.ScenarioRunID).Scan(&runStatus)
		pool.QueryRow(context.Background(), `SELECT status FROM variant_runs WHERE id=$1`, out.VariantRunID).Scan(&vrStatus)
		if runStatus != "running" || vrStatus != "running" {
			t.Errorf("runStatus=%q vrStatus=%q, want both running", runStatus, vrStatus)
		}
	})
}

func TestGetVariantRun_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetVariantRun(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestGetVariantRun_JoinsResultsIntoVerdicts dispatches a real variant run,
// then simulates the agent's result submission (writing scenario_runs.results
// directly, mirroring what SubmitScenarioResult persists), and pins that
// GetVariantRun correctly joins step records to result verdicts.
func TestGetVariantRun_JoinsResultsIntoVerdicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		agentID := "gvr-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		h := variantHandler(t, pool)
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		runRec := httptest.NewRecorder()
		h.RunVariants(runRec, variantsRunReq(map[string]any{
			"agentId": agentID, "techniqueId": "T1059.001", "command": "whoami", "executor": "powershell",
		}))
		var runOut struct {
			VariantRunID  string `json:"variantRunId"`
			ScenarioRunID string `json:"scenarioRunId"`
		}
		json.Unmarshal(runRec.Body.Bytes(), &runOut)
		fake.WaitForMessage(t, 2*time.Second)

		var taskID string
		if err := pool.QueryRow(context.Background(),
			`SELECT task_id FROM variant_run_steps WHERE variant_run_id=$1 LIMIT 1`, runOut.VariantRunID,
		).Scan(&taskID); err != nil {
			t.Fatalf("query a step's task_id: %v", err)
		}
		resultsJSON := `[{"id":"` + taskID + `","result":"fail","details":"bypassed"}]`
		if _, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET status='completed', results=$1 WHERE id=$2`,
			resultsJSON, runOut.ScenarioRunID); err != nil {
			t.Fatalf("seed result: %v", err)
		}

		rec := httptest.NewRecorder()
		h.GetVariantRun(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", runOut.VariantRunID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Run struct {
				Status string `json:"status"`
			} `json:"run"`
			Results []struct {
				TaskID  string `json:"taskId"`
				Verdict string `json:"verdict"`
			} `json:"results"`
			Summary struct {
				Total   int `json:"total"`
				Allowed int `json:"allowed"`
			} `json:"summary"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Run.Status != "completed" {
			t.Errorf("run.status = %q, want completed (synced from scenario_run)", out.Run.Status)
		}
		if out.Summary.Allowed != 1 {
			t.Errorf("summary.allowed = %d, want 1", out.Summary.Allowed)
		}
		var found bool
		for _, res := range out.Results {
			if res.TaskID == taskID && res.Verdict == "ALLOWED" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a result with taskId=%s verdict=ALLOWED, got %+v", taskID, out.Results)
		}
	})
}
