package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedVariantResult inserts one scenario_variant_results row — the shape
// GetVariantCoverageReport/GetVariantMatrix/computeVariantTechniqueSummary's
// best-bypass lookup all read.
func seedVariantResult(t *testing.T, pool *pgxpool.Pool, id, runID, techID, stepID, variantID, encoding, privilege, execCtx, verdict string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO scenario_variant_results
			(id, run_id, scenario_id, step_id, variant_id, technique_id,
			 encoding, privilege, execution_context, verdict)
		 VALUES ($1,$2,'__variant__test',$3,$4,$5,$6,$7,$8,$9)`,
		id, runID, stepID, variantID, techID, encoding, privilege, execCtx, verdict); err != nil {
		t.Fatalf("seed scenario_variant_result: %v", err)
	}
}

func seedVariantTechniqueSummary(t *testing.T, pool *pgxpool.Pool, runID, techID, techName, tactic string, executed, blocked, detected, logged, bypassed, errs int, bestBypassID *string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO scenario_variant_technique_summary
			(run_id, technique_id, technique_name, tactic, variants_executed,
			 blocked, detected, logged, bypassed, errors, best_bypass_variant_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		runID, techID, techName, tactic, executed, blocked, detected, logged, bypassed, errs, bestBypassID); err != nil {
		t.Fatalf("seed scenario_variant_technique_summary: %v", err)
	}
}

func TestGetVariantCoverageReport_RunNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetVariantCoverageReport(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetVariantCoverageReport_NoVariantDepth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "gvcr-none-run", "gvcr-none-agent", reportRunOpts{})
		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetVariantCoverageReport(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", "gvcr-none-run"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			VariantDepth string           `json:"variantDepth"`
			Techniques   []map[string]any `json:"techniques"`
			Summary      map[string]any   `json:"summary"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.VariantDepth != "none" || len(out.Techniques) != 0 {
			t.Fatalf("out = %+v, want variantDepth=none and empty techniques", out)
		}
	})
}

// TestGetVariantCoverageReport_WithData seeds a pre-computed technique
// summary plus its best-bypass detail row directly (bypassing
// computeVariantTechniqueSummary, which is tested separately below) to pin
// the report's read/assembly logic: bypass rate, headline/remediation
// attachment, and the run-level summary rollup.
func TestGetVariantCoverageReport_WithData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "gvcr-data-run"
		seedReportableRun(t, pool, runID, "gvcr-data-agent", reportRunOpts{})
		if _, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET variant_depth='full' WHERE id=$1`, runID); err != nil {
			t.Fatalf("set variant_depth: %v", err)
		}
		seedVariantResult(t, pool, "gvcr-best-1", runID, "T1059.001", "step-1", "v1", "base64", "user", "direct", "bypassed")
		bestID := "gvcr-best-1"
		seedVariantTechniqueSummary(t, pool, runID, "T1059.001", "PowerShell", "execution",
			10, 6, 2, 0, 2, 0, &bestID)

		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetVariantCoverageReport(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "runId", runID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Techniques []struct {
				TechniqueID       string   `json:"techniqueId"`
				VariantsExecuted  int      `json:"variantsExecuted"`
				Bypassed          int      `json:"bypassed"`
				HasBypass         bool     `json:"hasBypass"`
				BypassRate        float64  `json:"bypassRate"`
				Headline          string   `json:"headline"`
				RemediationPoints []string `json:"remediationPoints"`
				BestBypass        struct {
					Encoding string `json:"encoding"`
				} `json:"bestBypass"`
			} `json:"techniques"`
			Summary struct {
				TechniquesTotal      int `json:"techniquesTotal"`
				TechniquesWithBypass int `json:"techniquesWithBypass"`
				VariantsExecuted     int `json:"variantsExecuted"`
			} `json:"summary"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(out.Techniques) != 1 {
			t.Fatalf("techniques = %+v, want 1 entry", out.Techniques)
		}
		tc := out.Techniques[0]
		if tc.TechniqueID != "T1059.001" || !tc.HasBypass || tc.Bypassed != 2 {
			t.Fatalf("technique row = %+v, want T1059.001 hasBypass=true bypassed=2", tc)
		}
		if tc.Headline == "" || len(tc.RemediationPoints) == 0 {
			t.Error("expected a non-empty headline + remediation points for a bypassed technique")
		}
		if tc.BestBypass.Encoding != "base64" {
			t.Errorf("bestBypass.encoding = %q, want base64", tc.BestBypass.Encoding)
		}
		if out.Summary.TechniquesTotal != 1 || out.Summary.VariantsExecuted != 10 {
			t.Errorf("summary = %+v, want techniquesTotal=1 variantsExecuted=10", out.Summary)
		}
	})
}

func TestGetVariantMatrix_OrderingAndBestBypassFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "gvm-run"
		seedReportableRun(t, pool, runID, "gvm-agent", reportRunOpts{})
		seedVariantResult(t, pool, "gvm-blocked", runID, "T1059.001", "s1", "v1", "plain", "user", "direct", "blocked")
		seedVariantResult(t, pool, "gvm-bypassed", runID, "T1059.001", "s1", "v2", "charcode", "system", "com", "bypassed")
		bestID := "gvm-bypassed"
		seedVariantTechniqueSummary(t, pool, runID, "T1059.001", "PowerShell", "execution", 2, 1, 0, 0, 1, 0, &bestID)

		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetVariantMatrix(rec, withURLParams(httptest.NewRequest(http.MethodGet, "/x", nil),
			map[string]string{"runId": runID, "techniqueId": "T1059.001"}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			Total int `json:"total"`
			Rows  []struct {
				ID           string `json:"id"`
				Verdict      string `json:"verdict"`
				IsBestBypass bool   `json:"isBestBypass"`
			} `json:"rows"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Total != 2 {
			t.Fatalf("total = %d, want 2", out.Total)
		}
		// bypassed sorts before blocked (worst-first ordering).
		if out.Rows[0].Verdict != "bypassed" || !out.Rows[0].IsBestBypass {
			t.Fatalf("rows[0] = %+v, want bypassed + isBestBypass=true first", out.Rows[0])
		}
		if out.Rows[1].Verdict != "blocked" || out.Rows[1].IsBestBypass {
			t.Fatalf("rows[1] = %+v, want blocked + isBestBypass=false second", out.Rows[1])
		}
	})
}

// TestComputeVariantTechniqueSummary_NoVariantMeta_FastPathNoOp pins the
// early return: a step_meta map with no BaseTaskID entries means nothing to
// aggregate.
func TestComputeVariantTechniqueSummary_NoVariantMeta_FastPathNoOp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		h.computeVariantTechniqueSummary(context.Background(), "cvts-noop-run",
			[]models.SimulationResult{{ID: "t1", Result: models.ResultFail}},
			map[string]scenario.StepMeta{"t1": {TechniqueID: "T1059.001"}}) // no BaseTaskID
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM scenario_variant_technique_summary WHERE run_id='cvts-noop-run'`).Scan(&n)
		if n != 0 {
			t.Fatalf("expected no summary rows without variant meta, got %d", n)
		}
	})
}

// TestComputeVariantTechniqueSummary_AggregatesAndFindsBestBypass pins the
// core aggregation: per-technique verdict counts from simResults, plus the
// best-bypass lookup against a pre-existing scenario_variant_results row
// (written by persistVariantResults in production — out of 3e.6's scope,
// simulated here via seedVariantResult).
func TestComputeVariantTechniqueSummary_AggregatesAndFindsBestBypass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "cvts-agg-run"
		seedVariantResult(t, pool, "cvts-best", runID, "T1059.001", "base-1", "v-bypass", "base64", "user", "direct", "bypassed")

		results := []models.SimulationResult{
			{ID: "task-blocked", Result: models.ResultPass, Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}},
			{ID: "task-bypassed", Result: models.ResultFail, Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}},
		}
		meta := map[string]scenario.StepMeta{
			"task-blocked":  {TechniqueID: "T1059.001", BaseTaskID: "base-1", VariantSpec: &scenario.VariantSpec{Encoding: "plain", Privilege: "user", ExecContext: "direct"}},
			"task-bypassed": {TechniqueID: "T1059.001", BaseTaskID: "base-1", VariantSpec: &scenario.VariantSpec{Encoding: "base64", Privilege: "user", ExecContext: "direct"}},
		}
		h := variantHandler(t, pool)
		h.computeVariantTechniqueSummary(context.Background(), runID, results, meta)

		var total, blocked, bypassed int
		var bestBypassID *string
		if err := pool.QueryRow(context.Background(),
			`SELECT variants_executed, blocked, bypassed, best_bypass_variant_id
			   FROM scenario_variant_technique_summary WHERE run_id=$1 AND technique_id='T1059.001'`,
			runID,
		).Scan(&total, &blocked, &bypassed, &bestBypassID); err != nil {
			t.Fatalf("expected a summary row: %v", err)
		}
		if total != 2 || blocked != 1 || bypassed != 1 {
			t.Fatalf("total=%d blocked=%d bypassed=%d, want 2/1/1", total, blocked, bypassed)
		}
		if bestBypassID == nil || *bestBypassID != "cvts-best" {
			t.Fatalf("bestBypassID = %v, want cvts-best", bestBypassID)
		}
	})
}

func TestGetVariantCoverage_AggregatesOncePerTechnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedReportableRun(t, pool, "gvc-run", "gvc-agent", reportRunOpts{
			Results: []models.SimulationResult{
				{ID: "r1", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail},
				{ID: "r2", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultPass},
			},
		})
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO variant_runs (agent_id, technique_id, base_type, base_id, scenario_run_id, total_variants, status)
			 VALUES ('gvc-agent','T1059.001','art','test','gvc-run',2,'completed')`); err != nil {
			t.Fatalf("seed variant_run: %v", err)
		}

		h := variantHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetVariantCoverage(rec, httptest.NewRequest(http.MethodGet, "/api/variants/coverage", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out []struct {
			TechniqueID string `json:"techniqueId"`
			TotalTested int    `json:"totalTested"`
			Allowed     int    `json:"allowed"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 1 || out[0].TechniqueID != "T1059.001" || out[0].TotalTested != 2 || out[0].Allowed != 1 {
			t.Fatalf("coverage = %+v, want 1 row T1059.001 totalTested=2 allowed=1", out)
		}
	})
}

func TestGetVariantStats_ReflectsSeededCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := variantHandler(t, pool)
		h.CreatePayloadFamily(httptest.NewRecorder(), createFamilyReq(map[string]any{
			"techniqueId": "T1021.001", "name": "stats-family", "payload": "echo hi",
		}))
		agentID := "gvs-agent"
		seedActiveAgent(t, pool, agentID, "Windows")
		fake := startFakeAgent(t, h.hub, agentID)
		h.RunVariants(httptest.NewRecorder(), variantsRunReq(map[string]any{
			"agentId": agentID, "techniqueId": "T1059.001", "command": "whoami", "executor": "powershell",
		}))
		fake.WaitForMessage(t, 2*time.Second)
		fake.Disconnect(t)

		rec := httptest.NewRecorder()
		h.GetVariantStats(rec, httptest.NewRequest(http.MethodGet, "/api/variants/stats", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			PayloadFamilyCount int `json:"payloadFamilyCount"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.PayloadFamilyCount == 0 {
			t.Error("expected at least the seeded default families to be counted")
		}
	})
}

// TestRefreshCampaignVariantSummary_AggregatesAcrossRuns pins the
// campaign-level rollup: technique summaries from two child runs get
// combined into one campaign_variant_summary row (blocked/detected/bypassed
// totals, prevention score, and a top-bypasses entry for the technique that
// bypassed controls).
func TestRefreshCampaignVariantSummary_AggregatesAcrossRuns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		campID := "rcvs-camp"
		seedCampaign(t, pool, campID, "Campaign Variant Summary Scenario")
		seedReportableRun(t, pool, "rcvs-run-1", "rcvs-agent-1", reportRunOpts{CampaignID: campID})
		seedReportableRun(t, pool, "rcvs-run-2", "rcvs-agent-2", reportRunOpts{CampaignID: campID})

		seedVariantResult(t, pool, "rcvs-best", "rcvs-run-1", "T1059.001", "s1", "v1", "base64", "user", "direct", "bypassed")
		bestID := "rcvs-best"
		seedVariantTechniqueSummary(t, pool, "rcvs-run-1", "T1059.001", "PowerShell", "execution", 10, 6, 2, 0, 2, 0, &bestID)
		seedVariantTechniqueSummary(t, pool, "rcvs-run-2", "T1059.001", "PowerShell", "execution", 10, 8, 1, 0, 1, 0, nil)

		h := variantHandler(t, pool)
		h.refreshCampaignVariantSummary(context.Background(), campID)

		var techTested, varExec, blocked, bypassed, runCount int
		var prevScore float64
		var topJSON []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT techniques_tested, variants_executed, blocked, bypassed, run_count, prevention_score, top_bypasses
			   FROM campaign_variant_summary WHERE campaign_id=$1`, campID,
		).Scan(&techTested, &varExec, &blocked, &bypassed, &runCount, &prevScore, &topJSON); err != nil {
			t.Fatalf("expected a campaign_variant_summary row: %v", err)
		}
		if techTested != 1 || varExec != 20 || blocked != 14 || bypassed != 3 || runCount != 2 {
			t.Fatalf("techTested=%d varExec=%d blocked=%d bypassed=%d runCount=%d, want 1/20/14/3/2",
				techTested, varExec, blocked, bypassed, runCount)
		}
		if prevScore <= 0 {
			t.Error("expected a non-zero prevention_score")
		}
		var topBypasses []map[string]any
		json.Unmarshal(topJSON, &topBypasses)
		if len(topBypasses) != 1 || topBypasses[0]["techniqueId"] != "T1059.001" {
			t.Fatalf("top_bypasses = %s, want one T1059.001 entry", topJSON)
		}
	})
}
