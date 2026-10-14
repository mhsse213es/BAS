package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dxcorrelate"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestToAttemptRows_MapsStagingAndTransferIgnoresEncryptionCapabilities(t *testing.T) {
	rows := []db.RWAttemptRow{
		{TechniqueID: "T1560.001", Capability: "data_protection", Verdict: "FAIL", Action: "a1"},
		{TechniqueID: "T1567.002", Capability: "data_protection", Verdict: "PASS", Action: "a2"},
		{TechniqueID: "T1486", Capability: "prevention", Verdict: "FAIL", Action: "a3"},
		{TechniqueID: "T1486", Capability: "detection", Verdict: "PASS", Action: "a4"},
		{TechniqueID: "T1486", Capability: "containment", Verdict: "FAIL", Action: "a5"},
	}
	out := toAttemptRows(rows)
	if len(out) != 2 {
		t.Fatalf("got %d attempt rows, want 2 -- T1486's Prevention/Detection/Containment must never be translated", len(out))
	}
	byLeg := map[dxcorrelate.Leg]dxcorrelate.AttemptRow{}
	for _, r := range out {
		byLeg[r.Leg] = r
	}
	if byLeg[dxcorrelate.LegStaging].ControlEfficacy != dxcorrelate.EfficacyNotDetected {
		t.Errorf("staging ControlEfficacy = %q, want not_detected", byLeg[dxcorrelate.LegStaging].ControlEfficacy)
	}
	if byLeg[dxcorrelate.LegTransfer].ControlEfficacy != dxcorrelate.EfficacyDetected {
		t.Errorf("transfer ControlEfficacy = %q, want detected", byLeg[dxcorrelate.LegTransfer].ControlEfficacy)
	}
}

func TestToAttemptRows_BehaviorIsNeverDerivedFromControlEfficacy(t *testing.T) {
	for _, verdict := range []controlval.Verdict{"PASS", "FAIL", "ERROR", "SKIPPED"} {
		rows := []db.RWAttemptRow{{TechniqueID: "T1560.001", Capability: "data_protection", Verdict: verdict, SkipReason: "not_applicable", Action: "a"}}
		out := toAttemptRows(rows)
		if len(out) != 1 {
			t.Fatalf("verdict=%s: got %d attempt rows, want 1", verdict, len(out))
		}
		if out[0].Behavior != dxcorrelate.BehaviorNotEstablished {
			t.Fatalf("verdict=%s: Behavior = %q, want not_established -- control-efficacy must never establish behavior", verdict, out[0].Behavior)
		}
	}
}

func clopShapedDeps(runID, action, techniqueID string) rwevidence.StepDependencies {
	key := runID + "/" + techniqueID + "/" + action
	return rwevidence.StepDependencies{
		Prevention:     &controlval.FakeProvider{},
		Recovery:       &rwevidence.FakeRecoveryObserver{},
		Containment:    &rwevidence.FakeContainmentObserver{},
		Detection:      &rwevidence.FakeDetectionLookup{},
		DataProtection: &rwevidence.FakeDataProtectionLookup{Status: map[string]string{key: "NotDetected"}},
	}
}

func TestGetDoubleExtortionCorrelation_ClopShapedRun_ReportsHonestInsufficientEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "clop-shaped-run"

		stagingIn := rwevidence.StepInput{RunID: runID, Action: "staging-action", TechniqueID: "T1560.001", StepName: "Cl0p Stage 3 — Archive Staging via Compress-Archive (T1560.001)", CheckResult: "fail", Details: "FAIL: zip created unblocked"}
		stagingResults := rwevidence.EvaluateStep(stagingIn, clopShapedDeps(runID, "staging-action", "T1560.001"))
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "staging-action", stagingResults); err != nil {
			t.Fatalf("seed staging: %v", err)
		}

		transferIn := rwevidence.StepInput{RunID: runID, Action: "transfer-action", TechniqueID: "T1567.002", StepName: "Cl0p Stage 4 — Cloud Storage Egress Reachability (T1567.002)", CheckResult: "fail", Details: "FAIL: reachable"}
		transferResults := rwevidence.EvaluateStep(transferIn, clopShapedDeps(runID, "transfer-action", "T1567.002"))
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "transfer-action", transferResults); err != nil {
			t.Fatalf("seed transfer: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/double-extortion-correlation", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", runID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetDoubleExtortionCorrelation(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var got struct {
			Legs []struct {
				Leg             string `json:"leg"`
				ControlEfficacy string `json:"controlEfficacy"`
			} `json:"legs"`
			Classification string `json:"classification"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Classification != "insufficient_behavior_evidence" {
			t.Fatalf("Classification = %q, want insufficient_behavior_evidence -- real NotDetected control-efficacy evidence must never be promoted to a confirmed finding", got.Classification)
		}
		byLeg := map[string]string{}
		for _, l := range got.Legs {
			byLeg[l.Leg] = l.ControlEfficacy
		}
		if byLeg["staging"] != "not_detected" {
			t.Errorf("staging controlEfficacy = %q, want not_detected", byLeg["staging"])
		}
		if byLeg["transfer"] != "not_detected" {
			t.Errorf("transfer controlEfficacy = %q, want not_detected", byLeg["transfer"])
		}
		if byLeg["encryption"] != "no_evidence" {
			t.Errorf("encryption controlEfficacy = %q, want no_evidence", byLeg["encryption"])
		}
	})
}

func TestGetDoubleExtortionCorrelation_NoRelevantEvidence_Returns200InsufficientEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nonexistent-run/double-extortion-correlation", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", "nonexistent-run")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetDoubleExtortionCorrelation(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 -- a run with zero relevant evidence is not an error", rec.Code)
		}
		var got struct {
			Classification string `json:"classification"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Classification != "insufficient_behavior_evidence" {
			t.Fatalf("Classification = %q, want insufficient_behavior_evidence", got.Classification)
		}
	})
}
