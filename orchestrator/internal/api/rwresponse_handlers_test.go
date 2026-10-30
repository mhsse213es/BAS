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
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func rwResponseTestDeps() rwevidence.StepDependencies {
	return rwevidence.StepDependencies{
		Prevention:     rwevidence.ProviderPrevention{Provider: &controlval.FakeProvider{}},
		Recovery:       &rwevidence.FakeRecoveryObserver{},
		Containment:    &rwevidence.FakeContainmentObserver{},
		Detection:      &rwevidence.FakeDetectionLookup{},
		DataProtection: &rwevidence.FakeDataProtectionLookup{},
	}
}

func TestGetDetectionResponseEffectiveness_T1490AndT1486_ReportsAllThreeDimensionsHonestly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "effectiveness-test-run"

		t1490In := rwevidence.StepInput{RunID: runID, Action: "vss-delete", TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion (T1490)", CheckResult: "fail", Details: "FAIL: shadow copies deleted"}
		t1490Results := rwevidence.EvaluateStep(t1490In, rwResponseTestDeps())
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "vss-delete", t1490Results); err != nil {
			t.Fatalf("seed T1490: %v", err)
		}

		t1486In := rwevidence.StepInput{RunID: runID, Action: "encrypt", TechniqueID: "T1486", StepName: "Mass File Encryption (T1486)", CheckResult: "fail", Details: "FAIL: files encrypted"}
		t1486Results := rwevidence.EvaluateStep(t1486In, rwResponseTestDeps())
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "encrypt", t1486Results); err != nil {
			t.Fatalf("seed T1486: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/detection-response-effectiveness", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", runID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetDetectionResponseEffectiveness(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var got struct {
			Rows []struct {
				TechniqueID     string         `json:"techniqueId"`
				Detection       map[string]any `json:"detection"`
				Containment     map[string]any `json:"containment"`
				Recovery        map[string]any `json:"recovery"`
				ResponseLatency string         `json:"responseLatency"`
			} `json:"rows"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.Rows) != 2 {
			t.Fatalf("got %d rows, want 2 (T1490 and T1486)", len(got.Rows))
		}
		for _, row := range got.Rows {
			if row.ResponseLatency != "not_establishable" {
				t.Errorf("technique %s: responseLatency = %q, want not_establishable", row.TechniqueID, row.ResponseLatency)
			}
			if row.Detection == nil || row.Containment == nil || row.Recovery == nil {
				t.Errorf("technique %s: expected all three dimensions present (every EvaluateStep attempt writes all 5 capability rows), got detection=%v containment=%v recovery=%v", row.TechniqueID, row.Detection, row.Containment, row.Recovery)
			}
		}
	})
}

func TestGetDetectionResponseEffectiveness_NoEvidence_Returns200EmptyRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/nonexistent-run/detection-response-effectiveness", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", "nonexistent-run")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetDetectionResponseEffectiveness(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 -- a run with zero relevant evidence is not an error", rec.Code)
		}
		var got struct {
			Rows []any `json:"rows"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(got.Rows) != 0 {
			t.Fatalf("got %d rows, want 0", len(got.Rows))
		}
	})
}
