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
	"github.com/audspect/bas/internal/rwefficacy"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func getEfficacy(t *testing.T, pool *pgxpool.Pool, runID string) rwefficacy.Report {
	t.Helper()
	h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/ransomware-efficacy", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("runId", runID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()
	h.GetRansomwareEfficacy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var rep rwefficacy.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return rep
}

func TestGetRansomwareEfficacy_NoEvidence_IsUnprovenNeverEvidenced(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		rep := getEfficacy(t, pool, "efficacy-empty")
		if rep.Overall != rwefficacy.OverallUnproven || len(rep.Attempts) != 0 {
			t.Fatalf("got %+v", rep)
		}
	})
}

func TestGetRansomwareEfficacy_RealEvaluateStepRows_AreNeverEvidencedWithFakes(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "efficacy-fakes"
		in := rwevidence.StepInput{RunID: runID, Action: "vss-delete", TechniqueID: "T1490", StepName: "VSS Shadow Copy Deletion (T1490)", CheckResult: "fail"}
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "vss-delete", rwevidence.EvaluateStep(in, rwResponseTestDeps())); err != nil {
			t.Fatal(err)
		}
		rep := getEfficacy(t, pool, runID)
		if rep.Overall == rwefficacy.OverallEvidenced {
			t.Fatalf("fake observers must not read as evidenced: %+v", rep)
		}
		if len(rep.Attempts) != 1 || rep.Attempts[0].Verdicts["recovery"] == "" {
			t.Fatalf("attempts %+v", rep.Attempts)
		}
		_ = controlval.VerdictPass
	})
}
