package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetRunRWScore_NonexistentRunReturns404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/does-not-exist/rw-score", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", "does-not-exist")
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetRunRWScore(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetRunRWScore_RealRunReturnsScoreMatchingPersistedRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "rwscore-endpoint-run"
		seedRunRow(t, pool, runID, "ransomware-drill", "agent-rwscore", "running")

		results := []rwevidence.CapabilityResult{
			{Capability: rwevidence.CapabilityPrevention, TechniqueID: "T1490", Verdict: "PASS"},
			{Capability: rwevidence.CapabilityRecovery, TechniqueID: "T1490", Verdict: "FAIL"},
		}
		if err := db.WriteRWCapabilityResults(context.Background(), pool, runID, "action-1", results); err != nil {
			t.Fatalf("seed: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/scenarios/runs/"+runID+"/rw-score", nil)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("runId", runID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()

		h.GetRunRWScore(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var got struct {
			Rating        string `json:"Rating"`
			GateTriggered bool   `json:"GateTriggered"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !got.GateTriggered {
			t.Fatal("GateTriggered = false, want true -- the seeded Recovery FAIL must trip the gate")
		}
		if got.Rating != "at_risk" {
			t.Fatalf("Rating = %q, want at_risk", got.Rating)
		}
	})
}
