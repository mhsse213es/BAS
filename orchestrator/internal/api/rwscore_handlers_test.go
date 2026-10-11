package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestGetRunRWScore_ResponseUsesCamelCaseLikeEveryOtherAPIResponse(t *testing.T) {
	// Found during final review: every other API response struct in this
	// codebase (e.g. VariantCoverageReport{RunID string `json:"runId"`})
	// uses camelCase JSON keys. rwscore.RunScore/DimensionScore had no json
	// tags at all, so this endpoint alone would have serialized as
	// PascalCase ("Rating", "GateTriggered") -- an inconsistency the next
	// sub-project's UI would hit directly when consuming this endpoint
	// alongside every camelCase one.
	//
	// json.Unmarshal matches field names case-insensitively, so decoding
	// into a camelCase-tagged struct would wrongly pass against either
	// wire format -- this checks the raw response bytes directly instead,
	// which is the only way to actually distinguish them.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		runID := "rwscore-camelcase-run"
		seedRunRow(t, pool, runID, "ransomware-drill", "agent-rwscore-2", "running")

		results := []rwevidence.CapabilityResult{
			{Capability: rwevidence.CapabilityPrevention, TechniqueID: "T1490", Verdict: "PASS"},
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

		body := rec.Body.String()
		for _, key := range []string{`"overall"`, `"rating"`, `"gateTriggered"`, `"criticalFailures"`, `"dimensions"`} {
			if !strings.Contains(body, key) {
				t.Fatalf("response body missing camelCase key %s; got: %s", key, body)
			}
		}
		for _, wrongKey := range []string{`"Overall"`, `"Rating"`, `"GateTriggered"`} {
			if strings.Contains(body, wrongKey) {
				t.Fatalf("response body contains PascalCase key %s, inconsistent with every other API response; got: %s", wrongKey, body)
			}
		}
	})
}
