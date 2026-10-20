package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestCoverageProof_WithoutDatabaseIs503(t *testing.T) {
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	req := httptest.NewRequest(http.MethodPost, "/api/killchain/coverage/proofs", strings.NewReader(`{"scenarioId":"x"}`))
	rec := httptest.NewRecorder()
	h.RecordKillChainProof(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// A scenario outside the catalog cannot carry proof, whatever the references say.
func TestCoverageProof_UncataloguedScenarioIsRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := httptest.NewRequest(http.MethodPost, "/api/killchain/coverage/proofs",
			strings.NewReader(`{"scenarioId":"not-in-catalog","fixtureTestId":"fx"}`))
		rec := httptest.NewRecorder()
		h.RecordKillChainProof(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not in the catalog") {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCoverageProof_UnknownFieldIsRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := httptest.NewRequest(http.MethodPost, "/api/killchain/coverage/proofs",
			strings.NewReader(`{"scenarioId":"x","level":"live-validated"}`))
		rec := httptest.NewRecorder()
		h.RecordKillChainProof(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("a caller-declared level must be refused: status = %d", rec.Code)
		}
	})
}

func TestCoverage_ReportIsEmptyWithNoProofs(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := httptest.NewRequest(http.MethodGet, "/api/killchain/coverage", nil)
		rec := httptest.NewRecorder()
		h.GetKillChainCoverage(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"total":0`) {
			t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(strings.ToLower(rec.Body.String()), "percent") {
			t.Fatalf("report must not contain a combined percentage")
		}
	})
}
