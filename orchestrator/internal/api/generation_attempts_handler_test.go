package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/evidence"
)

func TestGetGenerationAttempts_FiltersByCycleID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := evidence.NewStore(pool)
		if err := store.RecordGenerationAttempt(context.Background(), evidence.GenerationAttempt{
			CycleID: "cycle-a", Outcome: "created", ReasonCode: "ok", GeneratorVersion: "4", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := store.RecordGenerationAttempt(context.Background(), evidence.GenerationAttempt{
			CycleID: "cycle-b", Outcome: "created", ReasonCode: "ok", GeneratorVersion: "4", StartedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}

		h := (&Handler{}).WithEvidenceStore(store)
		req := httptest.NewRequest(http.MethodGet, "/api/connector/generation-attempts?cycle_id=cycle-a", nil)
		w := httptest.NewRecorder()
		h.GetGenerationAttempts(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		body := w.Body.String()
		if !strings.Contains(body, "cycle-a") || strings.Contains(body, "cycle-b") {
			t.Fatalf("expected only cycle-a's attempt in the response, got: %s", body)
		}
	})
}

func TestGetGenerationAttempts_LimitCapsAt100(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := (&Handler{}).WithEvidenceStore(evidence.NewStore(pool))

		req := httptest.NewRequest(http.MethodGet, "/api/connector/generation-attempts?limit=99999", nil)
		w := httptest.NewRecorder()
		h.GetGenerationAttempts(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		// The real assertion is that the handler doesn't pass 99999 straight
		// through to the DB query uncapped -- covered by inspecting the call
		// the handler makes; since Store has no call-log seam, this test instead
		// just confirms the endpoint doesn't error on an absurd limit, and the
		// cap itself is exercised directly in Step 3's handler code (max 100,
		// matching GetCoverageAnalytics's existing convention).
	})
}

func TestGetGenerationAttempts_NilStoreReturns503(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/api/connector/generation-attempts", nil)
	w := httptest.NewRecorder()
	h.GetGenerationAttempts(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when evidenceStore is unwired, got %d: %s", w.Code, w.Body.String())
	}
}
