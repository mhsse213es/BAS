package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatidentity"
)

// registryEngine is the existing package-level test helper from
// content_gate_test.go (same package: api) — it returns a *scenario.Engine
// with a *contentregistry.Registry already attached via e.AttachRegistry.
// No e.Load() call is needed here: GetThreatExposure only calls
// h.engine.Registry(), it never touches loaded scenario files.

func TestGetThreatExposure_ReturnsActiveThreats(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		idStore := threatidentity.NewStore(pool)
		if _, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: "APT-handler-exposure"}, threatidentity.ProfileFields{}); err != nil {
			t.Fatal(err)
		}

		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}

		req := httptest.NewRequest(http.MethodGet, "/api/threats/exposure", nil)
		w := httptest.NewRecorder()
		h.GetThreatExposure(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "APT-handler-exposure") {
			t.Fatalf("expected the seeded threat's title in the response, got: %s", w.Body.String())
		}
	})
}

func TestGetThreatExposure_LimitQueryParamRespected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}

		req := httptest.NewRequest(http.MethodGet, "/api/threats/exposure?limit=99999", nil)
		w := httptest.NewRecorder()
		h.GetThreatExposure(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		// As with GetCoverageAnalytics/GetGenerationAttempts's existing tests, the
		// real cap is exercised inside threatcontent.ListActiveThreatExposure itself
		// (Task 1); this just confirms the handler doesn't error on an absurd value.
	})
}

func TestGetThreatExposure_NoRegistryReturns503(t *testing.T) {
	h := &Handler{engine: &scenario.Engine{}}
	req := httptest.NewRequest(http.MethodGet, "/api/threats/exposure", nil)
	w := httptest.NewRecorder()
	h.GetThreatExposure(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no registry is attached, got %d: %s", w.Code, w.Body.String())
	}
}
