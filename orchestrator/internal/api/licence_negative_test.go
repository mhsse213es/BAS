package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/scenario"
)

// A Core licence sending a direct API call to run an Advanced scenario is refused before any agent or
// database work starts. The refusal is 403, and the response says the scenario is not licensed.
func TestRunScenario_CoreLicenceRefusesAdvancedScenario_DirectCall(t *testing.T) {
	eng := scenario.NewEngine(filepath.Join("..", "..", "..", "scenarios"))
	if err := eng.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	core, err := license.TierProducts(license.TierCore)
	if err != nil {
		t.Fatal(err)
	}
	eng.SetLicence(func(p license.ProductLine) bool { return core[p] })
	h := &Handler{engine: eng}

	router := chi.NewRouter()
	router.Post("/api/scenarios/{id}/run", h.RunScenario)

	for _, id := range []string{"dlp-exfiltration-smtp", "apt29-kill-chain", "akira-kill-chain"} {
		req := httptest.NewRequest(http.MethodPost, "/api/scenarios/"+id+"/run",
			strings.NewReader(`{"agentId":"agent-1"}`))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403 (body %q)", id, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not included in this licence") {
			t.Fatalf("%s: unexpected body %q", id, rec.Body.String())
		}
	}
}
