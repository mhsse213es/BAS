package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/controlhealth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// TestGetControlHealthSummary_NilMapper503 mirrors the existing
// TestComplianceHandlers_NilMapper503 pattern in report_nil_engine_test.go:
// a Handler built with no WithControlHealth call must 503, not panic.
func TestGetControlHealthSummary_NilMapper503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// No WithControlHealth — controlHealthMapper stays nil.
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/controlhealth/summary", nil)
		w := httptest.NewRecorder()
		h.GetControlHealthSummary(w, req)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", w.Code)
		}
	})
}

func TestGetControlHealthSummary_ReturnsAllCategories(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mapper, err := controlhealth.NewMapper()
		if err != nil {
			t.Fatalf("controlhealth.NewMapper: %v", err)
		}
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithControlHealth(mapper)

		req := httptest.NewRequest(http.MethodGet, "/api/controlhealth/summary", nil)
		w := httptest.NewRecorder()
		h.GetControlHealthSummary(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var body struct {
			Categories []controlhealth.CategoryHealth `json:"categories"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(body.Categories) != 10 {
			t.Errorf("got %d categories, want 10", len(body.Categories))
		}
	})
}
