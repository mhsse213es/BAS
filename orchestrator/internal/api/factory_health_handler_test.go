package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetFactoryHealth_ReturnsNoDataMetricsOnFreshDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetFactoryHealth(rec, httptest.NewRequest(http.MethodGet, "/api/analytics/factory-health", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		dup, ok := got["duplicateGenerationRate"].(map[string]any)
		if !ok || dup["state"] != "no_data" {
			t.Fatalf("duplicateGenerationRate = %v, want state=no_data", got["duplicateGenerationRate"])
		}
	})
}
