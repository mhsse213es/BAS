package api

import (
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestIntelligenceCampaigns_Empty_ReturnsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")

		req := httptest.NewRequest("GET", "/api/intelligence/campaigns", nil)
		w := httptest.NewRecorder()
		h.IntelligenceCampaigns(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
	})
}

func TestIntelligenceMalware_Empty_ReturnsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		engine := scenario.NewEngine(t.TempDir())
		if err := engine.Load(); err != nil {
			t.Fatalf("engine.Load: %v", err)
		}
		h := New(pool, ws.NewHub(), engine, "")

		req := httptest.NewRequest("GET", "/api/intelligence/malware", nil)
		w := httptest.NewRecorder()
		h.IntelligenceMalware(w, req)

		if w.Code != 200 {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
	})
}
