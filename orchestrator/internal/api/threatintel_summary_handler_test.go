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

type threatIntelSummaryResponse struct {
	TopActors            []map[string]any `json:"topActors"`
	KEVExposedTechniques int              `json:"kevExposedTechniques"`
	TotalKEVCVEs         int              `json:"totalKevCves"`
}

func TestGetThreatIntelSummary_NoEngineConfigured_ReturnsEmptyActors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetThreatIntelSummary(rec, httptest.NewRequest(http.MethodGet, "/api/analytics/threat-intel-summary", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got threatIntelSummaryResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if len(got.TopActors) != 0 {
			t.Errorf("TopActors = %+v, want empty -- New() doesn't wire threatPriorityEngine by default in this test helper", got.TopActors)
		}
	})
}
