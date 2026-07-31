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

func TestGetEndpointPosture_EmptyFleet_ReturnsZeroSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetEndpointPosture(rec, httptest.NewRequest(http.MethodGet, "/api/analytics/endpoint-posture", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got struct {
			TotalAgents       int `json:"totalAgents"`
			CurrentlyIsolated int `json:"currentlyIsolated"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if got.TotalAgents != 0 || got.CurrentlyIsolated != 0 {
			t.Errorf("got %+v, want all zero on an empty fleet", got)
		}
	})
}
