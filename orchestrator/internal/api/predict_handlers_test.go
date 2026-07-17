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

func predictHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

type predictResp struct {
	Forecast struct {
		Direction   string `json:"direction"`
		HasForecast bool   `json:"hasForecast"`
	} `json:"forecast"`
	Exposure struct {
		OpenCount int  `json:"openCount"`
		HasData   bool `json:"hasData"`
	} `json:"exposure"`
}

func TestGetPredictRisk_EmptyFleet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := predictHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetPredictRisk(rec, httptest.NewRequest(http.MethodGet, "/api/predict/risk", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		var got predictResp
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
		}
		if got.Forecast.Direction != "unknown" {
			t.Errorf("Forecast.Direction = %q, want unknown", got.Forecast.Direction)
		}
		if got.Forecast.HasForecast {
			t.Error("HasForecast = true on empty fleet, want false")
		}
		if got.Exposure.HasData {
			t.Error("Exposure.HasData = true on empty fleet, want false")
		}
	})
}
