package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetAttackPathCorrelation_NilRules_ReturnsEmptyCorrelationNotError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetAttackPathCorrelation(rec, httptest.NewRequest(http.MethodGet, "/api/attackpath/correlation", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 even with h.rules nil", rec.Code)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		score, ok := out["detectionCoverageScore"].(float64)
		if !ok || score != 100 {
			t.Fatalf("detectionCoverageScore = %v, want 100 with no attack-path collections", out["detectionCoverageScore"])
		}
	})
}

func TestGetAttackPathCorrelation_WithRules_Returns200(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "").WithRuleLibrary(rulelib.NewEngine())
		rec := httptest.NewRecorder()
		h.GetAttackPathCorrelation(rec, httptest.NewRequest(http.MethodGet, "/api/attackpath/correlation", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, key := range []string{"summary", "detectionCoverageScore", "paths", "chokePoints", "gaps", "statistics"} {
			if _, ok := out[key]; !ok {
				t.Fatalf("response missing key %q: %v", key, out)
			}
		}
	})
}
