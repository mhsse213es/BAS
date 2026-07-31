package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGetIOCAnalytics_ReturnsAllFourLists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedIOC(t, pool, "command_line", "cmd-analytics", "agent-1", "sc-1")

		h := &Handler{db: pool}
		rec := httptest.NewRecorder()
		h.GetIOCAnalytics(rec, httptest.NewRequest(http.MethodGet, "/api/analytics/iocs", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, key := range []string{"mostDetected", "highestBypassRate", "frequentlyReused", "longestSurviving"} {
			if _, ok := got[key]; !ok {
				t.Errorf("response missing key %q: %+v", key, got)
			}
		}
	})
}
