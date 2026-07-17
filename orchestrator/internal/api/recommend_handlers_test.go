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

func recommendHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

type recommendResp struct {
	Techniques []struct {
		TechniqueID   string `json:"techniqueId"`
		Score         int    `json:"score"`
		CoverageState string `json:"coverageState"`
	} `json:"techniques"`
	SuggestedScenario struct {
		ID            string   `json:"id"`
		ARTTechniques []string `json:"artTechniques"`
	} `json:"suggestedScenario"`
	HasData bool `json:"hasData"`
}

func TestGetRecommendedSimulations_EmptyContent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := recommendHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetRecommendedSimulations(rec, httptest.NewRequest(http.MethodGet, "/api/recommend/simulations", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out recommendResp
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(out.Techniques) != 0 || out.HasData {
			t.Errorf("out = %+v, want no techniques and hasData=false on unseeded content", out)
		}
	})
}

func TestGetRecommendedSimulations_RanksAndClampsLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		for _, tech := range [][3]string{
			{"T1003.001", "LSASS Memory", "credential-access"},
			{"T1055", "Process Injection", "defense-evasion"},
			{"T1217", "Browser Bookmark Discovery", "discovery"},
		} {
			mustExecAPI(t, pool, `INSERT INTO techniques (technique_id, name, tactic) VALUES ($1, $2, $3)`,
				tech[0], tech[1], tech[2])
			mustExecAPI(t, pool, `
				INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command)
				VALUES ($1, 1, 'atomic', 'powershell', 'whoami')`, tech[0])
		}

		h := recommendHandler(t, pool)

		// limit=2 is respected.
		rec := httptest.NewRecorder()
		h.GetRecommendedSimulations(rec, httptest.NewRequest(http.MethodGet, "/api/recommend/simulations?limit=2", nil))
		var out recommendResp
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out.Techniques) != 2 {
			t.Fatalf("limit=2 returned %d techniques, want 2", len(out.Techniques))
		}
		if len(out.SuggestedScenario.ARTTechniques) != 2 {
			t.Errorf("suggestedScenario carried %d techniques, want 2", len(out.SuggestedScenario.ARTTechniques))
		}
		if !out.HasData {
			t.Error("hasData = false with seeded content, want true")
		}

		// An out-of-range limit falls back to the default rather than erroring.
		rec2 := httptest.NewRecorder()
		h.GetRecommendedSimulations(rec2, httptest.NewRequest(http.MethodGet, "/api/recommend/simulations?limit=99999", nil))
		if rec2.Code != http.StatusOK {
			t.Fatalf("limit=99999: status = %d, want 200", rec2.Code)
		}
		var out2 recommendResp
		json.Unmarshal(rec2.Body.Bytes(), &out2)
		if len(out2.Techniques) != 3 {
			t.Errorf("limit=99999 returned %d techniques, want all 3 (clamped, not errored)", len(out2.Techniques))
		}
	})
}
