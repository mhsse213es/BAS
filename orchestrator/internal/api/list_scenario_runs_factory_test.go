package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The factory validation lab's runs are an internal quality loop, not customer assessments. The runs list leaves
// them out unless asked, so Live Runs, reports and the figures computed from the list stay about the customer.

func listRunIDs(t *testing.T, h *Handler, url string) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, url, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status = %d, body = %s", url, rec.Code, rec.Body.String())
	}
	var runs []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	ids := []string{}
	for _, r := range runs {
		ids = append(ids, r["id"].(string))
	}
	sort.Strings(ids)
	return ids
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestListScenarioRuns_HidesFactoryValidationRunsByDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "fl-customer", "sc-fl", "agent-fl-customer", "completed")
		seedRunRow(t, pool, "fl-lab-1", "sc-fl-intel", "agent-fl-lab", "completed")
		seedRunRow(t, pool, "fl-lab-2", "sc-fl", "agent-fl-lab", "completed")
		if _, err := pool.Exec(context.Background(),
			`UPDATE scenario_runs SET execution_kind = 'factory_validation' WHERE id IN ('fl-lab-1','fl-lab-2')`); err != nil {
			t.Fatal(err)
		}

		if got := listRunIDs(t, h, "/api/scenarios/runs"); !equalIDs(got, []string{"fl-customer"}) {
			t.Errorf("default list = %v, want only the customer run", got)
		}
		if got := listRunIDs(t, h, "/api/scenarios/runs?scenarioId=sc-fl"); !equalIDs(got, []string{"fl-customer"}) {
			t.Errorf("by scenario = %v: a factory run of the same scenario must stay out", got)
		}
		if got := listRunIDs(t, h, "/api/scenarios/runs?agentId=agent-fl-lab"); !equalIDs(got, []string{"fl-lab-1", "fl-lab-2"}) {
			t.Errorf("asking for the lab agent = %v, want its runs (its drawer must not look empty)", got)
		}
		if got := listRunIDs(t, h, "/api/scenarios/runs?includeFactory=1"); !equalIDs(got, []string{"fl-customer", "fl-lab-1", "fl-lab-2"}) {
			t.Errorf("includeFactory=1 = %v, want every run", got)
		}
	})
}
