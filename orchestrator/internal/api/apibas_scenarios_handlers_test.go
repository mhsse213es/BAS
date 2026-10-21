package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// The collision check must catch an API BAS ID that is also an engine scenario ID, and must pass when
// the two sets are disjoint.
func TestAPIBASIDCollisions(t *testing.T) {
	api := []contract.Scenario{{ID: "API-BAS-AUTHZ-001"}, {ID: "API-BAS-DATA-001"}}

	if got := apiBASIDCollisions([]string{"apt29-kill-chain", "em-02-attack-behavioral-depth"}, api); len(got) != 0 {
		t.Fatalf("disjoint sets reported collisions: %v", got)
	}
	got := apiBASIDCollisions([]string{"API-BAS-DATA-001", "apt29-kill-chain"}, api)
	if len(got) != 1 || got[0] != "API-BAS-DATA-001" {
		t.Fatalf("collision not reported exactly: %v", got)
	}
}

// realEngine loads the repository's scenario folder, as the server does.
func realEngine(t *testing.T) *scenario.Engine {
	t.Helper()
	eng := scenario.NewEngine(filepath.Join("..", "..", "..", "scenarios"))
	if err := eng.Load(); err != nil {
		t.Fatalf("engine load: %v", err)
	}
	return eng
}

// The listing returns every embedded API BAS definition, tagged apibas and not runnable through the
// engine. None of its IDs appears in the engine's own list.
func TestAPIBASListing_SeparateFromEngine(t *testing.T) {
	eng := realEngine(t)
	h := New(nil, ws.NewHub(), eng, "")
	rec := httptest.NewRecorder()
	h.ListAPIBASScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/api-bas", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	var items []apiBASListItem
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) < 100 {
		t.Fatalf("listed %d API BAS definitions, want the full catalog", len(items))
	}
	engineIDs := map[string]bool{}
	for _, sc := range eng.List() {
		engineIDs[sc.ID] = true
	}
	for _, it := range items {
		if it.Source != "apibas" || it.RunnableHere {
			t.Fatalf("%s: source %q runnable %v, want apibas and not runnable here", it.ID, it.Source, it.RunnableHere)
		}
		if engineIDs[it.ID] {
			t.Fatalf("%s appears in the engine list", it.ID)
		}
	}
}

// If an API BAS ID collides with a loaded engine scenario, nothing is listed and the collision is reported.
func TestAPIBASListing_CollisionListsNothing(t *testing.T) {
	orig := loadAPIBASCatalog
	defer func() { loadAPIBASCatalog = orig }()
	loadAPIBASCatalog = func() ([]contract.Scenario, error) {
		return []contract.Scenario{{ID: "API-BAS-AUTHZ-001"}, {ID: "windows-backup-posture"}}, nil
	}
	h := New(nil, ws.NewHub(), realEngine(t), "")
	rec := httptest.NewRecorder()
	h.ListAPIBASScenarios(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/api-bas", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("collision: %d %s, want 409", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "windows-backup-posture") || strings.Contains(body, `"source"`) {
		t.Fatalf("collision body = %s, want the ID reported and no items", body)
	}
}
