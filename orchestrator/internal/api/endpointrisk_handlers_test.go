package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetAgentRisk_UnknownAgent404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "no-such-agent-er")
		w := httptest.NewRecorder()
		h.GetAgentRisk(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", w.Code)
		}
	})
}

func TestGetAgentRisk_KnownAgent_ReturnsAllCategories(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-h2-a1', 'ER-H2-HOST')`)
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-h2-run', 'er-h2-scn', 'ER H2 Run', 'er-h2-a1', 'completed', $1::jsonb, NOW())`,
			`[{"technique":{"id":"T1566","name":"Phishing","tactic":"initial-access"},"result":"pass","executedAt":"`+time.Now().UTC().Format(time.RFC3339)+`"}]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "er-h2-a1")
		w := httptest.NewRecorder()
		h.GetAgentRisk(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got endpointrisk.EndpointHealth
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got.Categories) != 9 {
			t.Errorf("got %d categories, want 9 (7 real-or-uncollected + 2 not-yet-collected)", len(got.Categories))
		}
	})
}

func TestGetAgentRisk_PatchAndApplicationRisk_CollectedFromRealChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-h3-a1', 'ER-H3-HOST')`)
		now := time.Now().UTC()
		mustExecAPI(t, pool, `
			INSERT INTO scenario_runs (id, scenario_id, name, agent_id, status, results, started_at)
			VALUES ('er-h3-run', 'windows-patch-posture', 'H3 Run', 'er-h3-a1', 'completed', $1::jsonb, NOW())`,
			`[
				{"checkId":"windows-last-patch-age","result":"pass","executedAt":"`+now.Format(time.RFC3339)+`"},
				{"checkId":"windows-installed-software","result":"pass","rawOutput":"Adobe Flash Player|32.0.0.465","executedAt":"`+now.Format(time.RFC3339)+`"}
			]`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		tx, err := endpointrisk.NewTaxonomy()
		if err != nil {
			t.Fatalf("NewTaxonomy: %v", err)
		}
		h.endpointRiskTaxonomy = tx
		cat, err := endpointrisk.NewCatalog()
		if err != nil {
			t.Fatalf("NewCatalog: %v", err)
		}
		h.eolCatalog = cat

		req := withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "agentId", "er-h3-a1")
		w := httptest.NewRecorder()
		h.GetAgentRisk(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var got endpointrisk.EndpointHealth
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		var patchCat, appRiskCat *endpointrisk.CategoryScore
		for i := range got.Categories {
			switch got.Categories[i].ID {
			case endpointrisk.CategoryPatchManagement:
				patchCat = &got.Categories[i]
			case endpointrisk.CategoryApplicationRisk:
				appRiskCat = &got.Categories[i]
			}
		}
		if patchCat == nil || !patchCat.Collected {
			t.Errorf("Patch Management = %+v, want Collected=true", patchCat)
		}
		if appRiskCat == nil || !appRiskCat.Collected || len(appRiskCat.Findings) != 1 {
			t.Errorf("Application Risk = %+v, want Collected=true with 1 finding (Flash)", appRiskCat)
		}
	})
}

func TestGetAgentRiskSummary_MixedOSFleet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-mix-win', 'ER-MIX-WIN', 'windows')`)
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname, os_version) VALUES ('er-mix-lin', 'ER-MIX-LIN', 'linux')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/agents/risk-summary", nil)
		w := httptest.NewRecorder()
		h.GetAgentRiskSummary(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var body struct {
			Agents []AgentRiskRow `json:"agents"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		seen := map[string]bool{}
		for _, a := range body.Agents {
			seen[a.AgentID] = true
		}
		if !seen["er-mix-win"] || !seen["er-mix-lin"] {
			t.Error("expected both Windows and Linux agents in the fleet risk summary")
		}
	})
}

func TestGetAgentRiskSummary_IncludesKnownAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('er-h4-a1', 'ER-H4-HOST')`)

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		req := httptest.NewRequest(http.MethodGet, "/api/agents/risk-summary", nil)
		w := httptest.NewRecorder()
		h.GetAgentRiskSummary(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
		}
		var body struct {
			Agents []AgentRiskRow `json:"agents"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		found := false
		for _, a := range body.Agents {
			if a.AgentID == "er-h4-a1" {
				found = true
			}
		}
		if !found {
			t.Error("expected er-h4-a1 in the fleet risk summary")
		}
	})
}
