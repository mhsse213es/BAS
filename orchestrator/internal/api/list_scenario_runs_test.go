package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/vexsweep"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestListScenarioRuns_NoFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "list-run-1", "sc-list", "agent-list-1", "completed")
		seedRunRow(t, pool, "list-run-2", "sc-list", "agent-list-2", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 2 {
			t.Fatalf("runs = %d, want 2", len(runs))
		}
	})
}

func TestListScenarioRuns_Filters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		seedRunRow(t, pool, "filt-run-a", "sc-filt-1", "agent-filt-1", "completed")
		seedRunRow(t, pool, "filt-run-b", "sc-filt-2", "agent-filt-1", "completed")
		seedRunRow(t, pool, "filt-run-c", "sc-filt-1", "agent-filt-2", "completed")

		cases := []struct {
			name       string
			agentID    string
			scenarioID string
			wantRunIDs []string
		}{
			{"by agentId", "agent-filt-1", "", []string{"filt-run-a", "filt-run-b"}},
			{"by scenarioId", "", "sc-filt-1", []string{"filt-run-a", "filt-run-c"}},
			{"by both", "agent-filt-1", "sc-filt-1", []string{"filt-run-a"}},
			{"matches neither", "no-such-agent", "no-such-scenario", nil},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				url := "/api/scenarios/runs?agentId=" + tc.agentID + "&scenarioId=" + tc.scenarioID
				rec := httptest.NewRecorder()
				h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, url, nil))
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
				}
				var raw []any
				if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
					t.Fatalf("decode (want a JSON array, possibly empty, never null): %v — body = %s", err, rec.Body.String())
				}
				var runs []map[string]any
				for _, item := range raw {
					runs = append(runs, item.(map[string]any))
				}
				if len(runs) != len(tc.wantRunIDs) {
					t.Fatalf("got %d runs, want %d (%+v)", len(runs), len(tc.wantRunIDs), runs)
				}
				got := map[string]bool{}
				for _, r := range runs {
					got[r["id"].(string)] = true
				}
				for _, id := range tc.wantRunIDs {
					if !got[id] {
						t.Fatalf("expected run %q in response, runs = %+v", id, runs)
					}
				}
			})
		}
	})
}

func TestListScenarioRuns_OrderedByStartedAtDesc(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-order','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		base := time.Now().Add(-1 * time.Hour)
		for i, id := range []string{"order-run-oldest", "order-run-middle", "order-run-newest"} {
			if _, err := pool.Exec(context.Background(),
				`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
				 VALUES ($1,'sc-order','agent-order','x','completed',$2)`,
				id, base.Add(time.Duration(i)*time.Minute)); err != nil {
				t.Fatalf("seed run %s: %v", id, err)
			}
		}

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-order", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 3 {
			t.Fatalf("runs = %d, want 3", len(runs))
		}
		wantOrder := []string{"order-run-newest", "order-run-middle", "order-run-oldest"}
		for i, want := range wantOrder {
			if runs[i]["id"] != want {
				t.Fatalf("runs[%d].id = %v, want %s (DESC by started_at)", i, runs[i]["id"], want)
			}
		}
	})
}

func TestListScenarioRuns_LimitOneHundred(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-limit','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		base := time.Now().Add(-200 * time.Minute)
		for i := 0; i < 105; i++ {
			if _, err := pool.Exec(context.Background(),
				`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at)
				 VALUES ($1,'sc-limit','agent-limit','x','completed',$2)`,
				fmt.Sprintf("limit-run-%03d", i), base.Add(time.Duration(i)*time.Minute)); err != nil {
				t.Fatalf("seed run %d: %v", i, err)
			}
		}

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-limit", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 100 {
			t.Fatalf("runs = %d, want exactly 100", len(runs))
		}
		if runs[0]["id"] != "limit-run-104" {
			t.Fatalf("runs[0].id = %v, want the most recent (limit-run-104)", runs[0]["id"])
		}
	})
}

func TestListScenarioRuns_DetectedTechsProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-det','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		detJSON := []byte(`{"techniques":[{"techniqueId":"T1059","verdict":"detected"}]}`)
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, detection_summary)
			 VALUES ('det-run','sc-det','agent-det','x','completed',NOW(),$1)`, detJSON); err != nil {
			t.Fatalf("seed run with detection_summary: %v", err)
		}
		seedRunRow(t, pool, "no-det-run", "sc-det", "agent-det", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-det", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var withDet, withoutDet map[string]any
		for _, r := range runs {
			if r["id"] == "det-run" {
				withDet = r
			}
			if r["id"] == "no-det-run" {
				withoutDet = r
			}
		}
		if withDet == nil || withoutDet == nil {
			t.Fatalf("expected both seeded runs in response, got %+v", runs)
		}
		dt, ok := withDet["detectedTechs"].(map[string]any)
		if !ok || dt["T1059"] != true {
			t.Fatalf("det-run detectedTechs = %v, want {T1059:true}", withDet["detectedTechs"])
		}
		if _, present := withoutDet["detectedTechs"]; present {
			t.Fatalf("no-det-run unexpectedly has detectedTechs: %v", withoutDet["detectedTechs"])
		}
	})
}

func TestListScenarioRuns_ProgressProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-prog','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, steps_total, steps_done)
			 VALUES ('prog-run','sc-prog','agent-prog','x','running',NOW(),5,2)`); err != nil {
			t.Fatalf("seed run with progress: %v", err)
		}
		seedRunRow(t, pool, "no-prog-run", "sc-prog", "agent-prog", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-prog", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var withProg, withoutProg map[string]any
		for _, r := range runs {
			if r["id"] == "prog-run" {
				withProg = r
			}
			if r["id"] == "no-prog-run" {
				withoutProg = r
			}
		}
		if withProg == nil || withoutProg == nil {
			t.Fatalf("expected both seeded runs, got %+v", runs)
		}
		if withProg["progress"] == nil {
			t.Fatal("prog-run: expected a populated progress field")
		}
		if withoutProg["progress"] != nil {
			t.Fatalf("no-prog-run: expected omitted progress, got %v", withoutProg["progress"])
		}
	})
}

func TestListScenarioRuns_ScoreProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-score-proj','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		scoreJSON, _ := json.Marshal(models.Score{
			Trend: "Improving", PreventionScore: 75.5,
			TacticBreakdown: map[string]models.TacticScore{}, CriticalFailures: []models.CriticalFailure{},
		})
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, score)
			 VALUES ('score-proj-run','sc-score-proj','agent-score-proj','x','completed',NOW(),$1)`, scoreJSON); err != nil {
			t.Fatalf("seed run with score: %v", err)
		}
		seedRunRow(t, pool, "null-score-run", "sc-score-proj", "agent-score-proj", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-score-proj", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var withScore, withoutScore map[string]any
		for _, r := range runs {
			if r["id"] == "score-proj-run" {
				withScore = r
			}
			if r["id"] == "null-score-run" {
				withoutScore = r
			}
		}
		if withScore == nil || withoutScore == nil {
			t.Fatalf("expected both seeded runs, got %+v", runs)
		}
		sc, ok := withScore["score"].(map[string]any)
		if !ok || sc["trend"] != "Improving" {
			t.Fatalf("score-proj-run score = %v, want trend=Improving", withScore["score"])
		}
		if withoutScore["score"] != nil {
			t.Fatalf("null-score-run: expected nil score, got %v", withoutScore["score"])
		}
	})
}

func TestListScenarioRuns_RevertedProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-reverted-proj','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		revertedJSON, _ := json.Marshal([]string{
			`registry removed: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil`,
			"schtask deleted: EvilTask",
		})
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, reverted)
			 VALUES ('reverted-proj-run','sc-reverted-proj','agent-reverted-proj','x','completed',NOW(),$1)`, revertedJSON); err != nil {
			t.Fatalf("seed run with reverted: %v", err)
		}
		seedRunRow(t, pool, "null-reverted-run", "sc-reverted-proj", "agent-reverted-proj", "completed")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-reverted-proj", nil))
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var withReverted, withoutReverted map[string]any
		for _, r := range runs {
			if r["id"] == "reverted-proj-run" {
				withReverted = r
			}
			if r["id"] == "null-reverted-run" {
				withoutReverted = r
			}
		}
		if withReverted == nil || withoutReverted == nil {
			t.Fatalf("expected both seeded runs, got %+v", runs)
		}
		rv, ok := withReverted["reverted"].([]any)
		if !ok || len(rv) != 2 {
			t.Fatalf("reverted-proj-run reverted = %v, want 2 items", withReverted["reverted"])
		}
		if rv[0] != `registry removed: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil` {
			t.Fatalf("reverted[0] = %v, want the registry-removal string", rv[0])
		}
		if _, present := withoutReverted["reverted"]; present {
			t.Fatalf("null-reverted-run: expected omitted reverted field, got %v", withoutReverted["reverted"])
		}
	})
}

func TestListScenarioRuns_MalformedResultsJSON_DegradesGracefully(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		if _, err := pool.Exec(context.Background(), `INSERT INTO agents (agent_id, hostname, state) VALUES ('agent-malformed','h','active')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		// Valid JSON, wrong shape for []models.SimulationResult (object instead of array).
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, results)
			 VALUES ('malformed-run','sc-malformed','agent-malformed','x','completed',NOW(),'{"not":"an array"}'::jsonb)`); err != nil {
			t.Fatalf("seed run with malformed results: %v", err)
		}

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-malformed", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (must degrade gracefully, not 500), body = %s", rec.Code, rec.Body.String())
		}
		var runs []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &runs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(runs) != 1 || runs[0]["id"] != "malformed-run" {
			t.Fatalf("runs = %+v, want exactly one run with id=malformed-run present despite the malformed results blob", runs)
		}
	})
}

func TestListScenarioRuns_DBError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		closedPool, err := pgxpool.New(context.Background(), sharedDB.Pool.Config().ConnString())
		if err != nil {
			t.Fatalf("new pool: %v", err)
		}
		closedPool.Close()
		h := New(closedPool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")

		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestListScenarioRuns_ExposesSweepIdOnlyForTaggedRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-list-sweep')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-list-sweep", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1,
		})
		if err != nil {
			t.Fatalf("Create sweep: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total, sweep_id)
			 VALUES ('sr-tagged', 'sc-x', 'agent-list-sweep', 'tagged run', 'completed', '[]', 1, $1)`,
			sw.ID); err != nil {
			t.Fatalf("seed tagged run: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total)
			 VALUES ('sr-untagged', 'sc-x', 'agent-list-sweep', 'untagged run', 'completed', '[]', 1)`); err != nil {
			t.Fatalf("seed untagged run: %v", err)
		}

		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.ListScenarioRuns(rec, httptest.NewRequest(http.MethodGet, "/api/scenarios/runs?agentId=agent-list-sweep", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		var got []struct {
			ID      string  `json:"id"`
			SweepID *string `json:"sweepId"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		byID := map[string]*string{}
		for _, r := range got {
			byID[r.ID] = r.SweepID
		}
		if byID["sr-tagged"] == nil || *byID["sr-tagged"] != sw.ID {
			t.Errorf("sr-tagged sweepId = %v, want %q", byID["sr-tagged"], sw.ID)
		}
		if byID["sr-untagged"] != nil {
			t.Errorf("sr-untagged sweepId = %q, want nil (not sweep-dispatched)", *byID["sr-untagged"])
		}
	})
}
