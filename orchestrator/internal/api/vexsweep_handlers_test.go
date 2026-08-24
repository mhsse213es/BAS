package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/vexsweep"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testVexSweepDispatcher builds a throwaway Dispatcher purely to satisfy
// WithVexSweep's constructor requirement -- these handler tests exercise
// HTTP endpoints directly and never tick the dispatcher.
func testVexSweepDispatcher(store *vexsweep.Store) *vexsweep.Dispatcher {
	return vexsweep.NewDispatcher(store, func(ctx context.Context, variantRunID string) (string, error) {
		return "running", nil
	})
}

func TestCreateVexSweep_RejectsWhenNoARTStoreLoaded(t *testing.T) {
	// No WithART/WithContentSeed called -- artStore is nil, so the handler
	// cannot resolve a technique list and must fail cleanly, not panic.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(vexsweep.NewStore(pool), testVexSweepDispatcher(vexsweep.NewStore(pool)))
		userID := seedUser(t, pool, "sweep-create-user", "password123", "admin", true)
		body, _ := json.Marshal(map[string]string{"agentId": "agent-1", "mode": "sequential"})
		req := authedRequest(t, http.MethodPost, "/api/vex/sweeps", bytes.NewReader(body), auth.RoleAdmin, userID)
		rec := callAuthed(h.CreateVexSweep, req)
		if rec.Code != http.StatusInternalServerError && rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want a server error (ART store not loaded), body: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateVexSweep_RejectsWhenAgentHasRunningVariantRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO variant_runs (id, agent_id, technique_id, scenario_run_id, total_variants, status)
			 VALUES ('vr-conflict-1', 'agent-conflict', 'T1059.001', 'sr-conflict-1', 33, 'running')`); err != nil {
			t.Fatalf("seed running variant_run: %v", err)
		}
		// A real ART store is required -- CreateVexSweep checks h.artStore
		// before the conflict check, so a nil store would 503 first and the
		// conflict path would never be exercised.
		if _, err := pool.Exec(ctx,
			`INSERT INTO techniques (technique_id, name, tactic) VALUES ('T1059.001','PowerShell','execution')
			 ON CONFLICT (technique_id) DO NOTHING`); err != nil {
			t.Fatalf("seed technique: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command)
			 VALUES ('T1059.001', 0, 'conflict-test-step', 'powershell', 'Get-Process')`); err != nil {
			t.Fatalf("seed art_atomic_tests: %v", err)
		}
		artStore, err := scenario.NewARTStoreFromDB(ctx, pool, nil)
		if err != nil {
			t.Fatalf("NewARTStoreFromDB: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(vexsweep.NewStore(pool), testVexSweepDispatcher(vexsweep.NewStore(pool))).WithART(artStore)
		userID := seedUser(t, pool, "sweep-conflict-user", "password123", "admin", true)
		body, _ := json.Marshal(map[string]string{"agentId": "agent-conflict", "mode": "sequential"})
		req := authedRequest(t, http.MethodPost, "/api/vex/sweeps", bytes.NewReader(body), auth.RoleAdmin, userID)
		rec := callAuthed(h.CreateVexSweep, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409, body: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateVexSweep_CombinesARTAndCalderaTechniques(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO techniques (technique_id, name, tactic) VALUES ('T1059.001','PowerShell','execution')
			 ON CONFLICT (technique_id) DO NOTHING`); err != nil {
			t.Fatalf("seed technique: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command)
			 VALUES ('T1059.001', 0, 'combined-test-step', 'powershell', 'Get-Process')`); err != nil {
			t.Fatalf("seed art_atomic_tests: %v", err)
		}
		artStore, err := scenario.NewARTStoreFromDB(ctx, pool, nil)
		if err != nil {
			t.Fatalf("NewARTStoreFromDB: %v", err)
		}
		calderaStore := scenario.NewCalderaStoreFromSteps(map[string][]scenario.ScenarioStep{
			"T1059.003": {{
				TaskID:      scenario.TaskID("T1059.003", "combined-caldera-ability"),
				TechniqueID: "T1059.003",
				Name:        "combined-caldera-ability",
				Framework:   "caldera",
				Executor:    "powershell",
				Command:     "whoami",
				TimeoutSec:  60,
			}},
		})

		store := vexsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret).
			WithVexSweep(store, testVexSweepDispatcher(store)).
			WithART(artStore).
			WithCalderaStore(calderaStore)
		userID := seedUser(t, pool, "sweep-combined-user", "password123", "admin", true)
		body, _ := json.Marshal(map[string]string{"agentId": "agent-combined", "mode": "sequential"})
		req := authedRequest(t, http.MethodPost, "/api/vex/sweeps", bytes.NewReader(body), auth.RoleAdmin, userID)
		rec := callAuthed(h.CreateVexSweep, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body: %s", rec.Code, rec.Body.String())
		}
		var got struct {
			ID         string   `json:"id"`
			Techniques []string `json:"techniques"`
			BaseTypes  []string `json:"baseTypes"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if len(got.Techniques) != len(got.BaseTypes) {
			t.Fatalf("techniques/baseTypes length mismatch: %d vs %d", len(got.Techniques), len(got.BaseTypes))
		}
		foundART, foundCaldera := false, false
		for i, tech := range got.Techniques {
			if tech == "T1059.001" && got.BaseTypes[i] == "art" {
				foundART = true
			}
			if tech == "T1059.003" && got.BaseTypes[i] == "caldera" {
				foundCaldera = true
			}
		}
		if !foundART {
			t.Errorf("expected T1059.001 dispatched with baseType=art, got techniques=%v baseTypes=%v", got.Techniques, got.BaseTypes)
		}
		if !foundCaldera {
			t.Errorf("expected T1059.003 dispatched with baseType=caldera, got techniques=%v baseTypes=%v", got.Techniques, got.BaseTypes)
		}
	})
}

func TestGetActiveVexSweep_404WhenNoneRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(vexsweep.NewStore(pool), testVexSweepDispatcher(vexsweep.NewStore(pool)))
		userID := seedUser(t, pool, "sweep-active-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/active?agentId=agent-no-sweep", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.GetActiveVexSweep, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestGetActiveVexSweep_ReturnsRunningSweepWithLiveCompletedVariants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-live-progress')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-live-progress", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{2, 12}, TotalVariants: 14,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-live-1", "sr-live-1"); err != nil {
			t.Fatalf("AdvanceToNext: %v", err)
		}
		// Simulate 1 of the 2 in-flight technique's variants having finished
		// -- steps_done is the column run_events ingestion (SubmitRunEvents)
		// increments live, per completed step, as an agent executes. Unlike
		// results (a jsonb blob the agent only ever writes once, atomically,
		// with the run's COMPLETE final snapshot -- see submitScenarioResult's
		// "REPLACE, never append" comment), steps_done is the only column
		// that actually reflects in-flight progress before the run finishes.
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, steps_total, steps_done)
			 VALUES ('sr-live-1', '__variant__t1059.001', 'agent-live-progress', 'test', 'running', 2, 1)`); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
		userID := seedUser(t, pool, "sweep-live-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/active?agentId=agent-live-progress", nil, auth.RoleViewer, userID)
		rec := callAuthed(h.GetActiveVexSweep, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		var got struct {
			CompletedVariants int `json:"completedVariants"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// 0 (no prior technique finished yet) + 1 (in-flight technique's
		// one recorded step result) = 1.
		if got.CompletedVariants != 1 {
			t.Fatalf("completedVariants = %d, want 1 (live, includes in-flight technique's finished steps)", got.CompletedVariants)
		}
	})
}

func TestCancelVexSweep_StopsSweepAndCancelsCurrentRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-cancel')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-cancel", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.AdvanceToNext(ctx, sw.ID, 0, 0, "vr-cancel-1", "sr-cancel-1"); err != nil {
			t.Fatalf("AdvanceToNext: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total)
			 VALUES ('sr-cancel-1', '__variant__t1059.001', 'agent-cancel', 'test', 'running', '[]', 33)`); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
		userID := seedUser(t, pool, "sweep-cancel-user", "password123", "admin", true)
		req := authedRequest(t, http.MethodPost, "/api/vex/sweeps/"+sw.ID+"/cancel", nil, auth.RoleAdmin, userID)
		req = withURLParam(req, "id", sw.ID)
		rec := callAuthed(h.CancelVexSweep, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		got, err := store.Get(ctx, sw.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Status != "stopped" {
			t.Errorf("Status = %q, want %q", got.Status, "stopped")
		}
		var runStatus string
		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'sr-cancel-1'`).Scan(&runStatus); err != nil {
			t.Fatalf("query scenario_runs: %v", err)
		}
		if runStatus != "partial" {
			t.Errorf("scenario_runs.status = %q, want %q (agent offline in this test, so cancel marks it partial immediately)", runStatus, "partial")
		}
	})
}

// TestCancelVexSweep_SucceedsWhenAgentDisconnected mirrors
// TestCancelEMSweep_SucceedsWhenAgentDisconnected -- see there for the full
// rationale (the "no option of Stop after the agent disconnected" report).
func TestCancelVexSweep_SucceedsWhenAgentDisconnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-cancel-disc')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-cancel-disc", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{33}, TotalVariants: 33,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.MarkDisconnected(ctx, sw.ID, 0); err != nil {
			t.Fatalf("MarkDisconnected: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
		userID := seedUser(t, pool, "sweep-cancel-disc-user", "password123", "admin", true)
		req := authedRequest(t, http.MethodPost, "/api/vex/sweeps/"+sw.ID+"/cancel", nil, auth.RoleAdmin, userID)
		req = withURLParam(req, "id", sw.ID)
		rec := callAuthed(h.CancelVexSweep, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (agent_disconnected must still be cancellable), body: %s", rec.Code, rec.Body.String())
		}

		got, err := store.Get(ctx, sw.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Status != "stopped" {
			t.Errorf("Status = %q, want %q", got.Status, "stopped")
		}
	})
}

func TestGetVexSweepRuns_ReturnsOnlyTaggedRunsPlusSweepSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-sweep-runs')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-sweep-runs", Mode: "sequential",
			Techniques: []string{"T1059.001", "T1059.003"}, TechniqueVariantCounts: []int{1, 1}, TotalVariants: 2,
		})
		if err != nil {
			t.Fatalf("Create sweep: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total, sweep_id)
			 VALUES ('sr-a', 'sc-x', 'agent-sweep-runs', 'technique A', 'completed', '[]', 1, $1)`, sw.ID); err != nil {
			t.Fatalf("seed sr-a: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total, sweep_id)
			 VALUES ('sr-b', 'sc-x', 'agent-sweep-runs', 'technique B', 'completed', '[]', 1, $1)`, sw.ID); err != nil {
			t.Fatalf("seed sr-b: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total)
			 VALUES ('sr-unrelated', 'sc-x', 'agent-sweep-runs', 'unrelated run', 'completed', '[]', 1)`); err != nil {
			t.Fatalf("seed sr-unrelated: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
		userID := seedUser(t, pool, "sweep-runs-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/"+sw.ID+"/runs", nil, auth.RoleViewer, userID)
		req = withURLParam(req, "id", sw.ID)
		rec := callAuthed(h.GetVexSweepRuns, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		var got struct {
			Sweep struct {
				ID string `json:"id"`
			} `json:"sweep"`
			Runs []struct {
				ID string `json:"id"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Sweep.ID != sw.ID {
			t.Errorf("sweep.id = %q, want %q", got.Sweep.ID, sw.ID)
		}
		if len(got.Runs) != 2 {
			t.Fatalf("len(runs) = %d, want 2 (sr-unrelated must be excluded)", len(got.Runs))
		}
		gotIDs := map[string]bool{got.Runs[0].ID: true, got.Runs[1].ID: true}
		if !gotIDs["sr-a"] || !gotIDs["sr-b"] {
			t.Errorf("runs = %v, want [sr-a, sr-b]", gotIDs)
		}
	})
}

func TestGetVexSweepRuns_404ForUnknownSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := vexsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret).WithVexSweep(store, testVexSweepDispatcher(store))
		userID := seedUser(t, pool, "sweep-runs-404-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/does-not-exist/runs", nil, auth.RoleViewer, userID)
		req = withURLParam(req, "id", "does-not-exist")
		rec := callAuthed(h.GetVexSweepRuns, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body: %s", rec.Code, rec.Body.String())
		}
	})
}

func TestGetSweepReport_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id) VALUES ('agent-sweep-report-api')`); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		store := vexsweep.NewStore(pool)
		sw, err := store.Create(ctx, vexsweep.Sweep{
			AgentID: "agent-sweep-report-api", Mode: "sequential",
			Techniques: []string{"T1059.001"}, TechniqueVariantCounts: []int{1}, TotalVariants: 1,
		})
		if err != nil {
			t.Fatalf("Create sweep: %v", err)
		}
		results := []models.SimulationResult{
			{ID: "r1", Technique: models.AttackTechnique{ID: "T1059.001", Name: "PowerShell", Tactic: "execution"}, Result: models.ResultFail, Severity: "High"},
		}
		resultsJSON, _ := json.Marshal(results)
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, sweep_id)
			 VALUES ('sr-report-api', '__variant__T1059.001', 'agent-sweep-report-api', 'T1059.001 variants', 'completed', $1, $2)`,
			resultsJSON, sw.ID); err != nil {
			t.Fatalf("seed scenario_runs: %v", err)
		}

		h := New(pool, ws.NewHub(), nil, testJWTSecret).
			WithVexSweep(store, testVexSweepDispatcher(store)).
			WithReporting(reporting.NewEngine(pool))
		userID := seedUser(t, pool, "sweep-report-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/"+sw.ID+"/report", nil, auth.RoleViewer, userID)
		req = withURLParam(req, "id", sw.ID)
		rec := callAuthed(h.GetSweepReport, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("content-type = %q", ct)
		}
		if !strings.Contains(rec.Body.String(), "T1059.001") {
			t.Fatal("HTML report missing seeded technique T1059.001")
		}
	})
}

func TestGetSweepReport_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := vexsweep.NewStore(pool)
		h := New(pool, ws.NewHub(), nil, testJWTSecret).
			WithVexSweep(store, testVexSweepDispatcher(store)).
			WithReporting(reporting.NewEngine(pool))
		userID := seedUser(t, pool, "sweep-report-404-user", "password123", "viewer", true)
		req := authedRequest(t, http.MethodGet, "/api/vex/sweeps/nope/report", nil, auth.RoleViewer, userID)
		req = withURLParam(req, "id", "nope")
		rec := callAuthed(h.GetSweepReport, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}
