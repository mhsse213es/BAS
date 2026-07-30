package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/audspect/bas/internal/auth"
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
		// Simulate 1 of the 2 in-flight technique's variants having a
		// recorded result already -- results is a jsonb array on
		// scenario_runs, one entry per completed step.
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, results, steps_total)
			 VALUES ('sr-live-1', '__variant__t1059.001', 'agent-live-progress', 'test', 'running', '[{"id":"step1"}]', 2)`); err != nil {
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
