package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReapNeverStartedRuns_MarksZeroProgressRunPastGuardAsFailed proves the
// core case: a 'running' scenario_run that's been sitting at steps_total=0
// well past neverStartedGuard gets reaped to 'failed'. This is the run that
// silently never reached the agent (see liveness.go's doc comment on why
// SendToAgent's success return doesn't guarantee delivery).
func TestReapNeverStartedRuns_MarksZeroProgressRunPastGuardAsFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, eng := minimalPostureScenario(t, "watchdog-never-started")
		h := New(pool, ws.NewHub(), eng, "")
		agentID := "watchdog-agent"
		seedActiveAgent(t, pool, agentID, "Windows")

		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, steps_total)
			 VALUES ('run-never-started', $1, $2, 'x', 'running', NOW() - interval '5 minutes', 0)`,
			sc.ID, agentID); err != nil {
			t.Fatalf("seed never-started run: %v", err)
		}

		if err := h.ReapNeverStartedRuns(ctx); err != nil {
			t.Fatalf("ReapNeverStartedRuns: %v", err)
		}

		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'run-never-started'`).Scan(&status); err != nil {
			t.Fatalf("query status: %v", err)
		}
		if status != "failed" {
			t.Fatalf("status = %q, want failed", status)
		}
	})
}

// TestReapNeverStartedRuns_LeavesRecentZeroProgressRunAlone proves a run
// that's only just started (well within neverStartedGuard) is left running
// -- the watchdog must not race a genuinely-starting run.
func TestReapNeverStartedRuns_LeavesRecentZeroProgressRunAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, eng := minimalPostureScenario(t, "watchdog-fresh")
		h := New(pool, ws.NewHub(), eng, "")
		agentID := "watchdog-agent-fresh"
		seedActiveAgent(t, pool, agentID, "Windows")

		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, steps_total)
			 VALUES ('run-just-started', $1, $2, 'x', 'running', NOW(), 0)`,
			sc.ID, agentID); err != nil {
			t.Fatalf("seed fresh run: %v", err)
		}

		if err := h.ReapNeverStartedRuns(ctx); err != nil {
			t.Fatalf("ReapNeverStartedRuns: %v", err)
		}

		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'run-just-started'`).Scan(&status); err != nil {
			t.Fatalf("query status: %v", err)
		}
		if status != "running" {
			t.Fatalf("status = %q, want running (must not reap a run still inside the guard window)", status)
		}
	})
}

// TestReapNeverStartedRuns_LeavesProgressingRunAlone proves a run that has
// genuinely started (steps_total > 0, real progress reported) is never
// touched, no matter how old -- the watchdog only targets zero-progress
// dispatches, not slow-but-real ones.
func TestReapNeverStartedRuns_LeavesProgressingRunAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		sc, eng := minimalPostureScenario(t, "watchdog-progressing")
		h := New(pool, ws.NewHub(), eng, "")
		agentID := "watchdog-agent-progressing"
		seedActiveAgent(t, pool, agentID, "Windows")

		ctx := context.Background()
		if _, err := pool.Exec(ctx,
			`INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, steps_total)
			 VALUES ('run-progressing', $1, $2, 'x', 'running', NOW() - interval '1 hour', 314)`,
			sc.ID, agentID); err != nil {
			t.Fatalf("seed progressing run: %v", err)
		}

		if err := h.ReapNeverStartedRuns(ctx); err != nil {
			t.Fatalf("ReapNeverStartedRuns: %v", err)
		}

		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'run-progressing'`).Scan(&status); err != nil {
			t.Fatalf("query status: %v", err)
		}
		if status != "running" {
			t.Fatalf("status = %q, want running (a run with real progress must never be reaped)", status)
		}
	})
}
