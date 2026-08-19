package api

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRunIsStale(t *testing.T) {
	now := time.Now()
	recentStart := now.Add(-1 * time.Minute)

	// Agent alive (fresh heartbeat) + recent run → not stale.
	if runIsStale(recentStart, now.Add(-10*time.Second), now) {
		t.Error("alive agent + recent run must not be stale")
	}
	// Agent offline (stale heartbeat) → stale immediately, even though run is recent.
	if !runIsStale(recentStart, now.Add(-5*time.Minute), now) {
		t.Error("offline agent must make its run stale immediately")
	}
	// Agent alive but run exceeds the hard ceiling → stale (backstop).
	if !runIsStale(now.Add(-3*time.Hour), now.Add(-5*time.Second), now) {
		t.Error("run beyond staleRunGuard ceiling must be stale")
	}
}

func TestReapAbandonedRuns_MarksPartialAfterThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		ctx := context.Background()

		// Agent offline well past abandonedRunGuard (5 min) -- must be reaped.
		seedRunRow(t, pool, "run-abandoned", "sc-reap", "agent-abandoned", "running")
		if _, err := pool.Exec(ctx,
			`UPDATE agents SET last_update = NOW() - interval '10 minutes' WHERE agent_id='agent-abandoned'`); err != nil {
			t.Fatalf("age the agent: %v", err)
		}

		// Agent offline but within the grace window -- must NOT be reaped yet
		// (give the agent's own 90s watchdog + reconnect a fair chance first).
		seedRunRow(t, pool, "run-recent-disc", "sc-reap", "agent-recent-disc", "running")
		if _, err := pool.Exec(ctx,
			`UPDATE agents SET last_update = NOW() - interval '2 minutes' WHERE agent_id='agent-recent-disc'`); err != nil {
			t.Fatalf("age the agent: %v", err)
		}

		// Agent alive, run long-running -- must NOT be reaped (that's
		// staleRunGuard's job, not this reaper's; this reaper only ever
		// fires on the agent-offline condition).
		seedRunRow(t, pool, "run-alive-agent", "sc-reap", "agent-alive-reap", "running")

		if err := h.ReapAbandonedRuns(ctx); err != nil {
			t.Fatalf("ReapAbandonedRuns: %v", err)
		}

		var status string
		var completedAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT status, completed_at FROM scenario_runs WHERE id = 'run-abandoned'`).Scan(&status, &completedAt); err != nil {
			t.Fatalf("query run-abandoned: %v", err)
		}
		if status != "partial" || completedAt == nil {
			t.Fatalf("run-abandoned status = %q completedAt = %v, want partial with completedAt set", status, completedAt)
		}

		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'run-recent-disc'`).Scan(&status); err != nil {
			t.Fatalf("query run-recent-disc: %v", err)
		}
		if status != "running" {
			t.Fatalf("run-recent-disc status = %q, want still running (within grace window)", status)
		}

		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'run-alive-agent'`).Scan(&status); err != nil {
			t.Fatalf("query run-alive-agent: %v", err)
		}
		if status != "running" {
			t.Fatalf("run-alive-agent status = %q, want still running (agent is connected)", status)
		}
	})
}

// TestReapAbandonedRuns_DoesNotConflictWithLateResultSubmission proves the
// race-safety property the spec calls out: SubmitScenarioResult has no
// status guard, so a late submission from an agent that reconnects moments
// after the reaper already marked its run 'partial' must still reconcile
// correctly rather than erroring or being silently dropped. Uses the
// existing submitResultOK helper (submit_scenario_result_test.go) rather
// than constructing the request by hand -- SubmitScenarioResult requires
// agent auth + a result MAC that helper already sets up correctly via
// validSubmitResultReq/rawResultBody.
func TestReapAbandonedRuns_DoesNotConflictWithLateResultSubmission(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		ctx := context.Background()

		seedRunRow(t, pool, "run-late-submit", "sc-reap-race", "agent-late-submit", "running")
		if _, err := pool.Exec(ctx,
			`UPDATE agents SET last_update = NOW() - interval '10 minutes' WHERE agent_id='agent-late-submit'`); err != nil {
			t.Fatalf("age the agent: %v", err)
		}

		if err := h.ReapAbandonedRuns(ctx); err != nil {
			t.Fatalf("ReapAbandonedRuns: %v", err)
		}
		var status string
		if err := pool.QueryRow(ctx, `SELECT status FROM scenario_runs WHERE id = 'run-late-submit'`).Scan(&status); err != nil {
			t.Fatalf("query after reap: %v", err)
		}
		if status != "partial" {
			t.Fatalf("status after reap = %q, want partial", status)
		}

		// submitResultOK itself asserts 200 (t.Fatalf on anything else) --
		// this is the assertion that the late submission still reconciles
		// despite the reaper's earlier UPDATE.
		submitResultOK(t, h, scenario.RawRunResult{
			RunID: "run-late-submit", ScenarioID: "sc-reap-race", AgentID: "agent-late-submit",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS: late"}},
		})
	})
}
