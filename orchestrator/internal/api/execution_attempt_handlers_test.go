package api

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDispatchRun_CreatesExecutionAttemptRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		agentID := "agent-ea-dispatch"
		seedActiveAgent(t, pool, agentID, "Linux")
		fake := startFakeAgent(t, h.hub, agentID)
		defer fake.Disconnect(t)

		sc, _ := minimalLiveScenario(t, "int-ea-dispatch")
		ctx := context.Background()
		runID, skipReason, err := h.dispatchRun(ctx, sc, agentID, dispatchOpts{Mode: "telemetry", ConfirmLive: true})
		if err != nil || skipReason != "" {
			t.Fatalf("dispatchRun failed: runID=%s skipReason=%s err=%v", runID, skipReason, err)
		}

		var source, granularity, status, sourceAttemptID string
		if err := pool.QueryRow(ctx,
			`SELECT source, granularity, status, source_attempt_id FROM execution_attempts WHERE source_execution_id = $1`,
			runID,
		).Scan(&source, &granularity, &status, &sourceAttemptID); err != nil {
			t.Fatalf("query execution_attempts: %v", err)
		}
		if granularity != "run" {
			t.Errorf("granularity = %q, want run", granularity)
		}
		if status != "dispatched" {
			t.Errorf("status = %q, want dispatched (dispatch succeeded)", status)
		}
		if sourceAttemptID != runID {
			t.Errorf("source_attempt_id = %q, want %q (same as run ID)", sourceAttemptID, runID)
		}
	})
}

func TestSubmitScenarioResult_CompletesExecutionAttempt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		runID := "run-ea-complete"
		seedRunRow(t, pool, runID, "sc-ea-complete", "agent-ea-complete", "running")
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, created_at, dispatch_sent_at)
			 VALUES ('art', 'run', $1, $1, 'dispatched', NOW(), NOW())`, runID); err != nil {
			t.Fatalf("seed execution_attempt: %v", err)
		}

		submitResultOK(t, h, scenario.RawRunResult{
			RunID: runID, ScenarioID: "sc-ea-complete", AgentID: "agent-ea-complete",
			Results: []scenario.ExecResult{{TaskID: "t0", ExitCode: 0, Stdout: "PASS"}},
		})

		var status string
		if err := pool.QueryRow(context.Background(),
			`SELECT status FROM execution_attempts WHERE source_attempt_id = $1`, runID,
		).Scan(&status); err != nil {
			t.Fatalf("query execution_attempts: %v", err)
		}
		if status != "completed" {
			t.Errorf("status = %q, want completed", status)
		}
	})
}
