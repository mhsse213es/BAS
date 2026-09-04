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

func TestExecutionAttemptsSchema_SkipConsistencyConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()

		// A skipped row WITHOUT skip_reason must be rejected.
		_, err := pool.Exec(ctx,
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, created_at, decision_at)
			 VALUES ('exercise', 'step', 'exec-1', 'attempt-bad-1', 'skipped', NOW(), NOW())`)
		if err == nil {
			t.Error("expected constraint violation: skipped row without skip_reason")
		}

		// A skipped row WITHOUT decision_at must be rejected.
		_, err = pool.Exec(ctx,
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, skip_reason, created_at)
			 VALUES ('exercise', 'step', 'exec-1', 'attempt-bad-2', 'skipped', 'condition_false', NOW())`)
		if err == nil {
			t.Error("expected constraint violation: skipped row without decision_at")
		}

		// A non-skipped row WITH skip_reason set must be rejected.
		_, err = pool.Exec(ctx,
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, skip_reason, created_at)
			 VALUES ('exercise', 'step', 'exec-1', 'attempt-bad-3', 'completed', 'condition_false', NOW())`)
		if err == nil {
			t.Error("expected constraint violation: completed row with skip_reason set")
		}

		// A valid skipped row must succeed.
		_, err = pool.Exec(ctx,
			`INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, skip_reason, created_at, decision_at)
			 VALUES ('exercise', 'step', 'exec-1', 'attempt-good-1', 'skipped', 'condition_false', NOW(), NOW())`)
		if err != nil {
			t.Errorf("valid skipped row should succeed: %v", err)
		}
	})
}

func TestExecutionAttemptsSchema_IdempotentOnRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		insert := `INSERT INTO execution_attempts (source, granularity, source_execution_id, source_attempt_id, status, created_at)
		            VALUES ('art', 'run', 'exec-idem', 'attempt-idem-1', 'pending', NOW())
		            ON CONFLICT (source, source_attempt_id) DO NOTHING`

		if _, err := pool.Exec(ctx, insert); err != nil {
			t.Fatalf("first insert: %v", err)
		}
		if _, err := pool.Exec(ctx, insert); err != nil {
			t.Fatalf("second insert (retry) should not error: %v", err)
		}

		var count int
		if err := pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM execution_attempts WHERE source_attempt_id = 'attempt-idem-1'`,
		).Scan(&count); err != nil {
			t.Fatalf("count query: %v", err)
		}
		if count != 1 {
			t.Errorf("row count = %d, want 1 (retry must not create a duplicate)", count)
		}
	})
}
