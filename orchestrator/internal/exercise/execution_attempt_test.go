package exercise

import (
	"context"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestUpsertExecutionAttempt_InsertsRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)

		se := &StepExecution{ExecutionID: execID, StepID: "step-1", StepType: StepTypeAgentTask, Status: StepRunning}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("UpsertStepExecution: %v", err)
		}
		if err := store.UpsertExecutionAttempt(ctx, se); err != nil {
			t.Fatalf("UpsertExecutionAttempt: %v", err)
		}

		var status string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM execution_attempts WHERE source_attempt_id = $1`, se.ID,
		).Scan(&status); err != nil {
			t.Fatalf("query execution_attempts: %v", err)
		}
		if status != "running" {
			t.Errorf("status = %q, want running", status)
		}
	})
}

// TestExecutor_ExecutionAttemptReachesTerminalStatus is the regression guard for
// the whole-branch review's Critical finding #1: instrumentation attached only
// to the UpsertStepExecution call sites left every exercise attempt row frozen
// at pending/running, because all terminal transitions go through
// Store.SetStepStatus. This test drives a real Executor (not the store
// directly) through one completing step and one condition-false step, then
// asserts the mirrored rows reached their terminal states.
func TestExecutor_ExecutionAttemptReachesTerminalStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		e.registry.Register(StepTypeNotify, completeHandler(store))
		ex := seedRunningExecution(t, store, e, []PlanStep{
			{ID: "a", Type: StepTypeNotify},
			{ID: "b", Type: StepTypeNotify, DependsOn: []string{"a"}, Condition: "never"},
		})
		ctx := context.Background()
		_ = e.advance(ctx, ex) // "a" dispatched → handler completes it
		_ = e.advance(ctx, ex) // "b" evaluated: condition false → skipped

		aStep, _ := store.GetStepExecByStepID(ctx, ex.ID, "a")
		bStep, _ := store.GetStepExecByStepID(ctx, ex.ID, "b")
		if aStep == nil || bStep == nil {
			t.Fatalf("expected both step executions to exist, got a=%v b=%v", aStep, bStep)
		}

		// Completed step: terminal status mirrored, no skip metadata.
		var status string
		var skipReason, sourceExecID *string
		var completedAt, decisionAt *time.Time
		if err := pool.QueryRow(ctx,
			`SELECT status, skip_reason, decision_at, completed_at, source_execution_id
			   FROM execution_attempts WHERE source = 'exercise' AND source_attempt_id = $1`,
			aStep.ID,
		).Scan(&status, &skipReason, &decisionAt, &completedAt, &sourceExecID); err != nil {
			t.Fatalf("query completed attempt: %v", err)
		}
		if status != "completed" {
			t.Errorf("completed step attempt status = %q, want completed", status)
		}
		if completedAt == nil {
			t.Error("completed step attempt: completed_at must be populated")
		}
		if skipReason != nil || decisionAt != nil {
			t.Errorf("completed step attempt must not carry skip metadata: skip_reason=%v decision_at=%v", skipReason, decisionAt)
		}
		if sourceExecID == nil || *sourceExecID != ex.ID {
			t.Errorf("source_execution_id = %v, want %q", sourceExecID, ex.ID)
		}

		// Skipped step: status + skip_reason + decision_at all populated.
		if err := pool.QueryRow(ctx,
			`SELECT status, skip_reason, decision_at
			   FROM execution_attempts WHERE source = 'exercise' AND source_attempt_id = $1`,
			bStep.ID,
		).Scan(&status, &skipReason, &decisionAt); err != nil {
			t.Fatalf("query skipped attempt: %v", err)
		}
		if status != "skipped" {
			t.Errorf("skipped step attempt status = %q, want skipped", status)
		}
		if skipReason == nil || *skipReason != string(models.SkipReasonConditionFalse) {
			t.Errorf("skipped step attempt skip_reason = %v, want %q", skipReason, models.SkipReasonConditionFalse)
		}
		if decisionAt == nil {
			t.Error("skipped step attempt: decision_at must be populated")
		}
	})
}

// TestExecutor_AbortMirrorsCancelledAttempt covers the other terminal status
// SetStepStatus produces: AbortExecution cancels every pending/waiting step.
func TestExecutor_AbortMirrorsCancelledAttempt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		e, store := newTestExecutor(pool)
		ex := seedRunningExecution(t, store, e, []PlanStep{{ID: "a", Type: StepTypeNotify}})
		ctx := context.Background()
		if err := e.AbortExecution(ctx, ex.ID); err != nil {
			t.Fatalf("AbortExecution: %v", err)
		}
		aStep, _ := store.GetStepExecByStepID(ctx, ex.ID, "a")
		if aStep == nil {
			t.Fatal("expected step execution to exist")
		}
		var status string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM execution_attempts WHERE source = 'exercise' AND source_attempt_id = $1`,
			aStep.ID,
		).Scan(&status); err != nil {
			t.Fatalf("query cancelled attempt: %v", err)
		}
		if status != "cancelled" {
			t.Errorf("aborted step attempt status = %q, want cancelled", status)
		}
	})
}

func TestExecutionAttemptStatusFromStepStatus(t *testing.T) {
	cases := []struct {
		in   StepStatus
		want models.ExecutionAttemptStatus
	}{
		{StepPending, models.ExecutionAttemptPending},
		{StepRunning, models.ExecutionAttemptRunning},
		{StepCompleted, models.ExecutionAttemptCompleted},
		{StepCancelled, models.ExecutionAttemptCancelled},
		{StepSkipped, models.ExecutionAttemptSkipped},
	}
	for _, c := range cases {
		got := executionAttemptStatusFromStepStatus(c.in)
		if got != c.want {
			t.Errorf("executionAttemptStatusFromStepStatus(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
