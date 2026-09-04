package exercise

import (
	"context"
	"testing"

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
