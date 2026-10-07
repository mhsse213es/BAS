package exercise

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CountActiveSteps is what the active-steps gauge is sampled from: running
// and waiting steps count; completed, failed and cancelled ones do not.
func TestCountActiveSteps_RunningAndWaitingOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		ctx := context.Background()
		execID := seedExecution(t, store)

		statuses := map[string]StepStatus{
			"s-run":    StepRunning,
			"s-wait":   StepWaiting,
			"s-done":   StepCompleted,
			"s-fail":   StepFailed,
			"s-cancel": StepCancelled,
		}
		for id, st := range statuses {
			se := &StepExecution{ExecutionID: execID, StepID: id, StepType: StepTypeAgentTask, Status: st}
			if err := store.UpsertStepExecution(ctx, se); err != nil {
				t.Fatalf("UpsertStepExecution %s: %v", id, err)
			}
		}
		got, err := store.CountActiveSteps(ctx)
		if err != nil {
			t.Fatalf("CountActiveSteps: %v", err)
		}
		if got != 2 {
			t.Fatalf("CountActiveSteps = %d, want 2 (running + waiting)", got)
		}

		// A finishing step leaves the count.
		se := &StepExecution{ExecutionID: execID, StepID: "s-run", StepType: StepTypeAgentTask, Status: StepCompleted}
		if err := store.UpsertStepExecution(ctx, se); err != nil {
			t.Fatalf("finish s-run: %v", err)
		}
		if got, _ := store.CountActiveSteps(ctx); got != 1 {
			t.Fatalf("after finish CountActiveSteps = %d, want 1", got)
		}
	})
}
