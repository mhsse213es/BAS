package initiatives

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
)

func TestComputeProgress_CountsEveryJobState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		jobsStore := jobs.NewStore(pool)

		it, err := store.Create(ctx, "progress-mixed", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		mkJob := func(agentID string) jobs.Job {
			j, err := jobsStore.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{agentID})
			if err != nil {
				t.Fatalf("CreateBatch: %v", err)
			}
			if _, err := jobsStore.SetJobInitiative(ctx, j.ID, it.ID); err != nil {
				t.Fatalf("SetJobInitiative: %v", err)
			}
			return j
		}

		mkJob("cp-a1") // stays requested (no state change)
		running := mkJob("cp-a2")
		if err := jobsStore.SetJobState(ctx, running.ID, jobs.JobStateRunning); err != nil {
			t.Fatalf("SetJobState(running): %v", err)
		}
		completed := mkJob("cp-a3")
		if err := jobsStore.SetJobState(ctx, completed.ID, jobs.JobStateCompleted); err != nil {
			t.Fatalf("SetJobState(completed): %v", err)
		}
		failed := mkJob("cp-a4")
		if err := jobsStore.SetJobState(ctx, failed.ID, jobs.JobStateFailed); err != nil {
			t.Fatalf("SetJobState(failed): %v", err)
		}

		progress, err := store.ComputeProgress(ctx, it.ID)
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		want := Progress{Total: 4, Requested: 1, Running: 1, Completed: 1, Failed: 1, PercentComplete: 50}
		if progress != want {
			t.Errorf("progress = %+v, want %+v", progress, want)
		}
	})
}

func TestComputeProgress_NoSuchInitiative_ReturnsZeroValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		progress, err := store.ComputeProgress(context.Background(), "no-such-initiative-id")
		if err != nil {
			t.Fatalf("ComputeProgress: %v", err)
		}
		if progress.Total != 0 || progress.PercentComplete != 0 {
			t.Errorf("progress = %+v, want all-zero for an initiative with no jobs", progress)
		}
	})
}
