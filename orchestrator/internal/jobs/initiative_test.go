package jobs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSetJobInitiative_AssignReassignClear(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		job, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"sji-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if job.InitiativeID != "" {
			t.Errorf("InitiativeID = %q on creation, want empty", job.InitiativeID)
		}

		assigned, err := store.SetJobInitiative(ctx, job.ID, "init-1")
		if err != nil {
			t.Fatalf("SetJobInitiative(assign): %v", err)
		}
		if assigned.InitiativeID != "init-1" {
			t.Errorf("InitiativeID = %q, want init-1", assigned.InitiativeID)
		}

		reassigned, err := store.SetJobInitiative(ctx, job.ID, "init-2")
		if err != nil {
			t.Fatalf("SetJobInitiative(reassign): %v", err)
		}
		if reassigned.InitiativeID != "init-2" {
			t.Errorf("InitiativeID = %q, want init-2", reassigned.InitiativeID)
		}

		cleared, err := store.SetJobInitiative(ctx, job.ID, "")
		if err != nil {
			t.Fatalf("SetJobInitiative(clear): %v", err)
		}
		if cleared.InitiativeID != "" {
			t.Errorf("InitiativeID = %q after clear, want empty", cleared.InitiativeID)
		}
	})
}
