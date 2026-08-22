package jobs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestList_NilFilterReturnsEverything(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		a, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"list-a1"})
		if err != nil {
			t.Fatalf("CreateBatch a: %v", err)
		}
		b, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"list-a2"})
		if err != nil {
			t.Fatalf("CreateBatch b: %v", err)
		}
		if _, err := store.SetJobInitiative(ctx, b.ID, "init-list-1"); err != nil {
			t.Fatalf("SetJobInitiative: %v", err)
		}

		all, err := store.List(ctx, nil)
		if err != nil {
			t.Fatalf("List(nil): %v", err)
		}
		foundA, foundB := false, false
		for _, j := range all {
			if j.ID == a.ID {
				foundA = true
			}
			if j.ID == b.ID {
				foundB = true
			}
		}
		if !foundA || !foundB {
			t.Errorf("List(nil) missing jobs, foundA=%v foundB=%v", foundA, foundB)
		}
	})
}

func TestList_EmptyStringFilterReturnsOnlyUnassigned(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		unassigned, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"list-b1"})
		if err != nil {
			t.Fatalf("CreateBatch unassigned: %v", err)
		}
		assigned, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"list-b2"})
		if err != nil {
			t.Fatalf("CreateBatch assigned: %v", err)
		}
		if _, err := store.SetJobInitiative(ctx, assigned.ID, "init-list-2"); err != nil {
			t.Fatalf("SetJobInitiative: %v", err)
		}

		empty := ""
		got, err := store.List(ctx, &empty)
		if err != nil {
			t.Fatalf("List(&\"\"): %v", err)
		}
		foundUnassigned, foundAssigned := false, false
		for _, j := range got {
			if j.ID == unassigned.ID {
				foundUnassigned = true
			}
			if j.ID == assigned.ID {
				foundAssigned = true
			}
		}
		if !foundUnassigned {
			t.Error("List(&\"\") missing the unassigned job")
		}
		if foundAssigned {
			t.Error("List(&\"\") incorrectly included a job assigned to an initiative")
		}
	})
}

func TestList_SpecificInitiativeIDFiltersToThatInitiative(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		mine, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"list-c1"})
		if err != nil {
			t.Fatalf("CreateBatch mine: %v", err)
		}
		if _, err := store.SetJobInitiative(ctx, mine.ID, "init-list-3"); err != nil {
			t.Fatalf("SetJobInitiative: %v", err)
		}
		other, err := store.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"list-c2"})
		if err != nil {
			t.Fatalf("CreateBatch other: %v", err)
		}
		if _, err := store.SetJobInitiative(ctx, other.ID, "init-list-4"); err != nil {
			t.Fatalf("SetJobInitiative: %v", err)
		}

		filter := "init-list-3"
		got, err := store.List(ctx, &filter)
		if err != nil {
			t.Fatalf("List(&filter): %v", err)
		}
		if len(got) != 1 || got[0].ID != mine.ID {
			t.Errorf("List(&%q) = %+v, want exactly [mine]", filter, got)
		}
	})
}
