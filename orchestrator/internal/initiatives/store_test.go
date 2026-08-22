package initiatives

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func TestCreateGet_RoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		created, err := store.Create(ctx, "Q3 Patch Compliance", "quarterly patch push", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if created.ID == "" {
			t.Fatal("Create: expected a generated ID")
		}
		if created.State != StateActive {
			t.Errorf("State = %q, want %q", created.State, StateActive)
		}

		got, err := store.Get(ctx, created.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Name != "Q3 Patch Compliance" || got.Description != "quarterly patch push" || got.CreatedBy != "user-1" {
			t.Errorf("got = %+v, want the values passed to Create", got)
		}
	})
}

func TestList_FiltersByState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		a, err := store.Create(ctx, "list-a", "", "user-1")
		if err != nil {
			t.Fatalf("Create a: %v", err)
		}
		b, err := store.Create(ctx, "list-b", "", "user-1")
		if err != nil {
			t.Fatalf("Create b: %v", err)
		}
		if _, err := store.Close(ctx, b.ID); err != nil {
			t.Fatalf("Close b: %v", err)
		}

		active, err := store.List(ctx, StateActive)
		if err != nil {
			t.Fatalf("List(active): %v", err)
		}
		foundA, foundB := false, false
		for _, it := range active {
			if it.ID == a.ID {
				foundA = true
			}
			if it.ID == b.ID {
				foundB = true
			}
		}
		if !foundA || foundB {
			t.Errorf("List(active) = %+v, want a present and b absent", active)
		}

		all, err := store.List(ctx, "")
		if err != nil {
			t.Fatalf("List(\"\"): %v", err)
		}
		if len(all) < 2 {
			t.Errorf("List(\"\") returned %d rows, want at least 2", len(all))
		}
	})
}

func TestClose_RejectsNonActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		it, err := store.Create(ctx, "close-twice", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := store.Close(ctx, it.ID); err != nil {
			t.Fatalf("first Close: %v", err)
		}
		if _, err := store.Close(ctx, it.ID); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("second Close: err = %v, want ErrInvalidTransition", err)
		}
	})
}

func TestArchive_RequiresClosedFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		it, err := store.Create(ctx, "archive-from-active", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := store.Archive(ctx, it.ID); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("Archive from active: err = %v, want ErrInvalidTransition", err)
		}

		if _, err := store.Close(ctx, it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}
		archived, err := store.Archive(ctx, it.ID)
		if err != nil {
			t.Fatalf("Archive after Close: %v", err)
		}
		if archived.State != StateArchived {
			t.Errorf("State = %q, want %q", archived.State, StateArchived)
		}
		if archived.ArchivedAt == nil {
			t.Error("ArchivedAt is nil, want set")
		}
	})
}

func TestDelete_RequiresArchived(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)

		it, err := store.Create(ctx, "delete-while-active", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := store.Delete(ctx, it.ID); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("Delete(active): err = %v, want ErrInvalidTransition", err)
		}

		if _, err := store.Close(ctx, it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := store.Delete(ctx, it.ID); !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("Delete(closed): err = %v, want ErrInvalidTransition", err)
		}
	})
}

func TestDelete_BlocksWhenJobsAttached(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		jobsStore := jobs.NewStore(pool)

		it, err := store.Create(ctx, "delete-with-job", "", "user-1")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := store.Close(ctx, it.ID); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := store.Archive(ctx, it.ID); err != nil {
			t.Fatalf("Archive: %v", err)
		}

		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		job, err := jobsStore.CreateBatch(ctx, "batch_remediation", payload, "user-1", []string{"del-a1"})
		if err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if _, err := jobsStore.SetJobInitiative(ctx, job.ID, it.ID); err != nil {
			t.Fatalf("SetJobInitiative: %v", err)
		}

		if err := store.Delete(ctx, it.ID); !errors.Is(err, ErrHasJobs) {
			t.Errorf("Delete: err = %v, want ErrHasJobs", err)
		}

		if _, err := jobsStore.SetJobInitiative(ctx, job.ID, ""); err != nil {
			t.Fatalf("detach: %v", err)
		}
		if err := store.Delete(ctx, it.ID); err != nil {
			t.Fatalf("Delete after detach: %v", err)
		}
		if _, err := store.Get(ctx, it.ID); err == nil {
			t.Error("Get after Delete: expected an error (row should be gone), got nil")
		}
	})
}
