package initiatives

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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
