package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// Needs the Docker-backed test database (TestMain of this package): written and
// compiled here, run on a Docker-capable host.
func TestDBSimRunCountForRunCountsGradedRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureDBSimRunSchema(ctx, pool); err != nil {
			t.Fatal(err)
		}
		if n, err := db.CountDBSimRunsForRun(ctx, pool, "bas-dbsim-run:count-none"); err != nil || n != 0 {
			t.Fatalf("unknown run: n=%d err=%v, want 0", n, err)
		}
		if _, err := db.SaveDBSimRun(ctx, pool, dbsimRun("bas-dbsim-run:count-1", "PASS")); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SaveDBSimRun(ctx, pool, dbsimRun("bas-dbsim-run:count-1", "PASS")); !errors.Is(err, db.ErrDBSimRunDuplicate) {
			t.Fatalf("duplicate save err = %v, want ErrDBSimRunDuplicate", err)
		}
		if n, err := db.CountDBSimRunsForRun(ctx, pool, "bas-dbsim-run:count-1"); err != nil || n != 1 {
			t.Fatalf("after one save and one duplicate: n=%d err=%v, want 1", n, err)
		}
	})
}
