package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEnsureSegmentationSchema_IdempotentAndCreatesTables(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	tdb.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		for i := range 2 {
			if err := db.EnsureSegmentationSchema(ctx, pool); err != nil {
				t.Fatalf("run %d: %v", i+1, err)
			}
		}
		for _, table := range []string{"segmentation_runs", "segmentation_probe_results"} {
			var exists bool
			if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, table).Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if !exists {
				t.Fatalf("table %s was not created", table)
			}
		}
	})
}
