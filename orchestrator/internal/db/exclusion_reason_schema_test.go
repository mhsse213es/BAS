package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

// TestExclusionReasonSchema checks the Gap 3 migration against the shared
// Postgres 16 test database: the reason_code column and both constraints exist,
// they are NOT VALID (legacy rows are not checked), and running the schema
// again is a no-op.
func TestExclusionReasonSchema(t *testing.T) {
	ctx := context.Background()
	pool := sharedDB.Pool
	if err := db.EnsureContentRegistrySchema(ctx, pool); err != nil {
		t.Fatalf("ensure registry schema (second run): %v", err)
	}

	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.columns
		 WHERE table_name = 'content_version_events' AND column_name = 'reason_code'`,
	).Scan(&n); err != nil || n != 1 {
		t.Fatalf("reason_code column missing: n=%d err=%v", n, err)
	}

	for _, name := range []string{"cve_reason_code_check", "cve_rejected_needs_reason"} {
		var validated bool
		if err := pool.QueryRow(ctx,
			`SELECT convalidated FROM pg_constraint WHERE conname = $1`, name,
		).Scan(&validated); err != nil {
			t.Fatalf("constraint %s missing: %v", name, err)
		}
		if validated {
			t.Errorf("constraint %s must be NOT VALID so legacy rows are not rejected", name)
		}
	}
}
