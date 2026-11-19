package db_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
)

// TestEnsureAppRole_ContentValidationsOutcomeColumnsUpdatable guards the grant
// the validation lab depends on. content_validations is append-only for bas_app
// (REVOKE UPDATE, DELETE), but the lab writes a NO_DATA placeholder row at
// dispatch and later UPDATEs it with the terminal outcome
// (validationlab.recordExecutionOutcome: `UPDATE content_validations SET
// outcome, run_id, detail WHERE ... outcome='NO_DATA'`). Without a column-scoped
// UPDATE grant for exactly those columns, that write fails with SQLSTATE 42501
// ("permission denied for table content_validations") and no content ever
// reaches VALIDATED / validated_coverage.
func TestEnsureAppRole_ContentValidationsOutcomeColumnsUpdatable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if err := db.EnsureAppRole(ctx, pool, testAppPassword); err != nil {
			t.Fatalf("EnsureAppRole: %v", err)
		}

		// The exact columns recordExecutionOutcome updates must be writable.
		for _, col := range []string{"outcome", "run_id", "detail"} {
			var ok bool
			if err := pool.QueryRow(ctx,
				`SELECT has_column_privilege('bas_app', 'content_validations', $1, 'UPDATE')`, col).Scan(&ok); err != nil {
				t.Fatalf("has_column_privilege(%s): %v", col, err)
			}
			if !ok {
				t.Fatalf("bas_app must have UPDATE on content_validations.%s so the validation lab can resolve the NO_DATA placeholder; it does not", col)
			}
		}

		// Append-only intent still holds: an immutable provenance column must
		// NOT be updatable, and DELETE must remain revoked.
		var canUpdateImmutable bool
		if err := pool.QueryRow(ctx,
			`SELECT has_column_privilege('bas_app', 'content_validations', 'content_version_id', 'UPDATE')`).Scan(&canUpdateImmutable); err != nil {
			t.Fatalf("has_column_privilege(content_version_id): %v", err)
		}
		if canUpdateImmutable {
			t.Fatal("bas_app must NOT have UPDATE on content_validations.content_version_id (append-only provenance)")
		}

		var canDelete bool
		if err := pool.QueryRow(ctx,
			`SELECT has_table_privilege('bas_app', 'content_validations', 'DELETE')`).Scan(&canDelete); err != nil {
			t.Fatalf("has_table_privilege(DELETE): %v", err)
		}
		if canDelete {
			t.Fatal("bas_app must NOT have DELETE on content_validations")
		}
	})
}
