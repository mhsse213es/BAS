package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureGenerationAttemptsSchema_CreatesTable(t *testing.T) {
	// sharedDB's bootstrap (Step 4 of this task) already calls this once;
	// calling it again here proves it's idempotent, matching every other
	// Ensure*Schema test in this package.
	if err := db.EnsureGenerationAttemptsSchema(context.Background(), sharedDB.Pool); err != nil {
		t.Fatalf("EnsureGenerationAttemptsSchema: %v", err)
	}

	var exists bool
	err := sharedDB.Pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'content_generation_attempts')`,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("check table exists: %v", err)
	}
	if !exists {
		t.Fatal("content_generation_attempts table was not created")
	}
}

func TestEnsureGenerationAttemptsSchema_OutcomeCheckConstraint(t *testing.T) {
	_, err := sharedDB.Pool.Exec(context.Background(), `INSERT INTO content_generation_attempts
		(cycle_id, outcome, reason_code, generator_version, started_at)
		VALUES ('check-constraint-test', 'not-a-real-outcome', 'ok', '4', NOW())`)
	if err == nil {
		t.Fatal("expected the outcome CHECK constraint to reject an invalid value")
	}
}

func TestEnsureGenerationAttemptsSchema_NullableFieldsAcceptNull(t *testing.T) {
	_, err := sharedDB.Pool.Exec(context.Background(), `INSERT INTO content_generation_attempts
		(cycle_id, outcome, reason_code, generator_version, started_at)
		VALUES ('nullable-fields-test', 'skipped', 'unresolved_identity', '4', NOW())`)
	if err != nil {
		t.Fatalf("expected a row with no threat_id/content_id/content_version_id/fingerprint to insert cleanly: %v", err)
	}

	var threatID, contentID, contentVersionID, fingerprint *string
	err = sharedDB.Pool.QueryRow(context.Background(),
		`SELECT threat_id, content_id, content_version_id, fingerprint FROM content_generation_attempts WHERE cycle_id = 'nullable-fields-test'`,
	).Scan(&threatID, &contentID, &contentVersionID, &fingerprint)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if threatID != nil || contentID != nil || contentVersionID != nil || fingerprint != nil {
		t.Fatalf("expected all four to be NULL, got threatID=%v contentID=%v contentVersionID=%v fingerprint=%v",
			threatID, contentID, contentVersionID, fingerprint)
	}
}
