package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureEvidenceSchema_CreatesTablesAndIsIdempotent(t *testing.T) {
	ctx := context.Background()

	for _, table := range []string{
		"source_instances", "source_trust_versions", "source_syncs",
		"source_observations", "threat_sources", "technique_claims",
		"threat_techniques", "content_generations",
	} {
		var exists bool
		if err := sharedDB.Pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
			table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("table %q was not created", table)
		}
	}

	// Idempotent: a second call must not error.
	if err := db.EnsureEvidenceSchema(ctx, sharedDB.Pool); err != nil {
		t.Fatalf("second EnsureEvidenceSchema call: %v", err)
	}
}
