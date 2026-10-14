package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
)

func TestEnsureTCVSchema_CreatesTablesAndWidensCandidateKind(t *testing.T) {
	ctx := context.Background()
	pool := sharedDB.Pool

	if err := db.EnsureTCVSchema(ctx, pool); err != nil {
		t.Fatalf("EnsureTCVSchema: %v", err)
	}
	// Idempotent -- running it twice must not error.
	if err := db.EnsureTCVSchema(ctx, pool); err != nil {
		t.Fatalf("EnsureTCVSchema (second run): %v", err)
	}

	for _, table := range []string{"threat_clock_starts", "threat_coverage_firsts"} {
		var exists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1)`,
			table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("table %q was not created", table)
		}
	}

	// The widened CHECK must now accept 'content_emulates_ref'.
	var threatID string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ('APT-tcv-schema-test', '{}') RETURNING id`).
		Scan(&threatID); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(ctx, `INSERT INTO actor_resolution_candidates
		(kind, source, external_id, raw_name, ref_entity_id, reason, resolver_context, resolver_context_hash)
		VALUES ('content_emulates_ref', 'attackdata', 'G9999', 'G9999', 'cv-schema-test', 'test', '{}'::jsonb, '')`)
	if err != nil {
		t.Fatalf("widened CHECK should accept 'content_emulates_ref': %v", err)
	}
}
