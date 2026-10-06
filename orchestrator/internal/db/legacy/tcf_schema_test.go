package legacy_test

// Moved from TCF's internal/db content_registry_schema_test.go and
// threat_identity_schema_test.go when their boot DDL joined the frozen chain
// (H1): adoption re-runs the chain on a pre-H1 install that may already have
// these objects, so each step must stay idempotent and keep its guard.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db/legacy"
	"github.com/audspect/bas/internal/db/pgtest"
)

func TestContentRegistryAndThreatIdentity_Idempotent(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.PoolFor(t, pgtest.NewDatabase(t))
	if err := legacy.EnsureAll(ctx, pool); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := legacy.EnsureContentRegistrySchema(ctx, pool); err != nil {
			t.Fatalf("content registry re-run %d: %v", i+1, err)
		}
		if err := legacy.EnsureThreatIdentitySchema(ctx, pool); err != nil {
			t.Fatalf("threat identity re-run %d: %v", i+1, err)
		}
	}
	for _, tbl := range []string{"content_versions", "content_version_events", "content_version_sources",
		"content_safety_verdicts", "content_validations", "content_registry_state", "threats"} {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_name=$1`, tbl).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing (n=%d err=%v)", tbl, n, err)
		}
	}
	var pk string
	if err := pool.QueryRow(ctx, `
		SELECT string_agg(a.attname, ',') FROM pg_constraint c
		  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
		 WHERE c.conrelid = 'threat_actor_profiles'::regclass AND c.contype = 'p'`).Scan(&pk); err != nil {
		t.Fatal(err)
	}
	if pk != "id" {
		t.Fatalf("threat_actor_profiles primary key = %q, want id", pk)
	}
}

// The guard against a deployment whose (historically dead) scenarios table
// has rows but no origin column.
func TestContentRegistrySchema_RefusesUnexpectedScenarioRows(t *testing.T) {
	ctx := context.Background()
	dsn := pgtest.NewDatabase(t)
	admin := pgtest.PoolFor(t, dsn)
	pgtest.Exec(t, admin, `CREATE SCHEMA cr_guard;
		CREATE TABLE cr_guard.scenarios (scenario_id text PRIMARY KEY, name text NOT NULL DEFAULT '');
		INSERT INTO cr_guard.scenarios (scenario_id) VALUES ('stray')`)
	cfg := admin.Config().Copy()
	cfg.ConnConfig.RuntimeParams["search_path"] = "cr_guard"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	err = legacy.EnsureContentRegistrySchema(ctx, p)
	if err == nil || !strings.Contains(err.Error(), "unexpected row") {
		t.Fatalf("want unexpected-row refusal, got %v", err)
	}
}
