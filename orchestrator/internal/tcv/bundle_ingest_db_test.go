package tcv

import (
	"context"
	"testing"
	"time"
)

// TestIngestBundleManifest_DatabaseRoundTripIsIdempotent exercises the real
// hash lookup and the real ledger write. A second run must record nothing new:
// the ledger's idempotency key makes the replay a no-op, leaving exactly one row.
func TestIngestBundleManifest_DatabaseRoundTripIsIdempotent(t *testing.T) {
	ctx := context.Background()
	pool := sharedDB.Pool

	const contentID = "cv-bundle-ingest-db"
	const sha = "bundle-ingest-db-sha-0001"
	if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, name, category, origin) VALUES ($1, $1, '', 'LOCAL')
		ON CONFLICT (scenario_id) DO NOTHING`, contentID); err != nil {
		t.Fatal(err)
	}
	var vid string
	if err := pool.QueryRow(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes, trust_level, lifecycle,
		 intake_source, schema_version, technique_ids, supported_os, generation, created_by)
		VALUES ($1, 'LOCAL', 1, $2, 0, '\x', 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'custom', 1, '{}', '{}', '{}'::jsonb, 'test')
		RETURNING id`, contentID, sha).Scan(&vid); err != nil {
		t.Fatal(err)
	}

	m := BundleManifest{
		Schema:     1,
		BundleID:   "bundle-db-roundtrip",
		PackagedAt: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC),
		Entries: []BundleEntry{
			{Path: "scenarios/known.yaml", SHA256: sha},
			{Path: "scenarios/unknown.yaml", SHA256: "not-in-registry"},
		},
	}

	recorded, unmatched, err := IngestBundleManifest(ctx, pool, DBVersionLookup(pool), m)
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	if recorded != 1 {
		t.Errorf("first run recorded = %d, want 1", recorded)
	}
	if len(unmatched) != 1 || unmatched[0] != "not-in-registry" {
		t.Errorf("first run unmatched = %v, want [not-in-registry]", unmatched)
	}

	// Re-running the same manifest must not add a second ledger row.
	if _, _, err := IngestBundleManifest(ctx, pool, DBVersionLookup(pool), m); err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM tcf_pipeline_events
		 WHERE event_type = 'bundle_packaged' AND content_version_id = $1`, vid).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Errorf("bundle_packaged rows for version = %d after two runs, want exactly 1", rows)
	}
}
