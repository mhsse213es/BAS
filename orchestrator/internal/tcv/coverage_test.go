package tcv

import (
	"context"
	"testing"
	"time"
)

// seedContentVersion inserts a minimal content_versions row this package's
// FK can reference -- internal/tcv must not import internal/contentregistry
// (Global Constraints), so it builds its own minimal fixture row directly.
func seedContentVersion(t *testing.T, contentID string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := sharedDB.Pool.Exec(ctx,
		`INSERT INTO scenarios (scenario_id, name, category, origin) VALUES ($1, $1, '', 'LOCAL')
		 ON CONFLICT (scenario_id) DO NOTHING`, contentID); err != nil {
		t.Fatal(err)
	}
	var vid string
	if err := sharedDB.Pool.QueryRow(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes, trust_level, lifecycle,
		 intake_source, schema_version, technique_ids, supported_os, generation, created_by)
		VALUES ($1, 'LOCAL', 1, 'deadbeef', 0, '\x', 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'custom', 1, '{}', '{}', '{}'::jsonb, 'test')
		RETURNING id`, contentID).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	return vid
}

func TestRecordCoverageFirst_WriteOncePerRelationshipKind(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-coverage-test")
	vid1 := seedContentVersion(t, "cv-coverage-test-1")
	vid2 := seedContentVersion(t, "cv-coverage-test-2")
	first := time.Now().Add(-1 * time.Hour)
	later := time.Now()

	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipEmulates, vid1, first); err != nil {
		t.Fatal(err)
	}
	// A later call for a DIFFERENT version, same (threat, kind), must not
	// move the already-written stop.
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipEmulates, vid2, later); err != nil {
		t.Fatal(err)
	}

	var gotVID string
	var firstExecutableAt time.Time
	if err := sharedDB.Pool.QueryRow(ctx,
		`SELECT content_version_id, first_executable_at FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
		threatID).Scan(&gotVID, &firstExecutableAt); err != nil {
		t.Fatal(err)
	}
	if gotVID != vid1 {
		t.Fatalf("content_version_id = %q, want the first call's version %q (write-once)", gotVID, vid1)
	}
	if diff := firstExecutableAt.Sub(first); diff < -time.Second || diff > time.Second {
		t.Fatalf("first_executable_at = %v, want %v", firstExecutableAt, first)
	}
}

func TestRecordCoverageFirst_EmulatesAndGeneratedForAreIndependent(t *testing.T) {
	ctx := context.Background()
	threatID := seedThreat(t, "APT-coverage-independent")
	vid := seedContentVersion(t, "cv-coverage-independent")
	now := time.Now()

	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipEmulates, vid, now); err != nil {
		t.Fatal(err)
	}
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, threatID, RelationshipGeneratedFor, vid, now); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1`, threatID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("threat_coverage_firsts rows = %d, want 2 (emulates and generated_for never collapse)", count)
	}
}
