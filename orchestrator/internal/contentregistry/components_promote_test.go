package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

// seedExecutableVersion creates a PUBLISHED_LOCAL/LOCAL_TRUSTED content_version
// with the given steps (as YAML `steps:` entries), ready to promote from.
func seedExecutableVersion(t *testing.T, pool *pgxpool.Pool, contentID string, stepsYAML string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ($1, 'LOCAL') ON CONFLICT DO NOTHING`, contentID); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("id: " + contentID + "\nname: Test\nsupported_os: [windows]\nsteps:\n" + stepsYAML)
	var versionID string
	if err := pool.QueryRow(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
		 trust_level, lifecycle, intake_source, schema_version, technique_ids, supported_os, created_by)
		VALUES ($1, 'LOCAL', 1, 'sha-'||gen_random_uuid()::text, $3, $2,
		 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'custom', 1, '{T1059}', '{windows}', 'test')
		RETURNING id`, contentID, artifact, len(artifact)).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	return versionID
}

func TestPromoteInternalComponent_RequiresExecutableVersion(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ('intel-draft-promote', 'LOCAL') ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		artifact := []byte("id: intel-draft-promote\nname: T\nsupported_os: [windows]\nsteps:\n- name: s\n  technique_id: T1059\n  framework: art\n  test_index: 0\n")
		var draftID string
		if err := pool.QueryRow(ctx, `INSERT INTO content_versions
			(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			 trust_level, lifecycle, intake_source, schema_version, technique_ids, created_by)
			VALUES ('intel-draft-promote', 'LOCAL', 1, 'sha-draft', $2, $1,
			 'UNTRUSTED', 'DRAFT', 'custom', 1, '{T1059}', 'test') RETURNING id`, artifact, len(artifact)).Scan(&draftID); err != nil {
			t.Fatal(err)
		}
		reg := New(pool, testutil.DevVerifier())
		_, err := reg.PromoteInternalComponent(ctx, draftID, 0, "admin-test")
		if err == nil {
			t.Fatal("expected promotion from a DRAFT (non-executable) version to be refused")
		}
	})
}

func TestPromoteInternalComponent_SnapshotsStepAndIsImmutable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		versionID := seedExecutableVersion(t, pool, "intel-promote-ok", "- name: s\n  technique_id: T1059\n  framework: art\n  test_index: 0\n")
		reg := New(pool, testutil.DevVerifier())

		componentID, err := reg.PromoteInternalComponent(ctx, versionID, 0, "admin-test")
		if err != nil {
			t.Fatalf("PromoteInternalComponent: %v", err)
		}

		var kind, techniqueID string
		var supportedOS []string
		if err := pool.QueryRow(ctx, `SELECT kind, technique_id, supported_os FROM content_components WHERE id = $1`,
			componentID).Scan(&kind, &techniqueID, &supportedOS); err != nil {
			t.Fatal(err)
		}
		if kind != "internal" {
			t.Fatalf("expected kind=internal, got %q", kind)
		}
		if techniqueID != "T1059" {
			t.Fatalf("expected technique_id=T1059, got %q", techniqueID)
		}
		if len(supportedOS) != 1 || supportedOS[0] != "windows" {
			t.Fatalf("expected supported_os carried forward from origin scenario ([windows]), got %v", supportedOS)
		}
	})
}

func TestPromoteInternalComponent_RefusesPromotingFromAComposedCandidate(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		composedID := seedExecutableVersion(t, pool, "intel-composed-source", "- name: s\n  technique_id: T1059\n  framework: art\n  test_index: 0\n")
		if _, err := pool.Exec(ctx, `INSERT INTO content_components
			(kind, technique_id, title, origin_content_version_id, step_snapshot, promoted_by)
			VALUES ('internal', 'T1053', 'other component', $1, '{}', 'test')`, composedID); err != nil {
			t.Fatal(err)
		}
		var someOtherComponentID string
		if err := pool.QueryRow(ctx, `SELECT id FROM content_components WHERE origin_content_version_id = $1`, composedID).Scan(&someOtherComponentID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_version_components (content_version_id, component_id, step_order) VALUES ($1, $2, 0)`,
			composedID, someOtherComponentID); err != nil {
			t.Fatal(err)
		}

		reg := New(pool, testutil.DevVerifier())
		_, err := reg.PromoteInternalComponent(ctx, composedID, 0, "admin-test")
		if err == nil {
			t.Fatal("expected promotion from a composed candidate's own content_version to be refused")
		}
	})
}
