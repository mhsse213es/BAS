package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
)

// builtinIntakeFileWithEmulates builds a minimal, signature-accepted
// builtin IntakeFile declaring the given emulates references.
func builtinIntakeFileWithEmulates(t *testing.T, contentID string, refs []scenario.EmulatesRef) scenario.IntakeFile {
	t.Helper()
	sc := scenario.Scenario{ID: contentID, Name: "G", LocalCheck: true, Emulates: refs}
	b, err := yaml.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	return scenario.IntakeFile{Path: contentID + ".yaml", Source: "builtin", Artifact: b,
		Signature: []byte("sig"), SignatureVerified: true}
}

// TestIntake_BuiltinEmulatesResolvesKnownGroupToThreat pins acceptance
// test 25: a signed builtin scenario declaring emulates: G0016 resolves
// to a real threat via the canonical actor registry, never free text.
func TestIntake_BuiltinEmulatesResolvesKnownGroupToThreat(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())

		f := builtinIntakeFileWithEmulates(t, "cv-emulates-g0016", []scenario.EmulatesRef{
			{SubjectType: "actor", ExternalID: "G0016"},
		})
		decision, err := reg.Intake(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if !decision.Accepted {
			t.Fatalf("intake refused: %s", decision.Reason)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_version_threats cvt
			JOIN content_versions cv ON cv.id = cvt.content_version_id
			WHERE cv.content_id = $1 AND cvt.relationship_kind = 'emulates' AND cvt.provenance_type = 'vendor_signed_metadata'`,
			"cv-emulates-g0016").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("emulates link rows = %d, want 1", count)
		}
	})
}

// TestIntake_BuiltinEmulatesUnknownGroupQueuesCandidateNoLink pins
// acceptance test 26: an external_id that isn't a real MITRE group
// produces no link and a queued resolution candidate, not an error.
func TestIntake_BuiltinEmulatesUnknownGroupQueuesCandidateNoLink(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())

		f := builtinIntakeFileWithEmulates(t, "cv-emulates-unknown", []scenario.EmulatesRef{
			{SubjectType: "actor", ExternalID: "G9999"},
		})
		decision, err := reg.Intake(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if !decision.Accepted {
			t.Fatalf("intake must still succeed despite the unresolvable emulates reference: %s", decision.Reason)
		}

		var linkCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_version_threats cvt
			JOIN content_versions cv ON cv.id = cvt.content_version_id
			WHERE cv.content_id = $1 AND cvt.relationship_kind = 'emulates'`,
			"cv-emulates-unknown").Scan(&linkCount); err != nil {
			t.Fatal(err)
		}
		if linkCount != 0 {
			t.Fatalf("emulates link rows = %d, want 0 (G9999 is not a real MITRE group)", linkCount)
		}

		var candidateCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates
			WHERE kind = 'content_emulates_ref' AND external_id = 'G9999' AND status = 'unresolved'`).Scan(&candidateCount); err != nil {
			t.Fatal(err)
		}
		if candidateCount != 1 {
			t.Fatalf("queued candidate rows = %d, want 1", candidateCount)
		}
	})
}
