package contentregistry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

// seedThreatForTCVTest mirrors internal/evidence's seedThreat -- this
// package has no existing helper that inserts a threats row.
func seedThreatForTCVTest(t *testing.T, pool *pgxpool.Pool, name string) string {
	t.Helper()
	ctx := context.Background()
	var actorID string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name, aliases) VALUES ($1, '{}') RETURNING id`,
		name).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	var threatID string
	if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, $2) RETURNING id`,
		actorID, name).Scan(&threatID); err != nil {
		t.Fatal(err)
	}
	return threatID
}

func TestQualifiesForTCVStop_ExcludesDevOnlyCombination(t *testing.T) {
	cases := []struct {
		name   string
		origin Origin
		trust  Trust
		lc     Lifecycle
		want   bool
	}{
		{"vendor signed published", OriginVendor, TrustVendorSigned, LifecyclePublished, true},
		{"local trusted published-local", OriginLocal, TrustLocalTrusted, LifecyclePublishedLocal, true},
		{"vendor untrusted published (dev-only combo)", OriginVendor, TrustUntrusted, LifecyclePublished, false},
		{"draft never qualifies", OriginVendor, TrustVendorSigned, LifecycleDraft, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := qualifiesForTCVStop(tc.origin, tc.trust, tc.lc); got != tc.want {
				t.Errorf("qualifiesForTCVStop(%s,%s,%s) = %v, want %v", tc.origin, tc.trust, tc.lc, got, tc.want)
			}
		})
	}
}

func TestTransition_RecordsCoverageFirstWhenLinkedVersionBecomesExecutable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-transition-coverage")

		art := []byte("id: cv-transition-coverage\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-transition-coverage", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor:    ActorMigration, source: SourceCustom, origin: OriginLocal,
			trust: TrustUntrusted, lifecycle: LifecycleDraft, exclusiveLocalSource: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_version_threats
			(content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
			VALUES ($1, $2, 'emulates', 'admin', 'test-setup')`, vid, threatID); err != nil {
			t.Fatal(err)
		}

		if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin", "approved"); err != nil {
			t.Fatal(err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1 (version became executable via Transition)", count)
		}
	})
}

func TestAttachVendorSignature_RecordsCoverageFirstOnTrustFlipAlone(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		reg := New(pool, signer.Verifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-signature-coverage")

		// VENDOR + PUBLISHED but NOT yet signed -- not executable yet (the
		// runtime gate requires VENDOR_SIGNED). Lifecycle never changes in
		// this test; only trust flips, via AttachVendorSignature alone.
		art := []byte("id: cv-signature-coverage\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-signature-coverage", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor:    ActorIntake, source: SourceBuiltin, origin: OriginVendor,
			trust: TrustUntrusted, lifecycle: LifecyclePublished,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_version_threats
			(content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
			VALUES ($1, $2, 'emulates', 'vendor_signed_metadata', 'G0016')`, vid, threatID); err != nil {
			t.Fatal(err)
		}

		sig := signer.Sign(art)
		if err := reg.AttachVendorSignature(ctx, vid, sig, "user:admin"); err != nil {
			t.Fatal(err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1 (lifecycle never changed; only AttachVendorSignature's trust flip made this executable)", count)
		}
	})
}

func TestCreateVersion_RecordsCoverageFirstWhenAlreadyExecutableAtCreation(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		signer := testutil.NewTestSigner(t)
		reg := New(pool, signer.Verifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-createversion-coverage")

		// A signature-verified builtin is created already PUBLISHED +
		// VENDOR_SIGNED -- executable from the moment createVersion commits,
		// with no later Transition/AttachVendorSignature call at all.
		art := []byte("id: cv-createversion-coverage\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-createversion-coverage", artifact: art, signature: signer.Sign(art),
			analysis: mustAnalyze(t, string(art)),
			actor:    ActorIntake, source: SourceBuiltin, origin: OriginVendor,
			trust: TrustVendorSigned, lifecycle: LifecyclePublished,
			emulatesLinks: []emulatesLink{{threatID: threatID, provenanceRef: "G0016"}},
		})
		if err != nil {
			t.Fatal(err)
		}

		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1 (version %s was executable at the moment it was created)", count, vid)
		}
	})
}
