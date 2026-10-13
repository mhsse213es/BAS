package contentregistry

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

// TestLinkThreat_AlreadyExecutableRecordsCoverageFirstImmediately pins
// acceptance test 33: linking emulates on a version that is already
// executable must stop the clock at link time, not wait for a future
// transition.
func TestLinkThreat_AlreadyExecutableRecordsCoverageFirstImmediately(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-link-threat-executable")

		art := []byte("id: cv-link-threat-executable\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-link-threat-executable", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorMigration, source: SourceCustom, origin: OriginLocal,
			trust: TrustLocalTrusted, lifecycle: LifecyclePublishedLocal, exclusiveLocalSource: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		if err := reg.LinkThreat(ctx, "cv-link-threat-executable", 1, threatID, "user:admin", "confirmed emulation"); err != nil {
			t.Fatal(err)
		}

		var linkCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM content_version_threats WHERE content_version_id = $1 AND relationship_kind = 'emulates' AND provenance_type = 'admin'`,
			vid).Scan(&linkCount); err != nil {
			t.Fatal(err)
		}
		if linkCount != 1 {
			t.Fatalf("emulates link rows = %d, want 1", linkCount)
		}

		var coverageCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&coverageCount); err != nil {
			t.Fatal(err)
		}
		if coverageCount != 1 {
			t.Fatalf("threat_coverage_firsts rows = %d, want 1 (version was already executable when linked)", coverageCount)
		}
	})
}

func TestLinkThreat_UnknownThreatRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		art := []byte("id: cv-link-threat-unknown\nname: G\nlocal_check: true\n")
		_, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-link-threat-unknown", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorMigration, source: SourceCustom, origin: OriginLocal,
			trust: TrustUntrusted, lifecycle: LifecycleDraft, exclusiveLocalSource: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		err = reg.LinkThreat(ctx, "cv-link-threat-unknown", 1, "thr-does-not-exist", "admin", "reason")
		if !errors.Is(err, ErrThreatNotFound) {
			t.Fatalf("err = %v, want ErrThreatNotFound", err)
		}
	})
}
