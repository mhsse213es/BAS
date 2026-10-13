package contentregistry

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

// TestIntegration_DraftNeverStopsClockFirstExecutableDoesLaterRevocationDoesNot
// pins acceptance test 28.
func TestIntegration_DraftNeverStopsClockFirstExecutableDoesLaterRevocationDoesNot(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())
		threatID := seedThreatForTCVTest(t, pool, "APT-acceptance-28")

		art := []byte("id: cv-acceptance-28\nname: G\nlocal_check: true\n")
		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-acceptance-28", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorMigration, source: SourceCustom, origin: OriginLocal,
			trust: TrustUntrusted, lifecycle: LifecycleDraft, exclusiveLocalSource: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.LinkThreat(ctx, "cv-acceptance-28", 1, threatID, "user:admin", "setup"); err != nil {
			t.Fatal(err)
		}

		assertCoverageCount(t, pool, threatID, 0) // still DRAFT -- no stop yet

		if err := reg.Transition(ctx, vid, LifecyclePublishedLocal, "user:admin", "approved"); err != nil {
			t.Fatal(err)
		}
		assertCoverageCount(t, pool, threatID, 1) // now executable -- stop recorded

		var firstAt time.Time
		if err := pool.QueryRow(ctx, `SELECT first_executable_at FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&firstAt); err != nil {
			t.Fatal(err)
		}

		// Retire it -- revocation must not move the already-written stop.
		if err := reg.Transition(ctx, vid, LifecycleRetired, "user:admin", "retired"); err != nil {
			t.Fatal(err)
		}
		var firstAtAfterRetire time.Time
		if err := pool.QueryRow(ctx, `SELECT first_executable_at FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`,
			threatID).Scan(&firstAtAfterRetire); err != nil {
			t.Fatal(err)
		}
		if !firstAtAfterRetire.Equal(firstAt) {
			t.Fatalf("first_executable_at moved from %v to %v after retirement", firstAt, firstAtAfterRetire)
		}
	})
}

// TestIntegration_DevOnlyExecutableNeverStopsClock pins acceptance test 32.
func TestIntegration_DevOnlyExecutableNeverStopsClock(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier()) // devBuild() == true
		threatID := seedThreatForTCVTest(t, pool, "APT-acceptance-32")

		art := []byte("id: cv-acceptance-32\nname: G\nlocal_check: true\n")
		_, _, err := reg.createVersion(ctx, newVersion{
			contentID: "cv-acceptance-32", artifact: art,
			analysis: mustAnalyze(t, string(art)),
			actor: ActorIntake, source: SourceBuiltin, origin: OriginVendor,
			trust: TrustUntrusted, lifecycle: LifecyclePublished, // the dev-only combo
			emulatesLinks: []emulatesLink{{threatID: threatID, provenanceRef: "G0016"}},
		})
		if err != nil {
			t.Fatal(err)
		}

		assertCoverageCount(t, pool, threatID, 0) // dev-only combo must never qualify
	})
}

func assertCoverageCount(t *testing.T, pool *pgxpool.Pool, threatID string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM threat_coverage_firsts WHERE threat_id = $1 AND relationship_kind = 'emulates'`, threatID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("threat_coverage_firsts rows = %d, want %d", got, want)
	}
}
