package analytics

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// perDay is pure arithmetic and needs no database.
func TestPerDay_DividesByWindowLength(t *testing.T) {
	got := perDay(14, 7)
	if got.State != DataMeasured || *got.Value != 2 {
		t.Fatalf("perDay(14, 7) = %+v, want measured 2", got)
	}
	zero := perDay(0, 7)
	if zero.State != DataMeasured || *zero.Value != 0 {
		t.Fatalf("perDay(0, 7) = %+v, want measured 0 (zero is a real answer)", zero)
	}
	if noWindow := perDay(5, 0); noWindow.State != DataNoData {
		t.Fatalf("perDay with no window = %+v, want NO_DATA", noWindow)
	}
}

// seedPublishedAt inserts a published version whose most recent publish event
// happened age ago, so freshness buckets can be tested at known ages.
func seedPublishedAt(t *testing.T, pool *pgxpool.Pool, contentID string, age time.Duration) string {
	t.Helper()
	mustExec(t, pool, `INSERT INTO scenarios (scenario_id, origin) VALUES ($1, 'LOCAL') ON CONFLICT DO NOTHING`, contentID)
	var vid string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO content_versions (content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			trust_level, lifecycle, intake_source, schema_version, created_by)
		VALUES ($1, 'LOCAL', 1, 'sha-'||$1, 1, 'x', 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'custom', 1, 'migration:test')
		RETURNING id`, contentID).Scan(&vid); err != nil {
		t.Fatalf("seedPublishedAt version: %v", err)
	}
	mustExec(t, pool, `
		INSERT INTO content_version_events (content_version_id, to_lifecycle, to_trust, actor, at)
		VALUES ($1, 'PUBLISHED_LOCAL', 'UNTRUSTED', 'user:tester', $2)`, vid, time.Now().Add(-age))
	return vid
}

func TestContentFreshness_BucketsByAgeOfLatestPublish(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedPublishedAt(t, pool, "fr-new", 10*24*time.Hour)
		seedPublishedAt(t, pool, "fr-mid", 45*24*time.Hour)
		seedPublishedAt(t, pool, "fr-year", 200*24*time.Hour)
		seedPublishedAt(t, pool, "fr-old", 400*24*time.Hour)

		kpi, err := factoryKPIs(context.Background(), pool, time.Now().Add(-30*24*time.Hour), 30*24*time.Hour)
		if err != nil {
			t.Fatalf("factoryKPIs: %v", err)
		}
		fr := kpi.ContentFreshness
		if fr.Total != 4 || fr.Under30Days != 1 || fr.Days31To90 != 1 || fr.Days91To365 != 1 || fr.Over365Days != 1 {
			t.Fatalf("ContentFreshness = %+v, want one version in each bucket (total 4)", fr)
		}
	})
}

func TestFactoryKPIs_CountsWindowThroughputAndPublishes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		// An old publish (40 days ago) must fall outside a 30-day window.
		seedPublishedAt(t, pool, "tp-old-pub", 40*24*time.Hour)
		// A recent publish (1 hour ago) falls inside it.
		seedPublishedAt(t, pool, "tp-new-pub", 1*time.Hour)
		seedThreatWithActor(t, pool, "tp-threat-1", "Actor TP 1")
		seedThreatWithActor(t, pool, "tp-threat-2", "Actor TP 2")

		window := 30 * 24 * time.Hour
		kpi, err := factoryKPIs(ctx, pool, time.Now().Add(-window), window)
		if err != nil {
			t.Fatalf("factoryKPIs: %v", err)
		}
		if kpi.PublishedInWindow.State != DataMeasured || *kpi.PublishedInWindow.Value != 1 {
			t.Fatalf("PublishedInWindow = %+v, want 1 (old publish excluded)", kpi.PublishedInWindow)
		}
		if kpi.CandidatesGenerated.State != DataMeasured || *kpi.CandidatesGenerated.Value < 2 {
			t.Fatalf("CandidatesGenerated = %+v, want at least the seeded versions", kpi.CandidatesGenerated)
		}
		if kpi.ThreatsIngestedPerDay.State != DataMeasured || *kpi.ThreatsIngestedPerDay.Value <= 0 {
			t.Fatalf("ThreatsIngestedPerDay = %+v, want a positive measured rate", kpi.ThreatsIngestedPerDay)
		}
	})
}
