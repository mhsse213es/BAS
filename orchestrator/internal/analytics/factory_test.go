package analytics

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStaticValidationPassRate_NoDataWhenNoneRunInWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := staticValidationPassRate(context.Background(), pool, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("staticValidationPassRate: %v", err)
		}
		if got.State != DataNoData {
			t.Fatalf("got %+v, want no_data when zero STRUCTURAL/STATIC validations ran in window", got)
		}
	})
}

func TestStaticValidationPassRate_ExcludesExecutionLevelAndNoDataOutcome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		since := time.Now().Add(-24 * time.Hour)
		vid := seedPublishedContentVersion(t, pool, "cv-passrate-1")
		mustExec(t, pool, `INSERT INTO content_validations (content_version_id, level, outcome, validator, validator_version) VALUES ($1,'STATIC','PASS','test','1')`, vid)
		mustExec(t, pool, `INSERT INTO content_validations (content_version_id, level, outcome, validator, validator_version) VALUES ($1,'STRUCTURAL','FAIL','test','1')`, vid)
		mustExec(t, pool, `INSERT INTO content_validations (content_version_id, level, outcome, validator, validator_version) VALUES ($1,'STATIC','NO_DATA','test','1')`, vid)
		// EXECUTION-level PASS requires a run_id (content_validations' own
		// CHECK); use DETECTED instead -- still proves the STATIC/STRUCTURAL
		// filter excludes EXECUTION-level rows regardless of outcome.
		mustExec(t, pool, `INSERT INTO content_validations (content_version_id, level, outcome, validator, validator_version) VALUES ($1,'EXECUTION','DETECTED','test','1')`, vid)

		got, err := staticValidationPassRate(context.Background(), pool, since)
		if err != nil {
			t.Fatalf("staticValidationPassRate: %v", err)
		}
		// Denominator = 2 (the STATIC PASS + STRUCTURAL FAIL; the NO_DATA
		// outcome and the EXECUTION-level row are both excluded).
		if got.State != DataMeasured || *got.Value != 0.5 {
			t.Fatalf("got %+v, want measured 0.5 (1 PASS of 2 qualifying STRUCTURAL/STATIC rows)", got)
		}
	})
}

func TestCoreCounts_ThreatsAndPublishedContent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		since := time.Now().Add(-24 * time.Hour)
		seedThreatWithActor(t, pool, "t-core-1", "Actor Core 1")
		seedThreatWithActor(t, pool, "t-core-2", "Actor Core 2")
		seedPublishedContentVersion(t, pool, "cv-core-1")

		got, err := coreCounts(context.Background(), pool, since)
		if err != nil {
			t.Fatalf("coreCounts: %v", err)
		}
		if got.ThreatsProcessed.State != DataMeasured || *got.ThreatsProcessed.Value != 2 {
			t.Fatalf("ThreatsProcessed = %+v, want measured 2", got.ThreatsProcessed)
		}
		if got.PublishedContent.State != DataMeasured || *got.PublishedContent.Value != 1 {
			t.Fatalf("PublishedContent = %+v, want measured 1", got.PublishedContent)
		}
	})
}

func TestCoreCounts_SourceToTechniqueCoverage_NoDataWhenNoThreatsInWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := coreCounts(context.Background(), pool, time.Now().Add(time.Hour)) // window in the future: nothing qualifies
		if err != nil {
			t.Fatalf("coreCounts: %v", err)
		}
		if got.SourceToTechniqueCoverage.State != DataNoData {
			t.Fatalf("SourceToTechniqueCoverage = %+v, want no_data when zero threats are in the window", got.SourceToTechniqueCoverage)
		}
	})
}

func TestCoreCounts_SourceToTechniqueCoverage_Measured(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		since := time.Now().Add(-24 * time.Hour)
		seedThreatWithActor(t, pool, "t-cov-1", "Actor Cov 1")
		seedThreatWithActor(t, pool, "t-cov-2", "Actor Cov 2")
		mustExec(t, pool, `INSERT INTO threat_techniques (threat_id, technique_id, last_seen_at, status, status_reason) VALUES ('t-cov-1','T1059',now(),'active','supported')`)

		got, err := coreCounts(context.Background(), pool, since)
		if err != nil {
			t.Fatalf("coreCounts: %v", err)
		}
		if got.SourceToTechniqueCoverage.State != DataMeasured || *got.SourceToTechniqueCoverage.Value != 0.5 {
			t.Fatalf("SourceToTechniqueCoverage = %+v, want measured 0.5 (1 of 2 threats has a technique)", got.SourceToTechniqueCoverage)
		}
	})
}

// seedThreatWithActor creates a real threat_actor_profiles row first and
// uses its generated id for both threats.actor_id and threats.subject_id --
// threats' own CHECK requires subject_id = actor_id for subject_type='actor',
// and actor_id is a hard FK into threat_actor_profiles(id).
func seedThreatWithActor(t *testing.T, pool *pgxpool.Pool, threatID, actorName string) {
	t.Helper()
	ctx := context.Background()
	var actorID string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ($1) RETURNING id`, actorName).Scan(&actorID); err != nil {
		t.Fatalf("seedThreatWithActor: insert actor: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
		VALUES ($1, 'actor', $2, $2, $3)`, threatID, actorID, actorName); err != nil {
		t.Fatalf("seedThreatWithActor: insert threat: %v", err)
	}
}

func seedPublishedContentVersion(t *testing.T, pool *pgxpool.Pool, contentID string) string {
	t.Helper()
	mustExec(t, pool, `INSERT INTO scenarios (scenario_id, origin) VALUES ($1, 'LOCAL') ON CONFLICT DO NOTHING`, contentID)
	var vid string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO content_versions (content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			trust_level, lifecycle, intake_source, schema_version, created_by)
		VALUES ($1, 'LOCAL', 1, 'sha-'||$1, 1, 'x', 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'custom', 1, 'migration:test')
		RETURNING id`, contentID).Scan(&vid); err != nil {
		t.Fatalf("seedPublishedContentVersion: %v", err)
	}
	return vid
}
