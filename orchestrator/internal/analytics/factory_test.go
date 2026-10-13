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

func TestDuplicateGenerationRate_AlwaysNoData(t *testing.T) {
	got := duplicateGenerationRate()
	if got.State != DataNoData {
		t.Fatalf("got %+v, want no_data unconditionally -- generation-attempt telemetry is not persisted in this phase", got)
	}
	if got.Value != nil {
		t.Fatalf("got Value = %v, want nil for a no_data metric", got.Value)
	}
	if got.Reason == "" {
		t.Fatal("got empty Reason -- the UI needs this to explain why the metric is unavailable")
	}
}

func TestIngestionHealth_DistinguishesNeverSyncedFromStale(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO source_instances (id, source_type, display_name, observation_mode) VALUES ('src-never','misp','Never Synced','snapshot')`)
		mustExec(t, pool, `INSERT INTO source_instances (id, source_type, display_name, observation_mode) VALUES ('src-ok','misp','Healthy Source','snapshot')`)
		mustExec(t, pool, `
			INSERT INTO source_syncs (source_instance_id, started_at, completed_at, status, completeness, authoritative, diagnostic)
			VALUES ('src-ok', now(), now(), 'succeeded', 'complete', true, '')`)

		got, err := ingestionHealth(context.Background(), pool, time.Now().Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("ingestionHealth: %v", err)
		}
		bySource := map[string]SourceHealth{}
		for _, s := range got.Sources {
			bySource[s.SourceInstanceID] = s
		}
		if bySource["src-never"].LastSuccessAt != nil {
			t.Fatalf("src-never LastSuccessAt = %v, want nil (never synced)", bySource["src-never"].LastSuccessAt)
		}
		if bySource["src-ok"].LastSuccessAt == nil {
			t.Fatal("src-ok LastSuccessAt = nil, want a real timestamp")
		}
	})
}

func TestIngestionHealth_CountsFailuresInWindowAndUnresolvedCandidates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO source_instances (id, source_type, display_name, observation_mode) VALUES ('src-fail','misp','Flaky Source','snapshot')`)
		mustExec(t, pool, `
			INSERT INTO source_syncs (source_instance_id, started_at, status, completeness, authoritative, diagnostic)
			VALUES ('src-fail', now(), 'failed', 'failed', false, 'connection timeout')`)
		mustExec(t, pool, `
			INSERT INTO actor_resolution_candidates (kind, source, raw_name, reason, resolver_context, resolver_context_hash)
			VALUES ('source_record', 'misp', 'Unresolved Actor', 'test', '{}', 'hash-ingestion-health-1')`)

		got, err := ingestionHealth(context.Background(), pool, time.Now().Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("ingestionHealth: %v", err)
		}
		var flaky SourceHealth
		for _, s := range got.Sources {
			if s.SourceInstanceID == "src-fail" {
				flaky = s
			}
		}
		if flaky.FailuresInWindow != 1 || flaky.LastDiagnostic != "connection timeout" {
			t.Fatalf("flaky source = %+v, want FailuresInWindow=1 and diagnostic set", flaky)
		}
		if got.UnresolvedCandidates < 1 {
			t.Fatalf("UnresolvedCandidates = %d, want >= 1", got.UnresolvedCandidates)
		}
	})
}

func TestLifecycleFunnel_BucketsByLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedPublishedContentVersion(t, pool, "cv-funnel-published")
		seedContentVersionWithLifecycle(t, pool, "cv-funnel-draft", "DRAFT")
		seedContentVersionWithLifecycle(t, pool, "cv-funnel-validated", "VALIDATED")
		seedContentVersionWithLifecycle(t, pool, "cv-funnel-rejected", "REJECTED")

		got, err := lifecycleFunnel(context.Background(), pool)
		if err != nil {
			t.Fatalf("lifecycleFunnel: %v", err)
		}
		if got.Candidate < 1 || got.Validated < 1 || got.Published < 1 || got.Rejected < 1 {
			t.Fatalf("got %+v, want all four buckets to have at least the one seeded row each", got)
		}
	})
}

func TestDataQuality_FlagsNeverSyncedSourceAndStaleValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO source_instances (id, source_type, display_name, observation_mode) VALUES ('src-stale-dq','misp','Stale DQ Source','snapshot')`)
		vid := seedContentVersionWithLifecycle(t, pool, "cv-dq-stale-validating", "VALIDATING")
		mustExec(t, pool, `
			INSERT INTO content_version_events (content_version_id, to_lifecycle, to_trust, actor, at)
			VALUES ($1, 'VALIDATING', 'LOCAL_TRUSTED', 'user:test', now() - interval '10 days')`, vid)

		got, err := dataQuality(context.Background(), pool, 7*24*time.Hour)
		if err != nil {
			t.Fatalf("dataQuality: %v", err)
		}
		found := false
		for _, name := range got.StaleSources {
			if name == "Stale DQ Source" {
				found = true
			}
		}
		if !found {
			t.Fatalf("StaleSources = %v, want to include 'Stale DQ Source'", got.StaleSources)
		}
		if got.StaleValidations < 1 {
			t.Fatalf("StaleValidations = %d, want >= 1", got.StaleValidations)
		}
	})
}

func seedContentVersionWithLifecycle(t *testing.T, pool *pgxpool.Pool, contentID, lifecycle string) string {
	t.Helper()
	mustExec(t, pool, `INSERT INTO scenarios (scenario_id, origin) VALUES ($1, 'LOCAL') ON CONFLICT DO NOTHING`, contentID)
	var vid string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO content_versions (content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			trust_level, lifecycle, intake_source, schema_version, created_by)
		VALUES ($1, 'LOCAL', 1, 'sha-'||$1, 1, 'x', 'LOCAL_TRUSTED', $2, 'custom', 1, 'migration:test')
		RETURNING id`, contentID, lifecycle).Scan(&vid); err != nil {
		t.Fatalf("seedContentVersionWithLifecycle: %v", err)
	}
	return vid
}

func TestThreatsProcessedTrend_BelowMinimumReturnsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedThreatWithActorAt(t, pool, "t-trend-1", "Actor Trend 1", time.Now())

		got, err := threatsProcessedTrend(context.Background(), pool, time.Now().Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("threatsProcessedTrend: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d points, want 0 (1 day of data is below minTrendPoints=%d)", len(got), minTrendPoints)
		}
	})
}

func TestThreatsProcessedTrend_MeetsMinimumReturnsPoints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		offsets := []time.Duration{-3 * 24 * time.Hour, -2 * 24 * time.Hour, -1 * 24 * time.Hour}
		for i, offset := range offsets {
			seedThreatWithActorAt(t, pool, "t-trend-pts-"+string(rune('a'+i)), "Actor Trend Pts "+string(rune('a'+i)), time.Now().Add(offset))
		}

		got, err := threatsProcessedTrend(context.Background(), pool, time.Now().Add(-7*24*time.Hour))
		if err != nil {
			t.Fatalf("threatsProcessedTrend: %v", err)
		}
		if len(got) < minTrendPoints {
			t.Fatalf("got %d points, want >= %d", len(got), minTrendPoints)
		}
	})
}

func TestFactoryHealth_AssemblesAllSectionsWithNoDataWhenEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		got, err := FactoryHealth(context.Background(), pool, 30*24*time.Hour)
		if err != nil {
			t.Fatalf("FactoryHealth: %v", err)
		}
		if got.ThreatsProcessed.State != DataMeasured || *got.ThreatsProcessed.Value != 0 {
			t.Fatalf("ThreatsProcessed = %+v, want measured 0 (a real zero, not no_data) on a fresh database", got.ThreatsProcessed)
		}
		if got.MedianThreatToContentTCV.State != DataNoData {
			t.Fatalf("MedianThreatToContentTCV = %+v, want no_data on a fresh database", got.MedianThreatToContentTCV)
		}
		if got.DuplicateGenerationRate.State != DataNoData {
			t.Fatalf("DuplicateGenerationRate = %+v, want no_data unconditionally", got.DuplicateGenerationRate)
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
	seedThreatWithActorAt(t, pool, threatID, actorName, time.Now())
}

// seedThreatWithActorAt is seedThreatWithActor with an explicit created_at,
// for trend tests that need threats spread across specific days.
func seedThreatWithActorAt(t *testing.T, pool *pgxpool.Pool, threatID, actorName string, createdAt time.Time) {
	t.Helper()
	ctx := context.Background()
	var actorID string
	if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ($1) RETURNING id`, actorName).Scan(&actorID); err != nil {
		t.Fatalf("seedThreatWithActorAt: insert actor: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO threats (id, subject_type, subject_id, actor_id, title, created_at)
		VALUES ($1, 'actor', $2, $2, $3, $4)`, threatID, actorID, actorName, createdAt); err != nil {
		t.Fatalf("seedThreatWithActorAt: insert threat: %v", err)
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
