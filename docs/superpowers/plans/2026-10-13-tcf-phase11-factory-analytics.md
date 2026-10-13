# TCF Phase 11 — Factory Analytics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a read-only `/api/analytics/factory-health` endpoint plus a minimal dashboard page that measures TCF pipeline health — content throughput, threat-to-content velocity, validation pass rate, ingestion health, lifecycle funnel, data quality — entirely from records the system already persists.

**Architecture:** One new aggregate query in `internal/tcv` (median/P95 TCV across all threats); a new `internal/analytics/factory.go` following that package's existing thin-function convention (raw SQL, one result struct); one new handler/route at `tierAny`; one new frontend feature module following the existing flat-module/`apicall`/tile-template convention, with inline SVG sparklines for the two metrics with real time-series history.

**Tech Stack:** Go (pgx/v5, chi router), vanilla JS (no framework, no new dependency), PostgreSQL.

**Spec:** [docs/superpowers/specs/2026-10-13-tcf-phase11-factory-analytics-design.md](../specs/2026-10-13-tcf-phase11-factory-analytics-design.md)

## Global Constraints

- No new database tables. Every query reads existing tables only.
- No new frontend framework, no charting library. Trends render as hand-rolled inline SVG polylines, matching `attack-path.js`/`evidence.js`'s existing convention.
- Every response endpoint. No mutation: this phase adds zero write paths.
- Every metric carries an explicit `state` (`"measured"` or `"no_data"`) — never a bare number, never a fabricated zero standing in for missing data.
- Duplicate-generation rate is **always** `no_data` in this phase — do not add a persisted generation-attempt log; that is Phase 9's deliverable.
- Median/P95 TCV is scoped to the `ThreatToEmulation` combination only (`clock='threat'`, `relationship_kind='emulates'`). The other three TCV combinations are out of scope for this tile.
- Static validation pass rate counts only `content_validations.level IN ('STRUCTURAL','STATIC')`, and is labeled as such in its response field name — never implies execution or detection validation.
- New API route uses `tierAny` access (same tier as its sibling `/api/analytics/threat-intel-summary` — no fine-grained permission for a reporting endpoint).
- A trend line renders only with ≥3 real data points; below that, the UI shows an honest empty state, never a 1-2-point line.

## Review Focus

- A metric with a zero denominator (e.g. zero STRUCTURAL/STATIC validations run, zero threats with any technique) must report `no_data`, not a divide-by-zero error and not a fabricated `0%`.
- The TCV aggregate query must exclude `Open`/`PreExisting`/`NoClock`-equivalent threats from the percentile — a threat whose clock started but has no coverage yet must not silently count as a zero-duration measurement.
- A source that has never once synced successfully (new source, zero `source_syncs` rows) must appear distinctly in ingestion health, not be indistinguishable from a source that synced successfully long ago and is merely stale.
- The frontend must render a `no_data` tile visually distinctly from a real `measured` zero-value tile — a reviewer must not be able to confuse "never measured" with "measured and zero."
- The sparkline's 3-point minimum must actually suppress rendering below that threshold, not draw a misleading 1- or 2-point line.

---

## Task 1: TCV aggregate query

**Files:**
- Create: `orchestrator/internal/tcv/aggregate.go`
- Test: `orchestrator/internal/tcv/aggregate_test.go`

**Interfaces:**
- Consumes: `threat_clock_starts` and `threat_coverage_firsts` tables (already exist, written by `internal/tcv/clocks.go` and `internal/tcv/coverage.go`).
- Produces: `AggregateMetrics(ctx context.Context, pool *pgxpool.Pool) (TCVAggregate, error)` and `TCVAggregate{MedianSeconds *float64, P95Seconds *float64, SampleSize int}` — consumed by Task 8.

- [ ] **Step 1: Write the failing test**

This package's tests (`clocks_test.go`, `coverage_test.go`, `metrics_test.go`) call `sharedDB.Pool` directly with no per-test truncation wrapper — confirmed real convention, not `sharedDB.RunWithPool`. Since `AggregateMetrics` is a genuine cross-threat aggregate (not scoped to one threat_id like every existing test in this package), asserting an absolute `SampleSize == 0` would be test-order-dependent on a shared, un-truncated table. Use delta assertions instead — correct regardless of what other tests in this package have already written:

```go
package tcv

import (
	"context"
	"testing"
	"time"
)

func TestAggregateMetrics_OpenAndPreExistingDoNotChangeSampleSize(t *testing.T) {
	ctx := context.Background()
	before, err := AggregateMetrics(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("AggregateMetrics (before): %v", err)
	}
	now := time.Now()

	// Open: clock started, no coverage yet -- must be excluded.
	openThreat := seedThreat(t, "APT-aggregate-open")
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, openThreat, now.Add(-time.Hour), "sync-open"); err != nil {
		t.Fatal(err)
	}

	// PreExisting: coverage before the clock started -- must be excluded.
	preThreat := seedThreat(t, "APT-aggregate-preexisting")
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, preThreat, now, "sync-pre"); err != nil {
		t.Fatal(err)
	}
	preVID := seedContentVersion(t, "cv-aggregate-pre")
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, preThreat, RelationshipEmulates, preVID, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	after, err := AggregateMetrics(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("AggregateMetrics (after): %v", err)
	}
	if after.SampleSize != before.SampleSize {
		t.Fatalf("SampleSize changed from %d to %d after adding only an Open and a PreExisting threat -- neither must count", before.SampleSize, after.SampleSize)
	}
}

func TestAggregateMetrics_MeasuredThreatIncreasesSampleSizeByOne(t *testing.T) {
	ctx := context.Background()
	before, err := AggregateMetrics(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("AggregateMetrics (before): %v", err)
	}

	measuredThreat := seedThreat(t, "APT-aggregate-measured")
	start := time.Now().Add(-200 * time.Second)
	if err := RecordThreatClockStart(ctx, sharedDB.Pool, measuredThreat, start, "sync-measured"); err != nil {
		t.Fatal(err)
	}
	measuredVID := seedContentVersion(t, "cv-aggregate-measured")
	if err := RecordCoverageFirst(ctx, sharedDB.Pool, measuredThreat, RelationshipEmulates, measuredVID, start.Add(100*time.Second)); err != nil {
		t.Fatal(err)
	}

	after, err := AggregateMetrics(ctx, sharedDB.Pool)
	if err != nil {
		t.Fatalf("AggregateMetrics (after): %v", err)
	}
	if after.SampleSize != before.SampleSize+1 {
		t.Fatalf("SampleSize = %d, want %d (exactly one new Measured threat added)", after.SampleSize, before.SampleSize+1)
	}
	if after.MedianSeconds == nil {
		t.Fatal("MedianSeconds = nil, want a real value once at least one threat is Measured")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/tcv/... -run TestAggregateMetrics -v`
Expected: FAIL with `undefined: AggregateMetrics` (compile error — function does not exist yet).

- [ ] **Step 3: Write minimal implementation**

```go
package tcv

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TCVAggregate is the factory-wide threat-to-emulation TCV distribution
// (spec: docs/superpowers/specs/2026-10-13-tcf-phase11-factory-analytics-design.md).
// Scoped to ClockThreat/RelationshipEmulates only -- the canonical
// "threat-to-content velocity" the TCF pipeline names. SampleSize == 0
// means no threat has reached StateMeasured yet for this combination.
type TCVAggregate struct {
	MedianSeconds *float64
	P95Seconds    *float64
	SampleSize    int
}

// AggregateMetrics computes the median and P95 threat-to-emulation TCV
// across every threat currently in StateMeasured (clock started AND
// coverage recorded at or after the clock start -- the same condition
// Store.Metrics uses per-threat, here computed as one SQL aggregate
// instead of an N+1 loop over per-threat queries).
func AggregateMetrics(ctx context.Context, pool *pgxpool.Pool) (TCVAggregate, error) {
	var sampleSize int
	var median, p95 *float64
	err := pool.QueryRow(ctx, `
		SELECT
			count(*),
			percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (f.first_executable_at - s.started_at))),
			percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (f.first_executable_at - s.started_at)))
		FROM threat_clock_starts s
		JOIN threat_coverage_firsts f
			ON f.threat_id = s.threat_id AND f.relationship_kind = $1
		WHERE s.clock = $2 AND f.first_executable_at >= s.started_at`,
		RelationshipEmulates, ClockThreat,
	).Scan(&sampleSize, &median, &p95)
	if err != nil {
		return TCVAggregate{}, err
	}
	if sampleSize == 0 {
		return TCVAggregate{}, nil
	}
	return TCVAggregate{MedianSeconds: median, P95Seconds: p95, SampleSize: sampleSize}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/tcv/... -run TestAggregateMetrics -v`
Expected: PASS, both tests.

- [ ] **Step 5: Run the package's full suite**

Run: `go test ./internal/tcv/...`
Expected: `ok` — no regressions in the existing `clocks_test.go`/`coverage_test.go`/`metrics_test.go` tests.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/tcv/aggregate.go orchestrator/internal/tcv/aggregate_test.go
git commit -m "feat(tcf-phase11): factory-wide TCV aggregate (median/P95 threat-to-emulation)"
```

---

## Task 2: Core counts (threats processed, published content, source-to-technique coverage)

**Files:**
- Create: `orchestrator/internal/analytics/factory.go`
- Test: `orchestrator/internal/analytics/factory_test.go`

**Interfaces:**
- Consumes: `threats`, `content_versions`, `threat_techniques` tables.
- Produces: `DataState` (`DataMeasured`/`DataNoData`), `Metric{State DataState, Value *float64, Reason string}`, helpers `measured(v float64) Metric` / `noData(reason string) Metric`, and `coreCounts(ctx, pool, since time.Time) (CoreCounts, error)` with `CoreCounts{ThreatsProcessed, PublishedContent, SourceToTechniqueCoverage Metric}` — all consumed by Task 8's `FactoryHealth`.

- [ ] **Step 1: Write the failing test**

```go
package analytics

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoreCounts_ThreatsAndPublishedContent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		since := time.Now().Add(-24 * time.Hour)
		mustExec(t, pool, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title) VALUES ('t-core-1','actor','t-core-1','t-core-1','T1')`)
		mustExec(t, pool, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title) VALUES ('t-core-2','actor','t-core-2','t-core-2','T2')`)
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
		mustExec(t, pool, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title) VALUES ('t-cov-1','actor','t-cov-1','t-cov-1','T1')`)
		mustExec(t, pool, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title) VALUES ('t-cov-2','actor','t-cov-2','t-cov-2','T2')`)
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

func seedPublishedContentVersion(t *testing.T, pool *pgxpool.Pool, contentID string) {
	t.Helper()
	mustExec(t, pool, `INSERT INTO scenarios (scenario_id, origin) VALUES ($1, 'LOCAL') ON CONFLICT DO NOTHING`, contentID)
	mustExec(t, pool, `
		INSERT INTO content_versions (content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			trust_level, lifecycle, intake_source, schema_version, created_by)
		VALUES ($1, 'LOCAL', 1, 'sha-'||$1, 1, 'x', 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'custom', 1, 'migration:test')`,
		contentID)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/analytics/... -run TestCoreCounts -v`
Expected: FAIL with `undefined: coreCounts` / `undefined: DataMeasured` (compile error).

- [ ] **Step 3: Write minimal implementation**

```go
package analytics

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DataState is explicit per spec's NO_DATA discipline: every factory-health
// metric says whether it was actually measured, so a caller can never
// mistake "never measured" for "measured and zero."
type DataState string

const (
	DataMeasured DataState = "measured"
	DataNoData   DataState = "no_data"
)

// Metric is one measurement in the factory-health report. Value is nil
// whenever State is DataNoData.
type Metric struct {
	State  DataState `json:"state"`
	Value  *float64  `json:"value"`
	Reason string    `json:"reason,omitempty"`
}

func measured(v float64) Metric      { return Metric{State: DataMeasured, Value: &v} }
func noData(reason string) Metric    { return Metric{State: DataNoData, Reason: reason} }

// CoreCounts holds the three simplest factory-health metrics.
type CoreCounts struct {
	ThreatsProcessed          Metric
	PublishedContent          Metric
	SourceToTechniqueCoverage Metric
}

// coreCounts computes threats processed and published content -- plain
// counts, where zero is itself a real measured answer -- plus
// source-to-technique mapping coverage, a ratio that is NO_DATA when its
// denominator (threats in the window) is zero.
func coreCounts(ctx context.Context, pool *pgxpool.Pool, since time.Time) (CoreCounts, error) {
	var threatsProcessed int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM threats WHERE created_at >= $1`, since).Scan(&threatsProcessed); err != nil {
		return CoreCounts{}, err
	}

	var publishedContent int
	if err := pool.QueryRow(ctx, `SELECT count(DISTINCT id) FROM content_versions WHERE lifecycle IN ('PUBLISHED','PUBLISHED_LOCAL')`).Scan(&publishedContent); err != nil {
		return CoreCounts{}, err
	}

	var withTechniques int
	if err := pool.QueryRow(ctx, `
		SELECT count(DISTINCT t.id) FROM threats t
		JOIN threat_techniques tt ON tt.threat_id = t.id
		WHERE t.created_at >= $1`, since).Scan(&withTechniques); err != nil {
		return CoreCounts{}, err
	}

	coverage := noData("no threats recorded in the selected window")
	if threatsProcessed > 0 {
		coverage = measured(float64(withTechniques) / float64(threatsProcessed))
	}

	return CoreCounts{
		ThreatsProcessed:          measured(float64(threatsProcessed)),
		PublishedContent:          measured(float64(publishedContent)),
		SourceToTechniqueCoverage: coverage,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/analytics/... -run TestCoreCounts -v`
Expected: PASS, all 3 tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/factory.go orchestrator/internal/analytics/factory_test.go
git commit -m "feat(tcf-phase11): core factory-health counts (threats, published content, technique coverage)"
```

---

## Task 3: Static validation pass rate

**Files:**
- Modify: `orchestrator/internal/analytics/factory.go`
- Modify: `orchestrator/internal/analytics/factory_test.go`

**Interfaces:**
- Consumes: `content_validations` table, `Metric`/`measured`/`noData` from Task 2.
- Produces: `staticValidationPassRate(ctx, pool, since time.Time) (Metric, error)` — consumed by Task 8.

- [ ] **Step 1: Write the failing test**

```go
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
		mustExec(t, pool, `INSERT INTO content_validations (content_version_id, level, outcome, validator, validator_version, run_id) VALUES ($1,'EXECUTION','PASS','test','1',NULL)`, vid)

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
```

Note: `seedPublishedContentVersion` from Task 2 must return the created version's id. Update its signature now (Task 2's helper is modified here since Task 3 is the first caller that needs the id back):

```go
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
```

And Task 2's own test call site becomes `seedPublishedContentVersion(t, pool, "cv-core-1")` (return value unused there — fine, Go allows discarding a single return value by just not assigning it).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/analytics/... -run TestStaticValidationPassRate -v`
Expected: FAIL with `undefined: staticValidationPassRate` (compile error).

- [ ] **Step 3: Write minimal implementation**

```go
// staticValidationPassRate is the pass rate among STRUCTURAL/STATIC
// content_validations rows only -- the only validation level with real
// data today (spec: Phase 6 doesn't exist yet). Labeled explicitly as
// "static" everywhere it surfaces, never implying execution or detection
// validation occurred. NO_DATA and NOT_APPLICABLE outcomes are excluded
// from both numerator and denominator -- they are neither a pass nor a
// fail.
func staticValidationPassRate(ctx context.Context, pool *pgxpool.Pool, since time.Time) (Metric, error) {
	var total, passed int
	err := pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE outcome IN ('PASS','FAIL','ERROR')),
			count(*) FILTER (WHERE outcome = 'PASS')
		FROM content_validations
		WHERE level IN ('STRUCTURAL','STATIC') AND created_at >= $1`, since,
	).Scan(&total, &passed)
	if err != nil {
		return Metric{}, err
	}
	if total == 0 {
		return noData("no STRUCTURAL/STATIC validations ran in the selected window"), nil
	}
	return measured(float64(passed) / float64(total)), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/analytics/... -run 'TestStaticValidationPassRate|TestCoreCounts' -v`
Expected: PASS, all tests (both Task 2's and Task 3's).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/factory.go orchestrator/internal/analytics/factory_test.go
git commit -m "feat(tcf-phase11): static validation pass rate metric, labeled by validation level"
```

---

## Task 4: Duplicate-generation rate (always NO_DATA)

**Files:**
- Modify: `orchestrator/internal/analytics/factory.go`
- Modify: `orchestrator/internal/analytics/factory_test.go`

**Interfaces:**
- Consumes: nothing (deliberately — see Global Constraints).
- Produces: `duplicateGenerationRate() Metric` — consumed by Task 8.

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/analytics/... -run TestDuplicateGenerationRate -v`
Expected: FAIL with `undefined: duplicateGenerationRate` (compile error).

- [ ] **Step 3: Write minimal implementation**

```go
// duplicateGenerationRate is always NO_DATA in this phase. Generation
// attempts happen (Scheduler.sync calls Generator.Write on every poll,
// idempotent via content_versions' dedup) but their outcomes are only
// logged to stdout and an in-memory, process-lifetime counter -- never
// persisted. Persisting a per-attempt log is Phase 9's deliverable, not
// this phase's; adding it here would be new write-path infrastructure
// this phase deliberately excludes.
func duplicateGenerationRate() Metric {
	return noData("generation-attempt telemetry is not yet persisted (tracked for Phase 9)")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/analytics/... -run TestDuplicateGenerationRate -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/factory.go orchestrator/internal/analytics/factory_test.go
git commit -m "feat(tcf-phase11): duplicate-generation rate as explicit NO_DATA (Phase 9 dependency)"
```

---

## Task 5: Ingestion and evidence health

**Files:**
- Modify: `orchestrator/internal/analytics/factory.go`
- Modify: `orchestrator/internal/analytics/factory_test.go`

**Interfaces:**
- Consumes: `source_instances`, `source_syncs`, `actor_resolution_candidates` tables.
- Produces: `IngestionHealth{Sources []SourceHealth, UnresolvedCandidates int}`, `SourceHealth{SourceInstanceID, DisplayName string, LastSuccessAt *time.Time, FailuresInWindow int, LastDiagnostic string}`, `ingestionHealth(ctx, pool, since time.Time) (IngestionHealth, error)` — consumed by Task 8.

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/analytics/... -run TestIngestionHealth -v`
Expected: FAIL with `undefined: ingestionHealth` (compile error).

- [ ] **Step 3: Write minimal implementation**

```go
// SourceHealth is one source instance's ingestion health. LastSuccessAt
// is nil when the source has never once synced successfully -- this is
// deliberately distinct from a non-nil-but-old timestamp (stale), which
// dataQuality (Task 6) reports separately.
type SourceHealth struct {
	SourceInstanceID string     `json:"sourceInstanceId"`
	DisplayName      string     `json:"displayName"`
	LastSuccessAt    *time.Time `json:"lastSuccessAt"`
	FailuresInWindow int        `json:"failuresInWindow"`
	LastDiagnostic   string     `json:"lastDiagnostic,omitempty"`
}

type IngestionHealth struct {
	Sources              []SourceHealth `json:"sources"`
	UnresolvedCandidates int            `json:"unresolvedCandidates"`
}

func ingestionHealth(ctx context.Context, pool *pgxpool.Pool, since time.Time) (IngestionHealth, error) {
	rows, err := pool.Query(ctx, `
		SELECT
			si.id, si.display_name,
			(SELECT max(completed_at) FROM source_syncs WHERE source_instance_id = si.id AND status = 'succeeded'),
			(SELECT count(*) FROM source_syncs WHERE source_instance_id = si.id AND status = 'failed' AND started_at >= $1),
			(SELECT diagnostic FROM source_syncs WHERE source_instance_id = si.id AND status = 'failed' ORDER BY started_at DESC LIMIT 1)
		FROM source_instances si
		ORDER BY si.id`, since)
	if err != nil {
		return IngestionHealth{}, err
	}
	defer rows.Close()

	var sources []SourceHealth
	for rows.Next() {
		var s SourceHealth
		var diagnostic *string
		if err := rows.Scan(&s.SourceInstanceID, &s.DisplayName, &s.LastSuccessAt, &s.FailuresInWindow, &diagnostic); err != nil {
			return IngestionHealth{}, err
		}
		if diagnostic != nil {
			s.LastDiagnostic = *diagnostic
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		return IngestionHealth{}, err
	}

	var unresolved int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM actor_resolution_candidates WHERE status = 'unresolved'`).Scan(&unresolved); err != nil {
		return IngestionHealth{}, err
	}

	return IngestionHealth{Sources: sources, UnresolvedCandidates: unresolved}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/analytics/... -run TestIngestionHealth -v`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/factory.go orchestrator/internal/analytics/factory_test.go
git commit -m "feat(tcf-phase11): ingestion/evidence health metrics (per-source sync status, unresolved candidates)"
```

---

## Task 6: Content lifecycle funnel and data quality

**Files:**
- Modify: `orchestrator/internal/analytics/factory.go`
- Modify: `orchestrator/internal/analytics/factory_test.go`

**Interfaces:**
- Consumes: `content_versions`, `source_instances`, `source_syncs`, `content_version_events` tables.
- Produces: `LifecycleFunnel{Candidate, Validated, Published, Rejected int}`, `lifecycleFunnel(ctx, pool) (LifecycleFunnel, error)`; `DataQuality{StaleSources []string, StaleValidations int}`, `dataQuality(ctx, pool, staleAfter time.Duration) (DataQuality, error)` — both consumed by Task 8.

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/analytics/... -run 'TestLifecycleFunnel|TestDataQuality' -v`
Expected: FAIL with `undefined: lifecycleFunnel` (compile error).

- [ ] **Step 3: Write minimal implementation**

```go
type LifecycleFunnel struct {
	Candidate int `json:"candidate"`
	Validated int `json:"validated"`
	Published int `json:"published"`
	Rejected  int `json:"rejected"`
}

// lifecycleFunnel buckets every content_versions row by its current,
// real, distinct lifecycle state -- no inference, no ambiguity between
// "candidate" and "rejected" (spec: these are unambiguous CHECK-constrained
// states, confirmed against internal/contentregistry/lifecycle.go).
func lifecycleFunnel(ctx context.Context, pool *pgxpool.Pool) (LifecycleFunnel, error) {
	var f LifecycleFunnel
	err := pool.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE lifecycle IN ('DRAFT','VALIDATING')),
			count(*) FILTER (WHERE lifecycle = 'VALIDATED'),
			count(*) FILTER (WHERE lifecycle IN ('PUBLISHED','PUBLISHED_LOCAL')),
			count(*) FILTER (WHERE lifecycle = 'REJECTED')
		FROM content_versions`).Scan(&f.Candidate, &f.Validated, &f.Published, &f.Rejected)
	return f, err
}

// DataQuality surfaces signals that undermine trust in the other metrics:
// sources that have gone quiet, and content stuck mid-validation.
type DataQuality struct {
	StaleSources     []string `json:"staleSources"`
	StaleValidations int      `json:"staleValidations"`
}

// dataQuality reports sources with no successful sync in staleAfter (this
// also catches a source that has NEVER synced successfully -- NOT EXISTS
// is true for both cases, and surfacing a never-synced source as "stale"
// here is correct: it IS stale, just maximally so; ingestionHealth (Task
// 5) is where the never-vs-stale distinction is reported precisely), and
// content_versions stuck in VALIDATING whose transition into that state
// happened more than staleAfter ago.
func dataQuality(ctx context.Context, pool *pgxpool.Pool, staleAfter time.Duration) (DataQuality, error) {
	cutoff := time.Now().Add(-staleAfter)

	rows, err := pool.Query(ctx, `
		SELECT si.display_name FROM source_instances si
		WHERE NOT EXISTS (
			SELECT 1 FROM source_syncs ss
			WHERE ss.source_instance_id = si.id AND ss.status = 'succeeded' AND ss.completed_at >= $1
		)
		ORDER BY si.id`, cutoff)
	if err != nil {
		return DataQuality{}, err
	}
	defer rows.Close()
	var staleSources []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return DataQuality{}, err
		}
		staleSources = append(staleSources, name)
	}
	if err := rows.Err(); err != nil {
		return DataQuality{}, err
	}

	var staleValidations int
	err = pool.QueryRow(ctx, `
		SELECT count(*) FROM content_versions cv
		WHERE cv.lifecycle = 'VALIDATING'
		AND EXISTS (
			SELECT 1 FROM content_version_events e
			WHERE e.content_version_id = cv.id AND e.to_lifecycle = 'VALIDATING' AND e.at < $1
		)`, cutoff).Scan(&staleValidations)
	if err != nil {
		return DataQuality{}, err
	}

	return DataQuality{StaleSources: staleSources, StaleValidations: staleValidations}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/analytics/... -run 'TestLifecycleFunnel|TestDataQuality' -v`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/factory.go orchestrator/internal/analytics/factory_test.go
git commit -m "feat(tcf-phase11): content lifecycle funnel and data-quality signals (stale sources, stuck validations)"
```

---

## Task 7: Historical trends

**Files:**
- Modify: `orchestrator/internal/analytics/factory.go`
- Modify: `orchestrator/internal/analytics/factory_test.go`

**Interfaces:**
- Consumes: `threats`, `threat_clock_starts`, `threat_coverage_firsts` tables.
- Produces: `TrendPoint{Day time.Time, Value float64}`, `Trends{ThreatsProcessedByDay, TCVByDay []TrendPoint}`, `threatsProcessedTrend(ctx, pool, since time.Time) ([]TrendPoint, error)`, `tcvTrend(ctx, pool, since time.Time) ([]TrendPoint, error)`, constant `minTrendPoints = 3` — all consumed by Task 8.

- [ ] **Step 1: Write the failing test**

```go
func TestThreatsProcessedTrend_BelowMinimumReturnsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title, created_at) VALUES ('t-trend-1','actor','t-trend-1','t-trend-1','T1', now())`)

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
		for i, day := range []string{"-3 days", "-2 days", "-1 days"} {
			mustExec(t, pool, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title, created_at)
				VALUES ($1,'actor',$1,$1,'T', now() + interval '`+day+`')`, "t-trend-pts-"+string(rune('a'+i)))
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/analytics/... -run TestThreatsProcessedTrend -v`
Expected: FAIL with `undefined: threatsProcessedTrend` (compile error).

- [ ] **Step 3: Write minimal implementation**

```go
// minTrendPoints is the smallest number of real data points the UI will
// draw as a trend line. Below this, a line would misleadingly imply more
// history than exists -- the UI shows an empty state instead (spec).
const minTrendPoints = 3

type TrendPoint struct {
	Day   time.Time `json:"day"`
	Value float64   `json:"value"`
}

type Trends struct {
	ThreatsProcessedByDay []TrendPoint `json:"threatsProcessedByDay"`
	TCVByDay              []TrendPoint `json:"tcvByDay"`
}

func threatsProcessedTrend(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]TrendPoint, error) {
	rows, err := pool.Query(ctx, `
		SELECT date_trunc('day', created_at), count(*)
		FROM threats WHERE created_at >= $1
		GROUP BY 1 ORDER BY 1`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []TrendPoint
	for rows.Next() {
		var p TrendPoint
		var n int
		if err := rows.Scan(&p.Day, &n); err != nil {
			return nil, err
		}
		p.Value = float64(n)
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(points) < minTrendPoints {
		return nil, nil
	}
	return points, nil
}

// tcvTrend averages threat-to-emulation TCV (seconds) by the day coverage
// first became executable, scoped to the same ClockThreat/RelationshipEmulates
// combination as AggregateMetrics (Task 1).
func tcvTrend(ctx context.Context, pool *pgxpool.Pool, since time.Time) ([]TrendPoint, error) {
	rows, err := pool.Query(ctx, `
		SELECT date_trunc('day', f.first_executable_at), avg(EXTRACT(EPOCH FROM (f.first_executable_at - s.started_at)))
		FROM threat_clock_starts s
		JOIN threat_coverage_firsts f ON f.threat_id = s.threat_id AND f.relationship_kind = 'emulates'
		WHERE s.clock = 'threat' AND f.first_executable_at >= s.started_at AND f.first_executable_at >= $1
		GROUP BY 1 ORDER BY 1`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []TrendPoint
	for rows.Next() {
		var p TrendPoint
		if err := rows.Scan(&p.Day, &p.Value); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(points) < minTrendPoints {
		return nil, nil
	}
	return points, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/analytics/... -run TestThreatsProcessedTrend -v`
Expected: PASS, both tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/analytics/factory.go orchestrator/internal/analytics/factory_test.go
git commit -m "feat(tcf-phase11): historical trend queries (threats processed, TCV) with a 3-point minimum"
```

---

## Task 8: Top-level FactoryHealth aggregator

**Files:**
- Modify: `orchestrator/internal/analytics/factory.go`
- Modify: `orchestrator/internal/analytics/factory_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1-7 (`coreCounts`, `staticValidationPassRate`, `duplicateGenerationRate`, `ingestionHealth`, `lifecycleFunnel`, `dataQuality`, `threatsProcessedTrend`, `tcvTrend`, `tcv.AggregateMetrics`).
- Produces: `PipelineStatus{Ingestion IngestionHealth, Funnel LifecycleFunnel, DataQuality DataQuality}`, `FactoryHealthReport{...}`, `FactoryHealth(ctx, pool, window time.Duration) (FactoryHealthReport, error)` — consumed by Task 9's handler.

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/analytics/... -run TestFactoryHealth_Assembles -v`
Expected: FAIL with `undefined: FactoryHealth` (compile error).

- [ ] **Step 3: Write minimal implementation**

```go
import "github.com/audspect/bas/internal/tcv"

type PipelineStatus struct {
	Ingestion   IngestionHealth `json:"ingestion"`
	Funnel      LifecycleFunnel `json:"funnel"`
	DataQuality DataQuality     `json:"dataQuality"`
}

// FactoryHealthReport is the full GET /api/analytics/factory-health
// response (spec: docs/superpowers/specs/2026-10-13-tcf-phase11-factory-analytics-design.md).
type FactoryHealthReport struct {
	WindowSince               time.Time      `json:"windowSince"`
	ThreatsProcessed          Metric         `json:"threatsProcessed"`
	PublishedContent          Metric         `json:"publishedContent"`
	MedianThreatToContentTCV  Metric         `json:"medianThreatToContentTcv"`
	P95ThreatToContentTCV     Metric         `json:"p95ThreatToContentTcv"`
	StaticValidationPassRate  Metric         `json:"staticValidationPassRate"`
	DuplicateGenerationRate   Metric         `json:"duplicateGenerationRate"`
	SourceToTechniqueCoverage Metric         `json:"sourceToTechniqueCoverage"`
	Pipeline                  PipelineStatus `json:"pipeline"`
	Trends                    Trends         `json:"trends"`
}

const staleAfter = 7 * 24 * time.Hour

// FactoryHealth assembles every factory-health metric for the trailing
// window. window is the lookback used by count/rate metrics and the
// trend queries; staleAfter (the data-quality staleness threshold) is
// fixed separately at 7 days regardless of window.
func FactoryHealth(ctx context.Context, pool *pgxpool.Pool, window time.Duration) (FactoryHealthReport, error) {
	since := time.Now().Add(-window)

	counts, err := coreCounts(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	passRate, err := staticValidationPassRate(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	ingestion, err := ingestionHealth(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	funnel, err := lifecycleFunnel(ctx, pool)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	dq, err := dataQuality(ctx, pool, staleAfter)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	threatsTrend, err := threatsProcessedTrend(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	tcvTrendPts, err := tcvTrend(ctx, pool, since)
	if err != nil {
		return FactoryHealthReport{}, err
	}
	tcvAgg, err := tcv.AggregateMetrics(ctx, pool)
	if err != nil {
		return FactoryHealthReport{}, err
	}

	median := noData("no threats have measured threat-to-emulation TCV yet")
	p95 := noData("no threats have measured threat-to-emulation TCV yet")
	if tcvAgg.SampleSize > 0 {
		median = measured(*tcvAgg.MedianSeconds)
		p95 = measured(*tcvAgg.P95Seconds)
	}

	return FactoryHealthReport{
		WindowSince:               since,
		ThreatsProcessed:          counts.ThreatsProcessed,
		PublishedContent:          counts.PublishedContent,
		MedianThreatToContentTCV:  median,
		P95ThreatToContentTCV:     p95,
		StaticValidationPassRate:  passRate,
		DuplicateGenerationRate:   duplicateGenerationRate(),
		SourceToTechniqueCoverage: counts.SourceToTechniqueCoverage,
		Pipeline:                  PipelineStatus{Ingestion: ingestion, Funnel: funnel, DataQuality: dq},
		Trends:                    Trends{ThreatsProcessedByDay: threatsTrend, TCVByDay: tcvTrendPts},
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/analytics/... -run TestFactoryHealth_Assembles -v`
Expected: PASS.

- [ ] **Step 5: Run the package's full suite**

Run: `go test ./internal/analytics/...`
Expected: `ok` — no regressions in `campaigns_test.go`/`compliance_test.go`/`detection_test.go`/`endpoint_test.go`/`exposure_test.go`/`ioc_test.go`/`risk_test.go`/`threatintel_test.go`.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/analytics/factory.go orchestrator/internal/analytics/factory_test.go
git commit -m "feat(tcf-phase11): FactoryHealth aggregator assembling all factory-health metrics"
```

---

## Task 9: API handler, route, and RBAC matrix entry

**Files:**
- Modify: `orchestrator/internal/api/ti_handlers.go` (add the handler next to `GetThreatIntelSummary`)
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`
- Create: `orchestrator/internal/api/factory_health_handler_test.go`

**Interfaces:**
- Consumes: `analytics.FactoryHealth` from Task 8.
- Produces: `(*Handler).GetFactoryHealth(w, r)`, route `GET /api/analytics/factory-health` — consumed by Task 10's frontend.

- [ ] **Step 1: Write the failing test**

This endpoint is `tierAny` with no role-based middleware in a direct handler call, matching its sibling's own test exactly (`internal/api/threatintel_summary_handler_test.go`, confirmed real pattern — `New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")`, no `withRole` needed):

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func TestGetFactoryHealth_ReturnsNoDataMetricsOnFreshDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		rec := httptest.NewRecorder()
		h.GetFactoryHealth(rec, httptest.NewRequest(http.MethodGet, "/api/analytics/factory-health", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		dup, ok := got["duplicateGenerationRate"].(map[string]any)
		if !ok || dup["state"] != "no_data" {
			t.Fatalf("duplicateGenerationRate = %v, want state=no_data", got["duplicateGenerationRate"])
		}
	})
}
```

Put this in a new file `internal/api/factory_health_handler_test.go` (mirroring `threatintel_summary_handler_test.go`'s own file-per-handler convention), not appended into `ti_handlers_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/... -run TestGetFactoryHealth -v`
Expected: FAIL with `undefined: h.GetFactoryHealth` (compile error).

- [ ] **Step 3: Write minimal implementation**

In `ti_handlers.go`, right after `GetThreatIntelSummary`:

```go
// GET /api/analytics/factory-health — read-only TCF pipeline health:
// content throughput, threat-to-content velocity, validation pass rate,
// ingestion health, lifecycle funnel, data quality. Viewer+. Optional
// ?days=N query param sets the lookback window (default 30).
func (h *Handler) GetFactoryHealth(w http.ResponseWriter, r *http.Request) {
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	result, err := analytics.FactoryHealth(r.Context(), h.db, time.Duration(days)*24*time.Hour)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, result)
}
```

(If `ti_handlers.go` doesn't already import `"strconv"` and `"time"`, add them to its import block — check first, since other handlers in this file may already import one or both.)

In `routes.go`, immediately after the `threat-intel-summary` line:

```go
r.Get("/api/analytics/threat-intel-summary", h.GetThreatIntelSummary)
r.Get("/api/analytics/factory-health", h.GetFactoryHealth)
```

In `rbac_matrix_test.go`'s `routeMatrix`, immediately after the `threat-intel-summary` entry:

```go
{http.MethodGet, "/api/analytics/threat-intel-summary", tierAny, ""},
{http.MethodGet, "/api/analytics/factory-health", tierAny, ""},
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/... -run TestGetFactoryHealth -v`
Expected: PASS.

- [ ] **Step 5: Run the RBAC drift test**

Run: `go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: the new route is not flagged (it will still fail on the pre-existing, out-of-scope `POST /api/intel/sources/{id}/trust` gap from Phase 2B — that is a known, already-ledgered issue, not something this task introduces or fixes).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/ti_handlers.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/factory_health_handler_test.go
git commit -m "feat(tcf-phase11): GET /api/analytics/factory-health endpoint and RBAC matrix entry"
```

---

## Task 10: Frontend — Factory Health dashboard page

**Files:**
- Create: `orchestrator/web/src/features/factory-health.js`
- Modify: `orchestrator/web/src/features/shell.js` (import + `showTab` dispatch)
- Modify: `orchestrator/web/index.html` (nav item + tab container)
- Test: `orchestrator/web/tests/unit/factory-health.test.mjs`

**Interfaces:**
- Consumes: `GET /api/analytics/factory-health` (Task 9), `apicall` from `../core/api.js`, `x` from `../core/escape.js`.
- Produces: `loadFactoryHealth()`, exported for `shell.js` to call on tab activation.

- [ ] **Step 1: Write the failing test**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

function fresh(html = '') {
  const dom = new JSDOM(`<!DOCTYPE html><body>${html}</body>`, { url: 'http://127.0.0.1/' });
  global.document = dom.window.document;
  return dom.window;
}

test('metricTile renders a NO_DATA tile distinctly from a measured tile', async () => {
  fresh();
  const { metricTile } = await import('../../src/features/factory-health.js');
  const measuredHtml = metricTile('Threats Processed', { state: 'measured', value: 5 }, (v) => String(v));
  const noDataHtml = metricTile('Duplicate Generation Rate', { state: 'no_data', reason: 'not persisted yet' }, (v) => String(v));
  assert.ok(measuredHtml.includes('5'), 'measured tile shows the real value');
  assert.ok(!measuredHtml.includes('NO DATA'), 'measured tile must not say NO DATA');
  assert.ok(noDataHtml.includes('NO DATA'), 'no_data tile must say so, not show a blank or zero');
  assert.ok(noDataHtml.includes('not persisted yet'), 'no_data tile explains why');
  assert.notEqual(measuredHtml, noDataHtml);
});

test('renderSparkline shows an empty state below 3 points, a polyline at or above', async () => {
  const win = fresh('<div id="spark"></div>');
  const { renderSparkline } = await import('../../src/features/factory-health.js');

  renderSparkline('spark', [{ day: '2026-01-01', value: 1 }, { day: '2026-01-02', value: 2 }]);
  assert.ok(!win.document.getElementById('spark').innerHTML.includes('<svg'), '2 points must not render a polyline');

  renderSparkline('spark', [{ day: '2026-01-01', value: 1 }, { day: '2026-01-02', value: 2 }, { day: '2026-01-03', value: 3 }]);
  assert.ok(win.document.getElementById('spark').innerHTML.includes('<polyline'), '3 points must render a polyline');

  renderSparkline('spark', null);
  assert.ok(!win.document.getElementById('spark').innerHTML.includes('<svg'), 'null/empty trend must not render a polyline');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test "tests/unit/factory-health.test.mjs"` (from `orchestrator/web/`)
Expected: FAIL — `factory-health.js` does not exist yet (module not found).

- [ ] **Step 3: Write minimal implementation**

`orchestrator/web/src/features/factory-health.js`:

```js
import { apicall } from '../core/api.js';
import { x } from '../core/escape.js';

var _loaded = false;

export function loadFactoryHealth() {
  apicall('/api/analytics/factory-health').then(function(r) {
    _loaded = true;
    renderFactoryHealthTiles(r);
    renderFactoryHealthFunnel(r);
    renderFactoryHealthDataQuality(r);
    renderFactoryHealthTrends(r);
  });
}

export function metricTile(label, metric, formatter) {
  if (metric.state === 'no_data') {
    return '<div class="kpi-card stat-tile" title="' + x(metric.reason || 'No data yet') + '">' +
      '<div class="kpi-label">' + x(label) + '</div>' +
      '<div class="kpi-value" style="color:var(--muted)">NO DATA</div>' +
      '<div class="kpi-sub">' + x(metric.reason || '') + '</div></div>';
  }
  return '<div class="kpi-card stat-tile">' +
    '<div class="kpi-label">' + x(label) + '</div>' +
    '<div class="kpi-value">' + x(formatter(metric.value)) + '</div></div>';
}

function formatCount(v) { return String(v); }
function formatDuration(seconds) { return (seconds / 86400).toFixed(1) + 'd'; }
function formatPercent(fraction) { return (fraction * 100).toFixed(0) + '%'; }

function renderFactoryHealthTiles(r) {
  var el = document.getElementById('factory-health-tiles');
  if (!el) return;
  el.innerHTML =
    metricTile('Threats Processed', r.threatsProcessed, formatCount) +
    metricTile('Published Content', r.publishedContent, formatCount) +
    metricTile('Median Threat→Content TCV', r.medianThreatToContentTcv, formatDuration) +
    metricTile('Static Validation Pass Rate', r.staticValidationPassRate, formatPercent) +
    metricTile('Duplicate Generation Rate', r.duplicateGenerationRate, formatPercent) +
    metricTile('Source→Technique Coverage', r.sourceToTechniqueCoverage, formatPercent);
}

function renderFactoryHealthFunnel(r) {
  var el = document.getElementById('factory-health-funnel');
  if (!el) return;
  var f = r.pipeline.funnel;
  el.innerHTML =
    '<div class="kpi-card stat-tile"><div class="kpi-label">Candidate</div><div class="kpi-value">' + f.candidate + '</div></div>' +
    '<div class="kpi-card stat-tile"><div class="kpi-label">Validated</div><div class="kpi-value">' + f.validated + '</div></div>' +
    '<div class="kpi-card stat-tile"><div class="kpi-label">Published</div><div class="kpi-value">' + f.published + '</div></div>' +
    '<div class="kpi-card stat-tile"><div class="kpi-label">Rejected</div><div class="kpi-value">' + f.rejected + '</div></div>';
}

function renderFactoryHealthDataQuality(r) {
  var el = document.getElementById('factory-health-dataquality');
  if (!el) return;
  var dq = r.pipeline.dataQuality;
  var stale = (dq.staleSources || []).length ?
    'Stale sources: ' + dq.staleSources.map(x).join(', ') : 'No stale sources';
  el.innerHTML = '<div class="kpi-sub">' + x(stale) + ' &middot; ' + dq.staleValidations + ' stuck in validation</div>';
}

function renderFactoryHealthTrends(r) {
  renderSparkline('factory-health-threats-trend', r.trends.threatsProcessedByDay);
  renderSparkline('factory-health-tcv-trend', r.trends.tcvByDay);
}

// renderSparkline draws an inline SVG polyline, matching the existing
// attack-path.js/evidence.js convention -- no charting library. Below
// minTrendPoints (kept in sync with the backend's own threshold), it
// shows an honest empty state instead of a misleading short line.
var minTrendPoints = 3;
export function renderSparkline(elementId, points) {
  var el = document.getElementById(elementId);
  if (!el) return;
  if (!points || points.length < minTrendPoints) {
    el.innerHTML = '<div class="kpi-sub" style="color:var(--muted)">Not enough history yet</div>';
    return;
  }
  var w = 240, h = 48, pad = 4;
  var values = points.map(function(p) { return p.value; });
  var min = Math.min.apply(null, values);
  var max = Math.max.apply(null, values);
  var range = max - min || 1;
  var step = (w - pad * 2) / (points.length - 1);
  var coords = values.map(function(v, i) {
    var cx = pad + i * step;
    var cy = h - pad - ((v - min) / range) * (h - pad * 2);
    return cx.toFixed(1) + ',' + cy.toFixed(1);
  }).join(' ');
  el.innerHTML = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
    '<polyline points="' + coords + '" fill="none" stroke="var(--accent)" stroke-width="2"/></svg>';
}
```

Add to `shell.js`'s import block:

```js
import { loadFactoryHealth } from './factory-health.js';
```

Add to `shell.js`'s `showTab`, next to the other `if (name === '...')` lines:

```js
if (name === 'factory-health') loadFactoryHealth();
```

Add to `index.html`'s nav list, next to the `campaigns` nav item:

```html
<div class="nav-item" data-tab="factory-health" title="Factory Health" data-on-click="showTab" data-args="[&quot;factory-health&quot;]">Factory Health</div>
```

Add to `index.html`'s tab containers, next to `tab-campaigns`:

```html
<div id="tab-factory-health" style="display:none">
  <div id="factory-health-tiles" class="kpi-row"></div>
  <div id="factory-health-funnel" class="kpi-row"></div>
  <div id="factory-health-dataquality"></div>
  <div id="factory-health-threats-trend"></div>
  <div id="factory-health-tcv-trend"></div>
</div>
```

`kpi-row` is the real wrapper class, confirmed at `index.html`'s `dash-ti-tiles` container (the KEV widget's own tile row).

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test "tests/unit/factory-health.test.mjs"` (from `orchestrator/web/`)
Expected: PASS, both tests.

- [ ] **Step 5: Run the frontend's full unit suite**

Run: `npm test` (from `orchestrator/web/`)
Expected: all existing `.test.mjs` files plus this new one pass — no regressions.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/web/src/features/factory-health.js orchestrator/web/src/features/shell.js orchestrator/web/index.html orchestrator/web/tests/unit/factory-health.test.mjs
git commit -m "feat(tcf-phase11): Factory Health dashboard page (tiles, funnel, data quality, SVG trend sparklines)"
```

---

## Final verification (after all 10 tasks)

Run the full suite across every touched package, plus the frontend:

```bash
cd orchestrator
go build ./...
go test ./internal/tcv/... ./internal/analytics/... ./internal/api/... -run 'TestAggregateMetrics|TestCoreCounts|TestStaticValidationPassRate|TestDuplicateGenerationRate|TestIngestionHealth|TestLifecycleFunnel|TestDataQuality|TestThreatsProcessedTrend|TestFactoryHealth|TestGetFactoryHealth|TestRBACMatrix' -v
cd web && npm test
```

Then follow executing-plans' Final Review step: dispatch a fresh whole-branch review (most capable available model) with this plan's Review Focus section verbatim, re-grade findings by effect, fix Critical/Important in one pass, ledger Minor as deferred, then `superpowers:finishing-a-development-branch`.
