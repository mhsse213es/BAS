# Phase 6, Subsystem 1 — Executive Dashboards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fleet-wide, time-series executive dashboard — daily snapshots of average risk score, exposure score, and detection-coverage score, persisted and rendered as trend charts in a new UI tab.

**Architecture:** A new pure-aggregator package `internal/dashboard` computes today's fleet-wide scores from the already-shipped `exposure.Build`/`pathcorrelation.Correlate`/`scenario_runs` machinery. A background scheduler (copying `internal/detect.StartRetention`'s ticker+upsert+prune shape) persists one row per day into a new `dashboard_snapshots` table. Two new read-only API endpoints expose live-current and stored-trend data. A new "Executive Dashboard" tab renders three KPI cards with hand-rolled inline-SVG sparklines (no charting library, no CDN).

**Tech Stack:** Go, PostgreSQL (pgx/v5), chi router, vanilla JS/inline SVG (no build step, no external dependencies).

## Global Constraints

- No external charting library or CDN — this is a fully offline/air-gapped platform. Sparklines are hand-rolled `<svg><polyline>`.
- `orchestrator/wwwroot/index.html` and `orchestrator/cmd/server/wwwroot/index.html` are the same file via an NTFS hardlink but tracked as two separate git paths — edit and `git add` both in every UI-touching commit.
- All new DB schema changes are additive (`CREATE TABLE IF NOT EXISTS`) — no destructive migrations.
- Read-only endpoints in this slice are Viewer+ (same RBAC group as `/api/exposure/assets`, `/api/attackpath/correlation`).
- Docker Desktop must be running for any test in this plan marked "Docker-backed" (`testutil.MustSharedTestDB()`).

---

### Task 1: `dashboard_snapshots` table

**Files:**
- Modify: `orchestrator/internal/db/postgres.go:866` (insert immediately after the `openaev_config` table block, before the closing `}` of the `stmts` slice)

**Interfaces:**
- Produces: table `dashboard_snapshots(id, snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count, created_at)` with `UNIQUE(snapshot_date)`, consumed by Tasks 2–4.

- [ ] **Step 1: Add the table to `EnsureSchema`**

In `orchestrator/internal/db/postgres.go`, find this exact block (currently the last entry in the `stmts` slice, right before the closing `}`):

```go
		`CREATE TABLE IF NOT EXISTS openaev_config (
			id                  int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			base_url            text        NOT NULL DEFAULT '',
			bearer_token        text        NOT NULL DEFAULT '',
			poll_interval_hours int         NOT NULL DEFAULT 24,
			enabled             boolean     NOT NULL DEFAULT false,
			last_sync_at        timestamptz,
			last_sync_status    text        NOT NULL DEFAULT 'never',
			last_error          text        NOT NULL DEFAULT '',
			updated_at          timestamptz NOT NULL DEFAULT NOW()
		)`,
	}
```

Replace it with (adding the new table right after `openaev_config`, still before the closing `}`):

```go
		`CREATE TABLE IF NOT EXISTS openaev_config (
			id                  int         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
			base_url            text        NOT NULL DEFAULT '',
			bearer_token        text        NOT NULL DEFAULT '',
			poll_interval_hours int         NOT NULL DEFAULT 24,
			enabled             boolean     NOT NULL DEFAULT false,
			last_sync_at        timestamptz,
			last_sync_status    text        NOT NULL DEFAULT 'never',
			last_error          text        NOT NULL DEFAULT '',
			updated_at          timestamptz NOT NULL DEFAULT NOW()
		)`,

		// dashboard_snapshots: Phase 6 executive dashboard. One row per day
		// (UNIQUE(snapshot_date) makes the daily scheduler's upsert idempotent).
		// See docs/superpowers/specs/2026-07-17-phase6-executive-dashboards-design.md.
		`CREATE TABLE IF NOT EXISTS dashboard_snapshots (
			id                 bigserial   PRIMARY KEY,
			snapshot_date      date        NOT NULL,
			avg_risk_score     int         NOT NULL,
			exposure_score     int         NOT NULL,
			detection_coverage int         NOT NULL,
			asset_count        int         NOT NULL DEFAULT 0,
			created_at         timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE(snapshot_date)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dashboard_snapshots_date ON dashboard_snapshots(snapshot_date DESC)`,
	}
```

- [ ] **Step 2: Verify it builds**

Run: `cd orchestrator && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 3: Commit**

```bash
cd orchestrator
git add internal/db/postgres.go
git commit -m "feat(dashboard): add dashboard_snapshots table"
```

There is no dedicated schema test — `EnsureSchema` is exercised implicitly by every Docker-backed test via `testutil.MustSharedTestDB()` (confirmed: `internal/testutil/testdb.go:60` calls `db.EnsureSchema`), so Task 2's tests are what actually prove this table works.

---

### Task 2: `internal/dashboard` package — `Compute`

**Files:**
- Create: `orchestrator/internal/dashboard/snapshot.go`
- Create: `orchestrator/internal/dashboard/snapshot_test.go`

**Interfaces:**
- Consumes: `attackpath.BuildGraphAndAnalyze(cols []attackpath.Collection, tags []attackpath.AssetTag) (*attackpath.Graph, attackpath.Summary)`; `pathcorrelation.DefaultPaths(g *attackpath.Graph, s attackpath.Summary) []pathcorrelation.AttackPath`; `pathcorrelation.Correlate(ctx, g, s, paths, mapper, runs, rules) (pathcorrelation.AttackPathCorrelation, error)` (field `.Score int` is the fleet detection-coverage score); `pathcorrelation.NewSQLRunLookup(pool) *pathcorrelation.SQLRunLookup`; `exposure.Build(ctx, g, s, corr, rels, enricher, findingsLookup, agents) (*exposure.AssetGraph, error)`; `(*exposure.AssetGraph).Summaries() []exposure.AssetSummary` (field `.ExposureScore int`); `exposure.NewSQLCVEEnricher(pool)`; `exposure.NewSQLFindingsLookup(pool)`.
- Produces: `dashboard.Snapshot{AvgRiskScore, ExposureScore, DetectionCoverage, AssetCount int}` and `dashboard.Compute(ctx context.Context, pool *pgxpool.Pool) (Snapshot, error)`, consumed by Tasks 3 and 4.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/dashboard/snapshot_test.go`:

```go
package dashboard

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func TestCompute_EmptyFleet_ReturnsZeroScores(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		snap, err := Compute(context.Background(), pool)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if snap != (Snapshot{}) {
			t.Errorf("Compute() = %+v, want zero value on an empty fleet", snap)
		}
	})
}

func TestCompute_AvgRiskScoreFromRecentRuns(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-1', 'a1', 'completed', '{"riskScore": 42}'::jsonb, NOW())`)
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-2', 'a1', 'completed', '{"riskScore": 58}'::jsonb, NOW())`)
		// Old run, outside the 30-day window — must not affect the average.
		mustExec(t, pool, `
			INSERT INTO scenario_runs (scenario_id, agent_id, status, score, completed_at)
			VALUES ('scn-3', 'a1', 'completed', '{"riskScore": 0}'::jsonb, NOW() - INTERVAL '90 days')`)

		snap, err := Compute(context.Background(), pool)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if snap.AvgRiskScore != 50 {
			t.Errorf("AvgRiskScore = %d, want 50 (avg of 42 and 58, excluding the 90-day-old run)", snap.AvgRiskScore)
		}
	})
}

// TestCompute_ExposureAndDetectionMatchDirectCalls pins Compute's fleet
// aggregation against the same exposure.Build/pathcorrelation.Correlate
// calls made directly, on identical seeded data — proving Compute isn't
// silently diverging from the established SP3/SP4 computations it wraps.
func TestCompute_ExposureAndDetectionMatchDirectCalls(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExec(t, pool, `INSERT INTO agents (agent_id, hostname) VALUES ('a1', 'HOST-1')`)

		ctx := context.Background()
		snap, err := Compute(ctx, pool)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if snap.AssetCount != 1 {
			t.Fatalf("AssetCount = %d, want 1 (one enrolled agent, no attack-path collections)", snap.AssetCount)
		}

		// Independently reproduce the same pipeline Compute wraps.
		g, s := attackpath.BuildGraphAndAnalyze(nil, nil)
		paths := pathcorrelation.DefaultPaths(g, s)
		wantCorr, err := pathcorrelation.Correlate(ctx, g, s, paths,
			pathcorrelation.DefaultEdgeTechniqueMapper{}, pathcorrelation.NewSQLRunLookup(pool), nil)
		if err != nil {
			t.Fatalf("pathcorrelation.Correlate: %v", err)
		}
		if snap.DetectionCoverage != wantCorr.Score {
			t.Errorf("DetectionCoverage = %d, want %d (direct pathcorrelation.Correlate call)", snap.DetectionCoverage, wantCorr.Score)
		}

		wantGraph, err := exposure.Build(ctx, g, s, wantCorr, nil,
			exposure.NewSQLCVEEnricher(pool), exposure.NewSQLFindingsLookup(pool),
			[]exposure.AgentRow{{AgentID: "a1", Hostname: "HOST-1"}})
		if err != nil {
			t.Fatalf("exposure.Build: %v", err)
		}
		wantSummaries := wantGraph.Summaries()
		if len(wantSummaries) != 1 {
			t.Fatalf("direct exposure.Build gave %d summaries, want 1", len(wantSummaries))
		}
		if snap.ExposureScore != wantSummaries[0].ExposureScore {
			t.Errorf("ExposureScore = %d, want %d (direct exposure.Build call)", snap.ExposureScore, wantSummaries[0].ExposureScore)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/dashboard/... -v`
Expected: FAIL — `internal/dashboard` package doesn't exist yet (`no Go files in ...` or `package dashboard: build constraints exclude all Go files`).

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/dashboard/snapshot.go`:

```go
// Package dashboard is the Phase 6 executive-dashboard aggregator: a pure
// consumer over the already-shipped attack-path graph (internal/attackpath),
// SP3 detection correlation (internal/pathcorrelation), and SP4 exposure
// scoring (internal/exposure), reduced to fleet-wide averages for a
// time-series view. It owns no DB tables itself — internal/api's scheduler
// persists what Compute returns.
package dashboard

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/exposure"
	"github.com/audspect/bas/internal/pathcorrelation"
)

// Snapshot is the fleet-wide posture at the moment Compute was called.
type Snapshot struct {
	AvgRiskScore      int `json:"avgRiskScore"`
	ExposureScore     int `json:"exposureScore"`
	DetectionCoverage int `json:"detectionCoverage"`
	AssetCount        int `json:"assetCount"`
}

// Compute builds today's fleet-wide snapshot. Nil-safe: an empty fleet (no
// runs, no assets) returns a zero-value Snapshot, never an error — same
// convention as exposure.Build/pathcorrelation.Correlate.
func Compute(ctx context.Context, pool *pgxpool.Pool) (Snapshot, error) {
	riskScore, err := avgRiskScore(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}

	cols, err := loadCollections(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	tags, err := loadAssetTags(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	g, s := attackpath.BuildGraphAndAnalyze(cols, tags)

	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(ctx, g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{}, pathcorrelation.NewSQLRunLookup(pool), nil)
	if err != nil {
		return Snapshot{}, err
	}

	agents, err := loadAgents(ctx, pool)
	if err != nil {
		return Snapshot{}, err
	}
	ag, err := exposure.Build(ctx, g, s, corr, nil,
		exposure.NewSQLCVEEnricher(pool), exposure.NewSQLFindingsLookup(pool), agents)
	if err != nil {
		return Snapshot{}, err
	}
	summaries := ag.Summaries()

	exposureAvg := 0
	if len(summaries) > 0 {
		total := 0
		for _, a := range summaries {
			total += a.ExposureScore
		}
		exposureAvg = total / len(summaries)
	}

	return Snapshot{
		AvgRiskScore:      riskScore,
		ExposureScore:     exposureAvg,
		DetectionCoverage: corr.Score,
		AssetCount:        len(summaries),
	}, nil
}

func avgRiskScore(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var avg int
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(ROUND(AVG((score->>'riskScore')::numeric)), 0)::int
		FROM scenario_runs
		WHERE completed_at IS NOT NULL
		  AND completed_at > NOW() - INTERVAL '30 days'
		  AND score IS NOT NULL`).Scan(&avg)
	return avg, err
}

func loadCollections(ctx context.Context, pool *pgxpool.Pool) ([]attackpath.Collection, error) {
	rows, err := pool.Query(ctx, `SELECT payload FROM attackpath_collections`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []attackpath.Collection
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		var c attackpath.Collection
		if json.Unmarshal(raw, &c) == nil {
			cols = append(cols, c)
		}
	}
	return cols, rows.Err()
}

func loadAssetTags(ctx context.Context, pool *pgxpool.Pool) ([]attackpath.AssetTag, error) {
	rows, err := pool.Query(ctx, `
		SELECT host_key, label, crown_jewel, segment, high_value,
		       criticality_tier, internet_facing, identity_exposed, production, compliance_scope
		FROM attackpath_asset_tags`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tags []attackpath.AssetTag
	for rows.Next() {
		var t attackpath.AssetTag
		if rows.Scan(&t.HostKey, &t.Label, &t.CrownJewel, &t.Segment, &t.HighValue,
			&t.CriticalityTier, &t.InternetFacing, &t.IdentityExposed, &t.Production, &t.ComplianceScope) == nil {
			tags = append(tags, t)
		}
	}
	return tags, rows.Err()
}

func loadAgents(ctx context.Context, pool *pgxpool.Pool) ([]exposure.AgentRow, error) {
	rows, err := pool.Query(ctx, `SELECT agent_id, hostname, ip_address, os_version FROM agents`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exposure.AgentRow
	for rows.Next() {
		var a exposure.AgentRow
		if rows.Scan(&a.AgentID, &a.Hostname, &a.IP, &a.OS) == nil {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/dashboard/... -v`
Expected: `PASS` on all 3 tests. Requires Docker Desktop running (Docker-backed via `testutil.MustSharedTestDB()`).

- [ ] **Step 5: Run gofmt, build, vet**

Run: `cd orchestrator && gofmt -l internal/dashboard/ && go build ./... && go vet ./...`
Expected: `gofmt -l` prints nothing (already formatted); build and vet exit 0.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add internal/dashboard/
git commit -m "feat(dashboard): add internal/dashboard.Compute fleet-wide aggregator"
```

---

### Task 3: Daily snapshot scheduler

**Files:**
- Create: `orchestrator/internal/api/dashboard_scheduler.go`
- Modify: `orchestrator/cmd/server/main.go` (near line 332, next to `api.StartAttackPathScheduler`)

**Interfaces:**
- Consumes: `dashboard.Compute(ctx, pool) (dashboard.Snapshot, error)` from Task 2.
- Produces: `api.StartDashboardScheduler(ctx context.Context, pool *pgxpool.Pool)`, called once from `main.go`.

- [ ] **Step 1: Write the scheduler**

Create `orchestrator/internal/api/dashboard_scheduler.go`:

```go
package api

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/dashboard"
)

// StartDashboardScheduler snapshots fleet-wide risk/exposure/detection-
// coverage scores into dashboard_snapshots once a day (immediately on start,
// then every 24h), and prunes rows older than 1 year. Fire-and-forget, same
// shape as internal/detect.StartRetention. Idempotent via
// dashboard_snapshots' UNIQUE(snapshot_date) + upsert, so a same-day restart
// just refreshes today's row instead of erroring or duplicating — this is
// why there's no separate "has today already run" gate the way the
// attack-path scheduler needs one (that one has a configurable interval and
// an enabled/disabled toggle; this one doesn't).
func StartDashboardScheduler(ctx context.Context, pool *pgxpool.Pool) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		snapshotAndPrune(ctx, pool)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				snapshotAndPrune(ctx, pool)
			}
		}
	}()
	log.Println("[+] Dashboard snapshot scheduler started")
}

func snapshotAndPrune(ctx context.Context, pool *pgxpool.Pool) {
	snap, err := dashboard.Compute(ctx, pool)
	if err != nil {
		log.Printf("[dashboard] snapshot failed: %v", err)
		return
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count)
		VALUES (CURRENT_DATE, $1, $2, $3, $4)
		ON CONFLICT (snapshot_date) DO UPDATE SET
			avg_risk_score     = EXCLUDED.avg_risk_score,
			exposure_score     = EXCLUDED.exposure_score,
			detection_coverage = EXCLUDED.detection_coverage,
			asset_count        = EXCLUDED.asset_count`,
		snap.AvgRiskScore, snap.ExposureScore, snap.DetectionCoverage, snap.AssetCount)
	if err != nil {
		log.Printf("[dashboard] snapshot upsert failed: %v", err)
		return
	}
	ct, err := pool.Exec(ctx, `DELETE FROM dashboard_snapshots WHERE snapshot_date < NOW() - INTERVAL '1 year'`)
	if err == nil {
		if n := ct.RowsAffected(); n > 0 {
			log.Printf("[dashboard] pruned %d snapshot(s) older than 1 year", n)
		}
	}
}
```

No dedicated test file for this task — matches the established precedent of `internal/detect/retention.go` (also an untested thin ticker/prune wrapper; the logic it calls, `dashboard.Compute`, is what Task 2 tests).

- [ ] **Step 2: Wire it into `main.go`**

In `orchestrator/cmd/server/main.go`, find this block (around line 329–332):

```go
	// ── Attack-Path Scheduler ─────────────────────────────────────────────
	// Ticks every 60 s and re-dispatches fleet-wide attack-path collection
	// when the operator-configured interval has elapsed.
	api.StartAttackPathScheduler(context.Background(), pool, hub)
```

Add immediately after it:

```go

	// ── Dashboard Snapshot Scheduler ──────────────────────────────────────
	// Snapshots fleet-wide risk/exposure/detection-coverage into
	// dashboard_snapshots once a day, powering the Executive Dashboard tab's
	// trend charts.
	api.StartDashboardScheduler(context.Background(), pool)
```

- [ ] **Step 3: Verify it builds**

Run: `cd orchestrator && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 4: Manual smoke check**

Run: `cd orchestrator && go run ./cmd/server` (with `DATABASE_URL` pointed at a real or test Postgres), watch stdout for:
```
[+] Dashboard snapshot scheduler started
```
Then check the table got a row: `psql $DATABASE_URL -c "SELECT * FROM dashboard_snapshots;"` — expect exactly 1 row dated today. Stop the server (Ctrl+C) once confirmed.

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add internal/api/dashboard_scheduler.go cmd/server/main.go
git commit -m "feat(dashboard): add daily snapshot scheduler"
```

---

### Task 4: API endpoints

**Files:**
- Create: `orchestrator/internal/api/dashboard_handlers.go`
- Create: `orchestrator/internal/api/dashboard_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (near line 180, next to the `/api/exposure/assets` routes)

**Interfaces:**
- Consumes: `dashboard.Compute(ctx, pool) (dashboard.Snapshot, error)` from Task 2; `respond(w, v)` / `jsonError(w, msg, code)` (existing helpers, `internal/api/handlers.go`).
- Produces: `GET /api/dashboard/current`, `GET /api/dashboard/trends?days=N`, both Viewer+.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/dashboard_handlers_test.go`:

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

func dashboardHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func TestGetDashboardCurrent_EmptyFleet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := dashboardHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetDashboardCurrent(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/current", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var snap struct {
			AvgRiskScore      int `json:"avgRiskScore"`
			ExposureScore     int `json:"exposureScore"`
			DetectionCoverage int `json:"detectionCoverage"`
			AssetCount        int `json:"assetCount"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if snap.AssetCount != 0 || snap.AvgRiskScore != 0 {
			t.Errorf("snap = %+v, want all-zero on an empty fleet", snap)
		}
	})
}

func TestGetDashboardTrends_EmptyHistoryReturnsEmptyArray(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := dashboardHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetDashboardTrends(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/trends", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		if rec.Body.String() != "[]\n" && rec.Body.String() != "[]" {
			t.Errorf("body = %q, want an empty JSON array, not null or an error", rec.Body.String())
		}
	})
}

func TestGetDashboardTrends_DayRangeFilteringAndClamping(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		mustExecAPI(t, pool, `
			INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count)
			VALUES
				(CURRENT_DATE, 50, 60, 70, 5),
				(CURRENT_DATE - INTERVAL '10 days', 40, 55, 65, 4),
				(CURRENT_DATE - INTERVAL '400 days', 10, 10, 10, 1)`)

		h := dashboardHandler(t, pool)

		// days=30 should include today and the 10-day-old row, exclude the 400-day-old one.
		rec := httptest.NewRecorder()
		h.GetDashboardTrends(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/trends?days=30", nil))
		var rows []struct {
			AvgRiskScore int `json:"avgRiskScore"`
		}
		json.Unmarshal(rec.Body.Bytes(), &rows)
		if len(rows) != 2 {
			t.Fatalf("days=30: got %d rows, want 2", len(rows))
		}

		// days=99999 clamps to 365 — still excludes the 400-day-old row.
		rec2 := httptest.NewRecorder()
		h.GetDashboardTrends(rec2, httptest.NewRequest(http.MethodGet, "/api/dashboard/trends?days=99999", nil))
		var rows2 []struct{ AvgRiskScore int `json:"avgRiskScore"` }
		json.Unmarshal(rec2.Body.Bytes(), &rows2)
		if len(rows2) != 2 {
			t.Fatalf("days=99999 (clamped to 365): got %d rows, want 2 (400-day-old row still excluded)", len(rows2))
		}
	})
}

func mustExecAPI(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetDashboard -v`
Expected: FAIL — `h.GetDashboardCurrent`/`h.GetDashboardTrends` undefined.

- [ ] **Step 3: Write the handlers**

Create `orchestrator/internal/api/dashboard_handlers.go`:

```go
package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/dashboard"
)

// GetDashboardCurrent returns today's fleet-wide posture, computed live
// (not read from dashboard_snapshots) so it never waits for the next
// scheduled tick. Read-only (Viewer+).
// GET /api/dashboard/current
func (h *Handler) GetDashboardCurrent(w http.ResponseWriter, r *http.Request) {
	snap, err := dashboard.Compute(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, snap)
}

// DashboardTrendPoint is one day's stored snapshot.
type DashboardTrendPoint struct {
	Date              string `json:"date"`
	AvgRiskScore      int    `json:"avgRiskScore"`
	ExposureScore     int    `json:"exposureScore"`
	DetectionCoverage int    `json:"detectionCoverage"`
	AssetCount        int    `json:"assetCount"`
}

// GetDashboardTrends returns stored daily snapshots for the requested range.
// Query params: days (default 90, clamped to [1, 365]). Read-only (Viewer+).
// GET /api/dashboard/trends?days=90
func (h *Handler) GetDashboardTrends(w http.ResponseWriter, r *http.Request) {
	days := 90
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 365 {
			days = n
		}
	}
	rows, err := h.db.Query(r.Context(), `
		SELECT snapshot_date, avg_risk_score, exposure_score, detection_coverage, asset_count
		FROM dashboard_snapshots
		WHERE snapshot_date >= CURRENT_DATE - $1::int
		ORDER BY snapshot_date ASC`, days)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []DashboardTrendPoint{}
	for rows.Next() {
		var p DashboardTrendPoint
		var d time.Time
		if rows.Scan(&d, &p.AvgRiskScore, &p.ExposureScore, &p.DetectionCoverage, &p.AssetCount) != nil {
			continue
		}
		p.Date = d.Format("2006-01-02")
		out = append(out, p)
	}
	respond(w, out)
}
```

- [ ] **Step 4: Register the routes**

In `orchestrator/internal/api/routes.go`, find:

```go
		r.Get("/api/exposure/assets", h.GetExposureAssets)
		r.Get("/api/exposure/assets/{hostKey}", h.GetExposureAsset)
```

Add immediately after:

```go
		r.Get("/api/exposure/assets", h.GetExposureAssets)
		r.Get("/api/exposure/assets/{hostKey}", h.GetExposureAsset)

		// Executive Dashboard — Phase 6. Fleet-wide risk/exposure/detection
		// trends, read-only (Viewer+).
		r.Get("/api/dashboard/current", h.GetDashboardCurrent)
		r.Get("/api/dashboard/trends", h.GetDashboardTrends)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run TestGetDashboard -v`
Expected: `PASS` on all 3 tests. Requires Docker Desktop running.

- [ ] **Step 6: Run the full package suite, gofmt, build, vet**

Run: `cd orchestrator && gofmt -l internal/api/ internal/dashboard/ && go build ./... && go vet ./... && go test ./internal/api/... ./internal/dashboard/...`
Expected: `gofmt -l` prints nothing; build/vet exit 0; both test suites `ok`.

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add internal/api/dashboard_handlers.go internal/api/dashboard_handlers_test.go internal/api/routes.go
git commit -m "feat(dashboard): add GET /api/dashboard/current and /trends endpoints"
```

---

### Task 5: UI — Executive Dashboard tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html`
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (hardlinked twin of the above — apply every edit to both)

**Interfaces:**
- Consumes: `GET /api/dashboard/current` → `{avgRiskScore, exposureScore, detectionCoverage, assetCount}`; `GET /api/dashboard/trends?days=N` → `[{date, avgRiskScore, exposureScore, detectionCoverage, assetCount}, ...]`; existing `apicall(url)` fetch wrapper (returns a Promise of parsed JSON); existing `showToast(msg, kind)`.
- Produces: nav item + tab `exec-dashboard`, JS functions `loadExecDashboard()`, `renderExecDashboard(current, trends)`, `edSparkline(values)`, `edTrendChip(values)`, `edKpiCard(label, current, trendSeries)`.

Apply every step below to **both** `orchestrator/wwwroot/index.html` and `orchestrator/cmd/server/wwwroot/index.html` — they are the same file on disk (NTFS hardlink) but two separate git-tracked paths whose history has drifted before when only one was edited.

- [ ] **Step 1: Add the nav item**

Find (in the Visibility nav group):

```html
        <div class="nav-item" data-tab="exposure" onclick="showTab('exposure')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <circle cx="8" cy="8" r="6"/><circle cx="8" cy="8" r="2.2"/>
          </svg>
          Exposure Explorer
        </div>
```

Add immediately after it:

```html
        <div class="nav-item" data-tab="exec-dashboard" onclick="showTab('exec-dashboard')">
          <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4">
            <path d="M2 13.5h12M4 13.5V8M8 13.5V4M12 13.5v-6"/>
          </svg>
          Executive Dashboard
        </div>
```

- [ ] **Step 2: Add the tab container**

Find:

```html
      <!-- Exposure Explorer -->
      <div id="tab-exposure" style="display:none">
```

...and its matching closing `</div>` right before the `<!-- Findings -->` comment. Add a new tab block immediately after the Exposure Explorer tab's closing `</div>` (i.e. right before `<!-- Findings -->`):

```html
      <!-- Executive Dashboard -->
      <div id="tab-exec-dashboard" style="display:none">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:1rem;flex-wrap:wrap">
          <div>
            <h1 style="font-family:var(--font-display);font-size:1.5rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem;color:var(--text)">Executive Dashboard</h1>
            <div style="font-size:0.8rem;color:var(--muted)">Fleet-wide risk, exposure, and detection-coverage trends over time — daily snapshots, not a single point-in-time report.</div>
          </div>
          <div style="display:flex;gap:0.5rem;align-items:center">
            <select id="ed-range" onchange="loadExecDashboard()" style="padding:0.35rem 0.6rem;background:var(--elevated);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:0.78rem">
              <option value="30">30 days</option>
              <option value="90" selected>90 days</option>
              <option value="365">1 year</option>
            </select>
            <button class="btn btn-outline btn-sm" onclick="loadExecDashboard()">Refresh</button>
          </div>
        </div>
        <div class="kpi-row" id="ed-kpi-row"><div class="empty">Loading…</div></div>
      </div>

```

- [ ] **Step 3: Wire the tab into `activateTab`/`TAB_TITLES`/`showTab`**

Find:

```js
var TAB_TITLES = { dashboard:'Dashboard', agents:'Agents', scenarios:'Scenarios', runs:'Live Runs', campaigns:'Campaigns', coverage:'ATT&CK Coverage', findings:'Findings', remediation:'Remediation', reports:'Reports', verification:'Detection Verification', users:'Users', compliance:'Compliance', settings:'Settings', variants:'Variant Executor', em:'Endpoint Mastery', exposure:'Exposure Explorer', openaev:'OpenAEV Connector', exercises:'Exercises' };
```

Replace with:

```js
var TAB_TITLES = { dashboard:'Dashboard', agents:'Agents', scenarios:'Scenarios', runs:'Live Runs', campaigns:'Campaigns', coverage:'ATT&CK Coverage', findings:'Findings', remediation:'Remediation', reports:'Reports', verification:'Detection Verification', users:'Users', compliance:'Compliance', settings:'Settings', variants:'Variant Executor', em:'Endpoint Mastery', exposure:'Exposure Explorer', 'exec-dashboard':'Executive Dashboard', openaev:'OpenAEV Connector', exercises:'Exercises' };
```

Find:

```js
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','integrations','openaev','exercises'].forEach(function(t) {
```

Replace with:

```js
  ['dashboard','agents','scenarios','runs','campaigns','coverage','findings','remediation','reports','verification','compliance','settings','variants','em','attackpath','exposure','exec-dashboard','integrations','openaev','exercises'].forEach(function(t) {
```

Find (inside `showTab`):

```js
  if (name === 'exposure') loadExposureAssets();
```

Add immediately after:

```js
  if (name === 'exposure') loadExposureAssets();
  if (name === 'exec-dashboard') loadExecDashboard();
```

- [ ] **Step 4: Add the JS loader, sparkline, and KPI-card renderer**

Find the existing `loadExposureAssets` function definition (search for `function loadExposureAssets`) and add the new functions immediately after its closing `}`:

```js
function loadExecDashboard() {
  var rangeEl = document.getElementById('ed-range');
  var days = rangeEl ? rangeEl.value : '90';
  Promise.all([
    apicall('/api/dashboard/current'),
    apicall('/api/dashboard/trends?days=' + encodeURIComponent(days))
  ]).then(function(res) {
    renderExecDashboard(res[0], res[1]);
  }).catch(function(e) { showToast(e.message, 'err'); });
}

function edSparkline(values) {
  if (!values.length) return '';
  var w = 140, h = 32;
  var min = Math.min.apply(null, values), max = Math.max.apply(null, values);
  var range = (max - min) || 1;
  var pts = values.map(function(v, i) {
    var x = values.length > 1 ? (i / (values.length - 1)) * w : w;
    var y = h - ((v - min) / range) * h;
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return '<svg class="stat-spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">' +
    '<polyline points="' + pts + '" fill="none" stroke="var(--accent)" stroke-width="1.6"/></svg>';
}

function edTrendChip(values) {
  if (values.length < 2) return '';
  var cur = values[values.length - 1];
  var priorIdx = Math.max(0, values.length - 8); // ~7 data points back
  var delta = cur - values[priorIdx];
  if (delta === 0) return '<span class="tiny muted">flat</span>';
  var up = delta > 0;
  var col = up ? 'var(--success)' : 'var(--danger)';
  return '<span class="tiny" style="color:' + col + '">' + (up ? '▲' : '▼') + ' ' + Math.abs(delta) + '</span>';
}

function edKpiCard(label, current, trendSeries) {
  return '<div class="kpi-card stat-tile">' +
    '<div class="stat-top"><div>' +
      '<div class="kpi-label">' + label + '</div>' +
      '<div class="kpi-value">' + current + '</div>' +
      edTrendChip(trendSeries) +
    '</div></div>' +
    edSparkline(trendSeries) +
  '</div>';
}

function renderExecDashboard(current, trends) {
  var el = document.getElementById('ed-kpi-row');
  if (!el) return;
  var risk = trends.map(function(p) { return p.avgRiskScore; });
  var exp = trends.map(function(p) { return p.exposureScore; });
  var det = trends.map(function(p) { return p.detectionCoverage; });
  var cnt = trends.map(function(p) { return p.assetCount; });
  el.innerHTML =
    edKpiCard('Risk Score', current.avgRiskScore, risk) +
    edKpiCard('Exposure Score', current.exposureScore, exp) +
    edKpiCard('Detection Coverage', current.detectionCoverage, det) +
    edKpiCard('Fleet Assets', current.assetCount, cnt);
}
```

- [ ] **Step 5: Syntax-check the inline `<script>` blocks**

Run: `node --check orchestrator/wwwroot/index.html 2>&1 | head -5` — this will fail (the file is HTML, not pure JS), so instead extract and check just the script content:

```bash
cd orchestrator
node -e "
const fs = require('fs');
const html = fs.readFileSync('wwwroot/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
scripts.forEach((s, i) => { try { new Function(s); } catch (e) { console.error('script block', i, ':', e.message); process.exitCode = 1; } });
console.log(scripts.length + ' inline script block(s) checked');
"
```

Expected: `N inline script block(s) checked` with no error lines, exit 0. Repeat for `cmd/server/wwwroot/index.html`.

- [ ] **Step 6: Confirm both wwwroot files are still byte-identical**

Run: `diff orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html`
Expected: no output (files identical) — if the hardlink held, editing one edited both automatically; this just confirms Step 1–4 weren't accidentally applied to only one path.

- [ ] **Step 7: Commit**

```bash
cd orchestrator
git add wwwroot/index.html cmd/server/wwwroot/index.html
git commit -m "feat(dashboard): add Executive Dashboard tab with trend sparklines"
```

**Known gap, flag to the user:** no browser tool is available in this environment to visually verify the new tab renders correctly, the sparklines draw sensible paths, or the range selector re-fetches — same honest gap SP4 and SP6 both had. Recommend a manual browser spot-check after this plan completes: open the Executive Dashboard tab, confirm the 4 KPI cards render, switch the range selector between 30/90/365 days, and confirm no console errors.

---

## Self-review notes (from the plan author, not a task to execute)

- **Spec coverage:** all 5 spec sections (data model, scheduler, API, UI, error handling) are covered — Task 1 (data model), Task 3 (scheduler + retention), Task 4 (API + empty-history/clamping edge cases), Task 5 (UI). The "first day after deploy, 0 or 1 rows" edge case is covered by Task 4's empty-history test and Task 5's sparkline/trend-chip length guards (`if (!values.length)` / `if (values.length < 2)`).
- **Deviations from the approved spec, both necessary and both explained inline above:** (1) tab id/label changed from `dashboard`/"Dashboard" to `exec-dashboard`/"Executive Dashboard" — the original name collides with the existing operational landing tab; the new tab is an addition to the Visibility group, not a replacement for the landing page. (2) The Go function is `dashboard.Compute`, not `dashboard.Snapshot` — the spec's proposed signature reused the type name as the function name, which Go doesn't allow.
- **Type consistency:** `dashboard.Snapshot`'s JSON field names (`avgRiskScore`, `exposureScore`, `detectionCoverage`, `assetCount`) are used consistently across Task 2 (struct tags), Task 4 (`GetDashboardCurrent` returns it directly; `DashboardTrendPoint` mirrors the same names), and Task 5 (JS reads `current.avgRiskScore` etc., matching).
