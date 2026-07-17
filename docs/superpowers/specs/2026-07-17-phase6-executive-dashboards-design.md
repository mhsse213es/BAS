# Phase 6, Subsystem 1 — Executive Dashboards (design)

**Date:** 2026-07-17
**Status:** approved
**Module:** Executive Dashboards — first of Phase 6's three subsystems (executive dashboards, recommendation engine, predictive risk), per `project_platform_roadmap_2026h2`. Builds the persistent, time-series aggregation layer the other two Phase 6 subsystems will consume.

## Problem
Phase 6 calls for executive dashboards showing risk trends, MITRE coverage, detection coverage, exposure trends, compliance posture, and readiness scores. Today's `ExecutiveSummary` (`internal/reporting/engine.go`) is scoped to a single report/run — there is no fleet-wide, time-series view answering "is our posture improving?", which is the actual executive-reporting use case.

Investigation found a real data problem underneath this: per-run `RiskScore` already has history (`scenario_runs.score` jsonb, one row per run, each with `started_at`) — but fleet-wide `ExposureScore` (SP4, `internal/exposure`) and `DetectionCoverageScore` (SP3, `internal/pathcorrelation`) are both computed live from *current* graph/verification state only. Nothing persists what they were last week. Real trending for those two requires a new snapshot mechanism, not just a new query.

## Decisions
1. **Scope: org/fleet-wide, time-series** — not a per-campaign snapshot. This is what "executive dashboard" means in practice; a richer per-run summary already exists in the report engine and isn't being duplicated here.
2. **Add scheduled daily snapshots** rather than trending only what's already historical, or piggybacking on report-generation events. New lightweight infrastructure (a table + a ticker goroutine), but it's the only option that gives real trends for all three metrics instead of leaving two of them as "current value only." Directly reuses `internal/api/attackpath_scheduler.go`'s existing ticker+singleton-row pattern — no new scheduling primitive invented.
3. **First slice covers 3 of Phase 6's 6 named metric families**: risk trend, fleet exposure trend, fleet detection-coverage trend. These three already have a live single-point computation to snapshot (`scenario_runs.score`, `exposure.Build`, `pathcorrelation.Correlate`) — no new scoring logic needed, just persistence + a chart. MITRE tactic-coverage, compliance posture, and readiness scores don't have an existing *fleet-wide* (as opposed to per-run) computation today; building those is a fast-follow slice once the snapshot mechanism exists, not part of this one.
4. **New top-level nav tab** ("Dashboard", Visibility group, landing page) rather than folding into Exposure Explorer — different audience (fleet-summary/trend consumption) and mental model (asset-centric drill-down) than the existing tab.
5. **Daily cadence, 1-year retention.** Matches how trend data is actually consumed (week/month/quarter-over-quarter); finer-grained cadence would be noisier without evidence it's needed. A year of daily rows per metric is trivially small.

## Architecture

### New package: `internal/dashboard`
Pure aggregator, same shape as `internal/exposure`/`internal/pathcorrelation` (no new tables owned by the computation itself — see Data model below for the one table that *is* new, owned by the scheduler/API layer, not the aggregator).

```go
// Snapshot computes today's fleet-wide metrics. Nil-safe: an empty fleet
// (no runs, no assets) returns zero-value scores, never an error.
func Snapshot(ctx context.Context, pool *pgxpool.Pool) (Snapshot, error)

type Snapshot struct {
    AvgRiskScore       int
    ExposureScore      int
    DetectionCoverage  int
    AssetCount         int
}
```
- `AvgRiskScore`: mean of `scenario_runs.score->>'riskScore'` over the last 30 days of completed runs (0 if none).
- `ExposureScore`: mean of `AssetExposureProfile.Score.ExposureScore` across `exposure.Build`'s asset universe.
- `DetectionCoverage`: fleet-wide `pathcorrelation.Correlate(...).DetectionCoverageScore`.
- `AssetCount`: `len(exposure.Build(...).Assets)` — carried along so a dashboard swing can be explained by fleet-size change, not just posture change.

### Data model
One new table, owned by the scheduler/API (not `internal/dashboard`, which stays a pure computation package with no persistence of its own):
```sql
CREATE TABLE dashboard_snapshots (
    id                 bigserial PRIMARY KEY,
    snapshot_date      date        NOT NULL,
    avg_risk_score     int         NOT NULL,
    exposure_score     int         NOT NULL,
    detection_coverage int         NOT NULL,
    asset_count        int         NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT NOW(),
    UNIQUE(snapshot_date)
);
CREATE INDEX idx_dashboard_snapshots_date ON dashboard_snapshots(snapshot_date DESC);
```
One row per day (`UNIQUE(snapshot_date)` makes a re-run idempotent via `ON CONFLICT (snapshot_date) DO UPDATE` — matches the "snapshot job" model, not an append-only log).

### Scheduler — `internal/api/dashboard_scheduler.go` (new, mirrors `attackpath_scheduler.go`)
```go
func StartDashboardScheduler(ctx context.Context, pool *pgxpool.Pool) {
    go func() {
        ticker := time.NewTicker(1 * time.Hour) // checks hourly, only *acts* once/day
        defer ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                runDailySnapshot(ctx, pool)
            }
        }
    }()
}
```
`runDailySnapshot` checks whether today's `snapshot_date` row already exists (skip if so — this is the "once daily" gate, no separate config row needed since there's no enable/disable toggle or configurable interval in this slice, unlike the attack-path scheduler which has both). Computes `dashboard.Snapshot(ctx, pool)`, upserts the row, then prunes rows older than 1 year (`DELETE FROM dashboard_snapshots WHERE snapshot_date < NOW() - INTERVAL '1 year'`), same retention-prune shape as `internal/detect/retention.go`. On a `Snapshot()` error: log and return — fire-and-forget, next hour's tick (which no-ops until midnight rolls the date) tries again next day.

### API — `internal/api/dashboard_handlers.go` (new)
- `GET /api/dashboard/current` (Viewer+) — calls `dashboard.Snapshot` live, uncached. Covers "I need today's number right now" without waiting for the scheduler or adding a manual-trigger endpoint.
- `GET /api/dashboard/trends?days=90` (Viewer+) — `SELECT * FROM dashboard_snapshots WHERE snapshot_date >= NOW() - $1::interval ORDER BY snapshot_date ASC`. `days` defaults to 90, clamped to [1, 365]. Returns `[]` (not an error) when no snapshots exist yet.

### UI
New nav item "Dashboard" (Visibility group, set as the default/landing view). Three KPI cards — Risk Score, Exposure Score, Detection Coverage — each showing today's value from `/api/dashboard/current`, a trend chip (▲/▼ vs. the value 7 days back in the trends array), and a small inline `<svg><polyline>` line chart plotting the selected range (no external charting library — hand-rolled from the trends array, consistent with the project's fully-offline/no-CDN constraint). A day-range selector (30/90/365) re-fetches `/api/dashboard/trends?days=N`. A 4th "Asset Count" tile for context. Follows existing `apicall()`/`x()`-escaping/`.kpi-row` conventions in `wwwroot/index.html` — both it and its `cmd/server/wwwroot/index.html` hardlink twin get edited and committed together (per the SP4 repo-quirk note).

## Error handling / edge cases
- Empty fleet: `Snapshot()` returns zero-value scores, never errors — same convention as `exposure.Build`/`pathcorrelation.Correlate`.
- Scheduler tick fires but `Snapshot()` errors (DB hiccup, etc.): log and skip; next tick retries. No retry queue, no alerting — matches the existing attack-path scheduler's fire-and-forget philosophy.
- First day after deploy: `dashboard_snapshots` has 0 or 1 rows; `/api/dashboard/trends` returns whatever exists, and the UI renders a single point rather than requiring a minimum history length before showing anything.
- No manual "snapshot now" admin action in this slice — `GET /api/dashboard/current` already covers that need without mutating stored history.

## Testing (TDD)
- `internal/dashboard/snapshot_test.go` — Docker-backed (same `sharedDB`/`TestMain` pattern as `internal/exposure`): empty fleet → zero scores; single run → `AvgRiskScore` matches; multi-asset fleet → `ExposureScore`/`DetectionCoverage` match direct calls to `exposure.Build`/`pathcorrelation.Correlate` on the same seeded data.
- `internal/api/dashboard_handlers_test.go` — `/current` live-compute round-trip; `/trends` day-range filtering and clamping; empty-history returns `[]` not an error; upsert idempotency (`runDailySnapshot` called twice same day → still 1 row).
- Retention: a test seeding rows older than 1 year confirms the prune deletes them and leaves recent rows untouched.
- Manual: browser spot-check of the new Dashboard tab, KPI cards, and inline sparkline charts — flagged as a known gap in the plan, same honest gap SP4/SP6 both had (no browser tool available mid-session historically for this repo).

## Out of scope
MITRE tactic-coverage, compliance-posture, and readiness-score metric families (Decision 3 — fast-follow once this snapshot mechanism exists). The recommendation-engine and predictive-risk Phase 6 subsystems (separate brainstorm cycles, sequenced after this one). Any admin UI for schedule configuration (enable/disable, interval) — this slice's cadence is fixed at daily with no toggle, unlike the attack-path scheduler.

## Capture
Vault: new `Executive Dashboards` feature note (status: in-progress); Roadmap Phase 6 gets its first subsystem marked in-progress; daily note.
