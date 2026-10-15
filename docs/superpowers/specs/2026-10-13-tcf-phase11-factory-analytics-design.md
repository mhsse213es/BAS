# TCF Phase 11 — Factory Analytics Design

**Status:** approved for planning
**Roadmap context:** [docs/threat-content-factory/roadmap-phases-4-11.md](../../threat-content-factory/roadmap-phases-4-11.md), position 1 of the 8-phase sequence (11→8→9→7→10→4→5→6)

## Goal

Give the factory a trustworthy, read-only measurement baseline — pipeline health, content throughput, threat-to-content latency — built entirely from records the system already persists. No automation, no triggering, no new write paths. This is the measurement instrument that every later automation phase (8, 9, 7, 10, 4, 5, 6) will be judged against.

## Scope boundary

| In this phase | Not this phase |
|---|---|
| Read-only aggregation API over existing tables | Any mutation: approval, publishing, triggering generation |
| A minimal, read-only dashboard page | Alerting, analytics-driven automation |
| Historical trend lines where real timestamped history exists | A full customer-facing threat-exposure dashboard (that's Phase 10) |
| Honest `NO_DATA` for metrics with no underlying data | A persisted generation-attempt log (that's Phase 9's deliverable) |
| New SQL queries over existing tables | New tables, new frontend framework, new charting library |

## Architecture

- **Backend aggregation:** `orchestrator/internal/analytics/factory.go`, a new file in the existing `internal/analytics` package (sibling to `threatintel.go`, `endpoint.go`, `ioc.go`). Same convention as the rest of that package: raw SQL via `pool.QueryRow`/`pool.Query`, no query builder, one plain result struct.
- **TCV aggregate:** a new function in `orchestrator/internal/tcv` (e.g. `AggregateMetrics(ctx, pool) (TCVAggregate, error)`) computing median/P95 TCV across all threats in one SQL query (`percentile_cont(0.5|0.95) WITHIN GROUP`), filtered to threats in `MetricState.Measured`. The existing per-threat `(*Store).Metrics(ctx, threatID)` is not reused here — looping it per threat would be an N+1 query pattern; this phase adds one new aggregate query instead.
- **API:** `(*Handler).GetFactoryHealth` in `orchestrator/internal/api/`, route `GET /api/analytics/factory-health`, `tierAny` access (same tier as its siblings `GetThreatIntelSummary` etc. — no fine-grained permission, this is a reporting endpoint).
- **Frontend:** `orchestrator/web/src/features/factory-health.js`, modeled directly on `campaigns.js`'s existing KEV-widget block — same `apicall()` fetch helper, same tile-template convention via `innerHTML` into pre-existing DOM element IDs. One new nav entry added to `index.html`. No new JS framework, no charting library.

## Metric definitions

Each metric's semantics are fixed here, before any query is written.

### Current-value tiles

| Metric | Definition | Source |
|---|---|---|
| Threats processed | Count of `threats` rows with `created_at` in the selected window | `threats` |
| Published content | Distinct `content_versions` where `lifecycle IN ('PUBLISHED','PUBLISHED_LOCAL')` | `content_versions` |
| Median / P95 TCV | **Scoped to `ThreatToEmulation` only** (clock = `threat`, relationship = `emulates`) — the canonical "threat-to-content velocity" the pipeline diagram names. The other three TCV combinations (`ThreatToGeneration`, `IntelligenceToEmulation`, `IntelligenceToGeneration`) are out of scope for this tile; a future pass can add them as separate tiles. Percentile over threats in `MetricState.Measured` only for that one combination (clock started AND coverage recorded; `Open`/`PreExisting`/`NoClock` excluded) | `threat_clock_starts` ⋈ `threat_coverage_firsts`, filtered to `clock='threat'`/`relationship_kind='emulates'` (new `tcv.AggregateMetrics`) |
| Validation pass rate | **STRUCTURAL/STATIC level only in v1** (the only `content_validations.level` with real data today) — labeled explicitly as "static validation pass rate," never implying execution or detection validation. Denominator = all validations run at that level in the window; numerator = `outcome = 'PASS'` | `content_validations` |
| Duplicate-generation rate | `NO_DATA` always in this phase. Generation-attempt outcomes are only logged to stdout and an in-memory, process-lifetime counter today — never persisted. The UI must show this as `NO_DATA` with the explanation "generation-attempt telemetry is not yet persisted," never a measured `0%` | none (explicit `NO_DATA`) |
| Source-to-technique mapping coverage | Share of `threats` with ≥1 row in the `threat_techniques` projection vs. total `threats` in window | `threats`, `threat_techniques` |

### Pipeline status

| Section | Content | Source |
|---|---|---|
| Ingestion and evidence | Last successful sync per source (`MAX(completed_at) WHERE status='succeeded'`), count of `status='failed'` syncs in window with their `diagnostic` text, count of `actor_resolution_candidates WHERE status='unresolved'` | `source_syncs`, `actor_resolution_candidates` |
| Content lifecycle funnel | Current-value counts by lifecycle: candidate = `DRAFT`/`VALIDATING`, validated = `VALIDATED`, published = `PUBLISHED`/`PUBLISHED_LOCAL`, rejected = `REJECTED` (all real, distinct, unambiguous states) | `content_versions` |
| Data quality and failures | Stale sources (no successful sync in N days — N configurable, default 7), failed lifecycle transitions (`content_version_events` with no corresponding successful follow-on — exact query defined in the plan), any metric currently reporting `NO_DATA` and why | `source_syncs`, `content_version_events` |

### Historical trends

Trend lines are included **only** for metrics with genuine timestamped history:
- Threats processed over time (bucketed by day/week from `threats.created_at`)
- TCV over time (bucketed `threat_coverage_firsts.first_executable_at` vs. `threat_clock_starts.started_at`)

Rendered as **inline SVG polylines**, matching the existing convention already used by `attack-path.js`/`evidence.js` — no new charting dependency. The funnel and all other tiles remain current-value-only; they do not get a time series in this phase. When a trend has fewer than a defined minimum number of data points (set in the plan), the UI shows an honest empty state, never a flat or interpolated line implying more history than exists.

## NO_DATA discipline

Every metric in the API response carries an explicit state, not just a bare number:

```json
{
  "metric": "duplicate_generation_rate",
  "state": "no_data",
  "value": null,
  "reason": "generation-attempt telemetry is not yet persisted"
}
```

`state` is one of `measured`, `no_data`. A `no_data` metric never carries a numeric `value`, and the frontend renders it as a distinct visual state (not a zero, not a blank tile) — the dashboard must make it impossible to mistake "never measured" for "measured and zero." This mirrors the precedent already set by `content_validations.outcome`'s own `NO_DATA`/`NOT_APPLICABLE` values.

## Query cost

None of the tables this phase queries are indexed with a time column as the leading index key (`content_version_events` and `content_validations` are indexed `(content_version_id, ...)`, not `(at, ...)` or `(..., at)`). At current and near-term data volumes this is a non-issue — these are low-cardinality tables. Flagged here, not acted on: if a specific windowed query proves slow once the plan's tests run against realistic volumes, add the index then, as a targeted follow-up, not preemptively.

## Testing approach

- Each metric's query gets a direct test against a seeded database: one case with real data (asserting the exact expected value), one case with genuinely no underlying data (asserting `state: "no_data"`, not a zero).
- The duplicate-generation-rate metric's test asserts `no_data` unconditionally — there is no code path in this phase that could produce a measured value for it, and the test should say so.
- The TCV aggregate query is tested against a mix of `Measured`, `Open`, and `NoClock` threats, asserting the percentile excludes the non-`Measured` ones.
- Frontend: a smoke test (or manual verification, per this repo's existing frontend testing convention — confirmed in the plan) that the dashboard renders all tiles including at least one `NO_DATA` tile distinctly from a measured tile.

## Acceptance criteria

1. Every metric in the API response is traceable to a real query over an existing table — no fabricated or placeholder values.
2. At least one metric (duplicate-generation rate) demonstrably renders as `NO_DATA`, and the UI visibly distinguishes this from a measured zero.
3. The validation pass rate metric is labeled with the specific validation level it covers (STRUCTURAL/STATIC), not implied to cover execution or detection.
4. TCV percentiles are computed only over `Measured`-state threats.
5. No new database tables, no new frontend framework, no new charting library.
6. At least one trend line (threats processed or TCV, whichever has sufficient history in test data) renders as an inline SVG polyline with no new dependency.
