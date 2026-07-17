# Phase 6, Subsystem 3 — Predictive Risk (design)

**Date:** 2026-07-17
**Status:** approved
**Module:** Predictive Risk — the third and final of Phase 6's three subsystems, per `project_platform_roadmap_2026h2`. Sequenced after [Executive Dashboards](2026-07-17-phase6-executive-dashboards-design.md) and [Recommendation Engine](2026-07-17-phase6-recommendation-engine-design.md) (both done 2026-07-17). Depends on the daily `dashboard_snapshots` trend series that Executive Dashboards began accumulating.

## Problem
Phase 6 names "predictive risk" as forward-looking analytics: where is the fleet's security posture heading, and how long has exposure been sitting open. Today the platform is entirely retrospective — Executive Dashboards shows the current KPI row and a trend sparkline, but nothing projects the trend forward, and nothing quantifies how *stale* open findings are. The raw material now exists:

| Existing | What it holds | What's missing |
|---|---|---|
| `dashboard_snapshots` | Daily `(avg_risk_score, exposure_score, detection_coverage, asset_count)` since Executive Dashboards shipped | No projection — just points on a chart |
| `findings` (`status`, `first_seen`, `resolved_at`, `reopened_count`) | Every open/closed finding with an age | Never aggregated into an exposure-window view |
| `reporting.buildTrendSummary` | Trend direction from run history | Report-scoped; no forecast, and deliberately refuses to invent a baseline |

Nothing answers "where is this heading?" or "how long has this been open?"

### The honesty constraint
An earlier design pass proposed an **attack-likelihood / breach-probability** score. It was cut. BAS control-test data measures whether *our* controls stop *our* simulations — it carries no base rate of real-world attack frequency, so any breach-probability number would be fiction dressed as arithmetic. That directly contradicts the precedent set by `reporting.buildTrendSummary`, which refuses to invent a baseline it cannot substantiate. This subsystem therefore predicts only what the data can honestly support: a **trend forecast** of a metric the platform actually measures, and **exposure windows** measured directly from finding ages. Every degradation path below exists to keep the feature from becoming fiction.

## Decisions
1. **Two independent signals, not one blended "risk oracle": Forecast + ExposureWindows.** They answer different questions ("where is the trend heading" vs. "how stale is what's open now"), draw from different tables, degrade independently, and are separately testable. Blending them into a single scalar would hide which signal is driving the number and couple two things that fail for different reasons. `Build` composes them; neither depends on the other.
2. **Forecast input is `dashboard_snapshots`, and it degrades honestly.** Hand-rolled ordinary-least-squares regression over `(dayIndex, score)` — no forecasting library (air-gapped), no seasonality/ARIMA (not enough history to fit, and unjustifiable on a daily-granularity BFSI control-posture series). A three-rung degradation ladder (below) means a fresh deploy returns "insufficient history" for two weeks and then self-heals — correct behavior, not a bug.
3. **Attack-likelihood / breach-probability is out of scope** (see the honesty constraint above). If a future data source ever supplies a real base rate, it gets its own brainstorm cycle; it is not bolted onto this one.
4. **Exposure windows are measured, never modeled.** `NOW() - first_seen` over open findings is a fact, not a prediction. It ships in the same subsystem because it is the honest, defensible half of "predictive risk" — the half a CISO can act on today ("these five findings have been open 90+ days"). No statistical machinery, no confidence gating; it is either present or the fleet has no open findings.
5. **UI extends the existing Executive Dashboard tab; it is not a new tab.** Predictive Risk is trend-consumption for the same executive audience that reads the dashboard — a forecast card and an exposure-window table below the existing KPI row. A separate tab would fragment one audience's view across two places. (Contrast with Recommendation Engine, which got its own tab precisely because it serves the *operator*, a different audience.)

## Architecture

### New package: `internal/predict`
Pure aggregator, owns no DB tables, same shape as `internal/dashboard` / `internal/recommend` / `internal/exposure`. Two responsibilities → two files, each independently testable:

- `forecast.go` — pure math over an in-memory series; **no DB, no `pgxpool` import**, so `forecast_test.go` runs without Docker.
- `predict.go` — the `Build` entry point: loads snapshots + findings from the pool, calls into `forecast.go`, assembles exposure windows.

```go
// Build composes a trend forecast (from dashboard_snapshots) and exposure
// windows (from open findings). Nil-safe: an empty/young fleet returns a
// Prediction whose sub-structs report their own insufficiency, never an error.
func Build(ctx context.Context, pool *pgxpool.Pool) (Prediction, error)

type Prediction struct {
    Forecast Forecast        `json:"forecast"`
    Exposure ExposureWindows `json:"exposure"`
}

// Forecast is an OLS projection of a single dashboard metric over time.
type Forecast struct {
    Metric        string      `json:"metric"`        // "avg_risk_score"
    Direction     string      `json:"direction"`     // improving | worsening | flat | unclear | unknown
    Confidence    string      `json:"confidence"`    // high | medium | low | none
    HasForecast   bool        `json:"hasForecast"`   // false during cold start
    SampleDays    int         `json:"sampleDays"`    // n snapshots used
    History       []Point     `json:"history"`       // the observed series (for charting)
    Projected     []Point     `json:"projected,omitempty"` // forward points, only when HasForecast
    Slope         float64     `json:"slope,omitempty"`     // score units per day
    RSquared      float64     `json:"rSquared,omitempty"`
    Note          string      `json:"note"`          // human-readable state, e.g. "insufficient history"
}

type Point struct {
    DayIndex int     `json:"dayIndex"`  // 0-based from first snapshot
    Date     string  `json:"date"`      // YYYY-MM-DD; empty for projected points
    Score    float64 `json:"score"`
    Low      float64 `json:"low,omitempty"`  // prediction interval, projected points only
    High     float64 `json:"high,omitempty"`
}

// ExposureWindows is a measured (not modeled) view of open-finding staleness.
type ExposureWindows struct {
    OpenCount        int              `json:"openCount"`
    WorstDaysOpen    int              `json:"worstDaysOpen"`
    MedianDaysOpen   int              `json:"medianDaysOpen"`
    OverThreshold    int              `json:"overThreshold"`    // count open > 30 days
    ThresholdDays    int              `json:"thresholdDays"`    // 30
    Worst            []ExposureItem   `json:"worst"`            // N oldest open findings
    HasData          bool             `json:"hasData"`
}

type ExposureItem struct {
    TechniqueID   string `json:"techniqueId"`
    TechniqueName string `json:"techniqueName"`
    Severity      string `json:"severity"`
    DaysOpen      int    `json:"daysOpen"`
    FirstSeen     string `json:"firstSeen"`     // YYYY-MM-DD
    ReopenedCount int    `json:"reopenedCount"`
}
```

### Forecast pipeline (`forecast.go`)
1. **Load** the ordered `(snapshot_date, avg_risk_score)` series from `dashboard_snapshots ORDER BY snapshot_date ASC` (done in `predict.go`; passed in as a slice so the math is DB-free and unit-testable).
2. **Degradation ladder** — the whole point of the design:
   - **n < 2** → `Direction: "unknown"`, `Confidence: "none"`, `HasForecast: false`, `Note: "insufficient history"`. No line can be fit through fewer than two points.
   - **2 ≤ n < 14** → direction from the sign of `(last − first)` only; `Confidence: "low"`, `HasForecast: false`, `Note: "early trend, not enough history to forecast"`. We will *describe* a two-week-young series but refuse to *project* it.
   - **n ≥ 14** → full OLS: compute `slope`, intercept, `rSquared`; `HasForecast: true`; project forward 14 days with a widening prediction interval.
3. **Direction** (n ≥ 14) from `slope` with a dead-band so noise doesn't read as a trend: `|slope| < flatEps` → `flat`; `slope < 0` → `improving` (lower risk score is better); `slope > 0` → `worsening`.
4. **Confidence** (n ≥ 14) from `rSquared`: `≥ 0.7` → `high`; `≥ 0.3` → `medium`; `< 0.3` → `low`. **At `low` confidence the projection is too noisy to name a direction, so `Direction` is forced to `"unclear"`** — the line is still returned for charting, but the headline word tells the truth about the fit.
5. **Prediction interval** widens with distance from the last observation (standard OLS interval: proportional to `sqrt(1/n + (x−x̄)² / Σ(xᵢ−x̄)²)`), so a far-out projection visibly carries more uncertainty than a near one. Scores clamped to `[0,100]`.

All arithmetic is hand-rolled (air-gapped; no `gonum`). The OLS closed form is `slope = Σ(xᵢ−x̄)(yᵢ−ȳ) / Σ(xᵢ−x̄)²`, `intercept = ȳ − slope·x̄`, `R² = 1 − SS_res/SS_tot`; guard `SS_tot == 0` (a perfectly flat series) → `R² = 1`, `slope = 0`, `Direction: "flat"`.

### Exposure-window pipeline (`predict.go`)
Single query over `findings WHERE status = 'open' ORDER BY first_seen ASC`, computing per row `daysOpen = floor((NOW() − first_seen) / 1 day)`:
- `OpenCount` — total open.
- `WorstDaysOpen` — max `daysOpen` (the oldest, first row).
- `MedianDaysOpen` — median of `daysOpen` (computed in Go over the ordered slice; even count → mean of the two middle values, floored).
- `OverThreshold` — count with `daysOpen > 30` (`ThresholdDays = 30`, a fixed constant this slice does not make configurable).
- `Worst` — the N oldest (default N = 10) as `ExposureItem`s, surfacing `technique_id`, `technique_name`, `severity`, `daysOpen`, `first_seen`, and `reopened_count` (a finding that has been reopened is a worse exposure story than a first-timer of the same age).
- Empty result → `HasData: false`, all counts zero. No open findings is a *good* state, reported plainly — not an error, not "insufficient data."

### API
`GET /api/predict/risk` (Viewer+, matching the Executive Dashboard endpoints it sits beside). No query parameters in this slice — forecast horizon (14d) and exposure threshold (30d) are fixed constants, not yet tunable. Returns `Prediction`; a young or empty fleet returns a well-formed `Prediction` whose sub-structs report their own insufficiency, never an error or an HTTP failure.

**The route must also be registered in `rbac_matrix_test.go`'s `routeMatrix` as `tierAny`.** `TestRBACMatrix_NoDrift` caught exactly this omission during the Executive Dashboards slice and would fail the whole `internal/api` suite otherwise — this is a known trap in this codebase, carried as an explicit plan step.

### UI (extends the existing Executive Dashboard tab)
Below the existing KPI row / sparkline on `tab-exec-dashboard`, two additions:
- **Forecast card** — the metric name, the direction word rendered honestly (`improving` green / `worsening` red / `flat` neutral / `unclear` muted / `unknown` muted), a confidence chip, and an inline-SVG chart showing history as a solid line and the projection as a dashed line inside a shaded prediction-interval band. When `HasForecast` is false, the card renders `Note` as plain text ("Insufficient history — a forecast appears after 14 days of daily snapshots") and draws only the observed points. **It never renders a placeholder number or a fabricated projection.**
- **Exposure-window table** — `OpenCount`, `WorstDaysOpen`, `MedianDaysOpen`, and `OverThreshold` as a small stat strip, then the `Worst` list as a table (technique, severity, days-open, reopened-count) with days-open past the threshold visually flagged. Empty state renders "No open findings" plainly.

Reuses the file's established `apicall()` / `x()`-escaping / `.kpi-row` / sparkline-drawing conventions from the Executive Dashboard slice. Both hardlinked copies (`wwwroot/index.html`, `cmd/server/wwwroot/index.html`) are edited and committed together; verified with `diff`, not assumed.

## Error handling / cold start
- **Fresh install, 0–1 snapshots** → `Forecast.Direction: "unknown"`, `HasForecast: false`, honest `Note`. Self-heals as snapshots accumulate.
- **2–13 snapshots** → early-trend direction, still no forecast. The two-week cold-start window is intentional and correct, not a defect.
- **≥ 14 snapshots but noisy (low R²)** → `Direction: "unclear"`, `Confidence: "low"`; the line is charted but the headline refuses to over-claim.
- **No open findings** → `ExposureWindows.HasData: false`, plainly reported as the good state it is.
- Snapshots and findings are read independently — a healthy forecast with no findings, or open findings with too-young a snapshot series, each render their own half correctly.
- Nil-safe throughout, matching `exposure.Build` / `pathcorrelation.Correlate`.

## Testing (TDD)
- `internal/predict/forecast_test.go` (**pure, no Docker**):
  - known-slope recovery — a series generated with a fixed slope recovers that slope within tolerance;
  - `R² ≈ 1.0` on a perfect line; near-zero on pure noise → `Direction: "unclear"`, `Confidence: "low"`;
  - `n = 1` → `Direction: "unknown"`, `HasForecast: false`;
  - `n = 13` → early-trend direction present, `HasForecast: false` (below-boundary);
  - `n = 14` → `HasForecast: true`, projection present (at-boundary — pins the ladder threshold);
  - prediction interval at a far horizon is wider than at a near one;
  - flat series (`SS_tot == 0`) → `Direction: "flat"`, `R² = 1`, no divide-by-zero.
- `internal/predict/predict_test.go` (Docker-backed, `testutil.MustSharedTestDB()`):
  - days-open computed correctly from a seeded `first_seen`;
  - median over an even and an odd count;
  - 30-day threshold count;
  - resolved (`status != 'open'`) findings excluded;
  - a reopened finding surfaces its `reopened_count`;
  - empty fleet → `HasData: false`, no error;
  - `Build` composes both halves (young snapshots + open findings → insufficient forecast **and** populated exposure).
- `internal/api/predict_handlers_test.go`: live round-trip; empty/young fleet returns a well-formed `Prediction`, HTTP 200, not an error.
- Manual: browser spot-check of the extended Executive Dashboard tab (forecast card states, exposure table, threshold flagging) — flagged as a known gap in the plan, same as SP4/SP6/Executive Dashboards/Recommendation Engine (no browser tool available in this environment).

## Out of scope
Attack-likelihood / breach-probability (Decision 3 — cannot be honestly substantiated by BAS data). Seasonality / ARIMA / any multi-parameter time-series model (Decision 2 — unjustifiable at daily granularity with this history). Per-asset or per-technique forecasting (fleet-level only this slice). Configurable forecast horizon or exposure threshold (fixed constants for now). Any new DB table — this package is a pure consumer of `dashboard_snapshots` and `findings`. This is the last Phase 6 subsystem; Phase 7 (Enterprise Platform) and Phase 8 (Production Readiness) are separate initiatives with their own cycles.

## Capture
Vault: new `Predictive Risk` feature note; Roadmap Phase 6 marked **complete** (all three subsystems done); daily note. An ADR **is** warranted for one decision — cutting attack-likelihood — because "we deliberately do not compute breach probability from control-test data, and here is why" is an architectural stance future contributors will re-propose and should find already answered. The forecast-ladder thresholds (14 days, R² bands) are implementation calibration captured in this spec plus the boundary tests, not an ADR.
