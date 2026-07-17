# Phase 6 Predictive Risk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `internal/predict` aggregator that forecasts the fleet risk-score trend (hand-rolled OLS over `dashboard_snapshots`, honest degradation) and measures open-finding exposure windows, surfaced at `GET /api/predict/risk` and on the existing Executive Dashboard tab.

**Architecture:** New pure-consumer package `internal/predict`, zero new DB tables — same shape as `internal/dashboard`/`internal/recommend`. `forecast.go` is DB-free math (unit-testable without Docker); `predict.go` loads snapshots + open findings and composes `Build`. One read-only handler, one route, one RBAC-matrix row, and a UI extension (not a new tab).

**Tech Stack:** Go 1.x, pgx/v5, chi router, Postgres (Docker testcontainers via `internal/testutil`), vanilla-JS single-file UI with inline SVG.

**Spec:** `docs/superpowers/specs/2026-07-17-phase6-predictive-risk-design.md`

---

## File Structure

- **Create** `orchestrator/internal/predict/forecast.go` — `Forecast`/`Point` types + pure `forecastSeries(...)` OLS. No DB imports.
- **Create** `orchestrator/internal/predict/forecast_test.go` — pure unit tests (no Docker, no `TestMain`).
- **Create** `orchestrator/internal/predict/predict.go` — `Prediction`/`ExposureWindows`/`ExposureItem` types, `Build`, snapshot + findings loaders.
- **Create** `orchestrator/internal/predict/predict_test.go` — Docker-backed tests (`TestMain` + `sharedDB`).
- **Create** `orchestrator/internal/api/predict_handlers.go` — `GetPredictRisk` handler.
- **Create** `orchestrator/internal/api/predict_handlers_test.go` — handler round-trip test.
- **Modify** `orchestrator/internal/api/routes.go:189` — register `GET /api/predict/risk`.
- **Modify** `orchestrator/internal/api/rbac_matrix_test.go:104` — add the route as `tierAny`.
- **Modify** `orchestrator/wwwroot/index.html` **and** `orchestrator/cmd/server/wwwroot/index.html` (NTFS hardlink — one inode `4503599628265725`, two paths; edit the working copy, then `git add` both; verify with `diff`) — extend the Executive Dashboard tab.

**Working directory:** every Go command runs from `orchestrator/`. The Bash tool's cwd resets between calls — prefix each with `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator &&`.

---

## Task 1: Pure OLS forecast (`forecast.go`)

**Files:**
- Create: `orchestrator/internal/predict/forecast.go`
- Test: `orchestrator/internal/predict/forecast_test.go`

The three-rung degradation ladder is the heart of this feature. `forecastSeries` takes parallel ordered slices (`dates`, `scores`) so the math never touches the DB.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/predict/forecast_test.go`:

```go
package predict

import (
	"math"
	"testing"
)

// linSeries builds n consecutive daily points y = intercept + slope*i.
func linSeries(n int, intercept, slope float64) ([]string, []float64) {
	dates := make([]string, n)
	scores := make([]float64, n)
	for i := 0; i < n; i++ {
		dates[i] = "2026-01-01"
		scores[i] = intercept + slope*float64(i)
	}
	return dates, scores
}

func TestForecastSeries_RecoversKnownSlope(t *testing.T) {
	dates, scores := linSeries(20, 50, 2) // rising risk => worsening
	fc := forecastSeries("avg_risk_score", dates, scores, 14)
	if !fc.HasForecast {
		t.Fatal("HasForecast = false, want true at n=20")
	}
	if math.Abs(fc.Slope-2) > 0.001 {
		t.Errorf("Slope = %v, want ~2", fc.Slope)
	}
	if fc.RSquared < 0.999 {
		t.Errorf("RSquared = %v, want ~1 on a perfect line", fc.RSquared)
	}
	if fc.Direction != "worsening" {
		t.Errorf("Direction = %q, want worsening (rising risk score)", fc.Direction)
	}
	if fc.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", fc.Confidence)
	}
}

func TestForecastSeries_FallingScoreIsImproving(t *testing.T) {
	dates, scores := linSeries(20, 80, -1.5)
	fc := forecastSeries("avg_risk_score", dates, scores, 14)
	if fc.Direction != "improving" {
		t.Errorf("Direction = %q, want improving (falling risk score)", fc.Direction)
	}
}

func TestForecastSeries_NoiseIsUnclear(t *testing.T) {
	// Alternating 40/60: mean ~50, slope ~0, huge residuals => R^2 ~ 0.
	dates := make([]string, 30)
	scores := make([]float64, 30)
	for i := 0; i < 30; i++ {
		dates[i] = "2026-01-01"
		if i%2 == 0 {
			scores[i] = 40
		} else {
			scores[i] = 60
		}
	}
	fc := forecastSeries("avg_risk_score", dates, scores, 14)
	if fc.Confidence != "low" {
		t.Errorf("Confidence = %q, want low on noise (R^2=%v)", fc.Confidence, fc.RSquared)
	}
	if fc.Direction != "unclear" {
		t.Errorf("Direction = %q, want unclear at low confidence", fc.Direction)
	}
	if !fc.HasForecast {
		t.Error("HasForecast = false, want true (n>=14) even when unclear — the line still charts")
	}
}

func TestForecastSeries_SinglePointUnknown(t *testing.T) {
	dates, scores := linSeries(1, 50, 0)
	fc := forecastSeries("avg_risk_score", dates, scores, 14)
	if fc.Direction != "unknown" || fc.Confidence != "none" {
		t.Errorf("n=1: Direction=%q Confidence=%q, want unknown/none", fc.Direction, fc.Confidence)
	}
	if fc.HasForecast {
		t.Error("HasForecast = true at n=1, want false")
	}
	if len(fc.History) != 1 {
		t.Errorf("History len = %d, want 1 (raw point still returned for charting)", len(fc.History))
	}
}

func TestForecastSeries_ThirteenPointsDirectionNoForecast(t *testing.T) {
	dates, scores := linSeries(13, 50, 1) // rising
	fc := forecastSeries("avg_risk_score", dates, scores, 14)
	if fc.HasForecast {
		t.Error("HasForecast = true at n=13, want false (below the 14-day floor)")
	}
	if fc.Direction != "worsening" {
		t.Errorf("Direction = %q, want worsening from first-vs-last delta", fc.Direction)
	}
	if len(fc.Projected) != 0 {
		t.Errorf("Projected len = %d, want 0 below the floor", len(fc.Projected))
	}
}

func TestForecastSeries_FourteenPointsForecastAppears(t *testing.T) {
	dates, scores := linSeries(14, 50, 1)
	fc := forecastSeries("avg_risk_score", dates, scores, 14)
	if !fc.HasForecast {
		t.Fatal("HasForecast = false at n=14, want true (at the floor)")
	}
	if len(fc.Projected) != 14 {
		t.Errorf("Projected len = %d, want 14", len(fc.Projected))
	}
}

func TestForecastSeries_IntervalWidensWithHorizon(t *testing.T) {
	// Add a little scatter so the interval has non-zero width.
	dates := make([]string, 20)
	scores := make([]float64, 20)
	for i := 0; i < 20; i++ {
		dates[i] = "2026-01-01"
		scores[i] = 50 + 1.5*float64(i)
		if i%3 == 0 {
			scores[i] += 3
		}
	}
	fc := forecastSeries("avg_risk_score", dates, scores, 14)
	near := fc.Projected[0].High - fc.Projected[0].Low
	far := fc.Projected[len(fc.Projected)-1].High - fc.Projected[len(fc.Projected)-1].Low
	if far <= near {
		t.Errorf("interval did not widen: near=%v far=%v", near, far)
	}
}

func TestForecastSeries_FlatSeriesNoDivideByZero(t *testing.T) {
	dates, scores := linSeries(20, 50, 0) // perfectly flat
	fc := forecastSeries("avg_risk_score", dates, scores, 14)
	if fc.Direction != "flat" {
		t.Errorf("Direction = %q, want flat", fc.Direction)
	}
	if math.Abs(fc.Slope) > 1e-9 {
		t.Errorf("Slope = %v, want 0", fc.Slope)
	}
	if fc.RSquared != 1 {
		t.Errorf("RSquared = %v, want 1 by convention on a flat series (SS_tot=0)", fc.RSquared)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/predict/ -run TestForecastSeries -v`
Expected: FAIL — `undefined: forecastSeries`, `undefined: Forecast` (package doesn't compile yet).

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/predict/forecast.go`:

```go
// Package predict is the Phase 6 predictive-risk aggregator: a pure consumer
// that forecasts the fleet risk-score trend from dashboard_snapshots and
// measures open-finding exposure windows. It owns no DB tables.
//
// forecast.go holds only in-memory math — no DB imports — so it is unit-testable
// without a container. The design deliberately predicts only what BAS data can
// honestly support (a trend of a measured metric), never a fabricated
// breach-probability. See the design spec for the full rationale.
package predict

import "math"

const (
	// forecastMinDays is the floor below which we describe a direction but
	// refuse to project a line — two weeks of daily snapshots.
	forecastMinDays = 14
	// forecastHorizon is how many days forward Build projects.
	forecastHorizon = 14
)

// Forecast is an OLS projection of a single dashboard metric over time.
type Forecast struct {
	Metric      string  `json:"metric"`
	Direction   string  `json:"direction"`  // improving | worsening | flat | unclear | unknown
	Confidence  string  `json:"confidence"` // high | medium | low | none
	HasForecast bool    `json:"hasForecast"`
	SampleDays  int     `json:"sampleDays"`
	History     []Point `json:"history"`
	Projected   []Point `json:"projected,omitempty"`
	Slope       float64 `json:"slope,omitempty"`
	RSquared    float64 `json:"rSquared,omitempty"`
	Note        string  `json:"note"`
}

// Point is one observed or projected value. DayIndex is the snapshot ordinal
// (0-based from the first snapshot), not a calendar offset. Date is empty for
// projected points; Low/High carry the prediction interval on projected points.
type Point struct {
	DayIndex int     `json:"dayIndex"`
	Date     string  `json:"date,omitempty"`
	Score    float64 `json:"score"`
	Low      float64 `json:"low,omitempty"`
	High     float64 `json:"high,omitempty"`
}

// forecastSeries fits an OLS trend to an ordered daily series and degrades
// honestly: n<2 -> unknown/no-forecast; 2<=n<forecastMinDays -> direction from
// first-vs-last only; n>=forecastMinDays -> full projection. dates and scores
// are parallel and already ordered oldest-first.
func forecastSeries(metric string, dates []string, scores []float64, horizon int) Forecast {
	n := len(scores)
	fc := Forecast{Metric: metric, SampleDays: n, History: make([]Point, n)}
	for i := 0; i < n; i++ {
		fc.History[i] = Point{DayIndex: i, Date: dates[i], Score: scores[i]}
	}

	if n < 2 {
		fc.Direction = "unknown"
		fc.Confidence = "none"
		fc.Note = "insufficient history"
		return fc
	}

	if n < forecastMinDays {
		fc.Confidence = "low"
		fc.Note = "early trend, not enough history to forecast"
		fc.Direction = deltaDirection(scores[0], scores[n-1])
		return fc
	}

	// Full OLS over the snapshot ordinal x = 0..n-1.
	var sx, sy float64
	for i := 0; i < n; i++ {
		sx += float64(i)
		sy += scores[i]
	}
	meanX := sx / float64(n)
	meanY := sy / float64(n)

	var sxx, sxy, sst float64
	for i := 0; i < n; i++ {
		dx := float64(i) - meanX
		dy := scores[i] - meanY
		sxx += dx * dx
		sxy += dx * dy
		sst += dy * dy
	}

	// A perfectly flat series has sst==0 (and sxy==0): slope 0, R^2 1 by convention.
	if sst == 0 {
		fc.HasForecast = true
		fc.Slope = 0
		fc.RSquared = 1
		fc.Confidence = "high"
		fc.Direction = "flat"
		fc.Note = "flat"
		fc.Projected = projectFlat(meanY, n, horizon)
		return fc
	}

	slope := sxy / sxx
	intercept := meanY - slope*meanX

	var ssr float64
	for i := 0; i < n; i++ {
		pred := intercept + slope*float64(i)
		resid := scores[i] - pred
		ssr += resid * resid
	}
	r2 := 1 - ssr/sst
	if r2 < 0 {
		r2 = 0
	}

	fc.HasForecast = true
	fc.Slope = slope
	fc.RSquared = r2
	fc.Confidence = confidenceFor(r2)

	if fc.Confidence == "low" {
		// The fit is too weak to trust the slope's sign.
		fc.Direction = "unclear"
	} else {
		fc.Direction = slopeDirection(slope, horizon)
	}
	fc.Note = ""

	// Prediction interval: s = sqrt(SS_res/(n-2)); half-width at x0 is
	// z * s * sqrt(1/n + (x0-meanX)^2 / sxx). z ~ 1.96 (normal approximation;
	// no t-table shipped in an air-gapped build).
	s := math.Sqrt(ssr / float64(n-2))
	const z = 1.96
	fc.Projected = make([]Point, 0, horizon)
	for k := 1; k <= horizon; k++ {
		x0 := float64(n - 1 + k)
		yhat := intercept + slope*x0
		hw := z * s * math.Sqrt(1.0/float64(n)+(x0-meanX)*(x0-meanX)/sxx)
		fc.Projected = append(fc.Projected, Point{
			DayIndex: n - 1 + k,
			Score:    clamp01(yhat),
			Low:      clamp01(yhat - hw),
			High:     clamp01(yhat + hw),
		})
	}
	return fc
}

func projectFlat(y float64, n, horizon int) []Point {
	out := make([]Point, 0, horizon)
	for k := 1; k <= horizon; k++ {
		out = append(out, Point{DayIndex: n - 1 + k, Score: clamp01(y), Low: clamp01(y), High: clamp01(y)})
	}
	return out
}

// slopeDirection applies a dead-band: a projected change of under one point
// across the horizon reads as flat, so noise near zero doesn't masquerade as a
// trend. Lower risk score is better, so a negative slope is "improving".
func slopeDirection(slope float64, horizon int) string {
	if math.Abs(slope*float64(horizon)) < 1.0 {
		return "flat"
	}
	if slope < 0 {
		return "improving"
	}
	return "worsening"
}

func deltaDirection(first, last float64) string {
	if last < first {
		return "improving"
	}
	if last > first {
		return "worsening"
	}
	return "flat"
}

func confidenceFor(r2 float64) string {
	switch {
	case r2 >= 0.7:
		return "high"
	case r2 >= 0.3:
		return "medium"
	default:
		return "low"
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/predict/ -run TestForecastSeries -v`
Expected: PASS (all 9 tests).

- [ ] **Step 5: gofmt + vet**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/predict/ && go vet ./internal/predict/`
Expected: no output from `gofmt` (already formatted), no vet errors.

- [ ] **Step 6: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/predict/forecast.go internal/predict/forecast_test.go
git commit -m "feat(predict): add pure OLS risk-score forecast with honest degradation

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```

---

## Task 2: `Build` + exposure windows (`predict.go`)

**Files:**
- Create: `orchestrator/internal/predict/predict.go`
- Test: `orchestrator/internal/predict/predict_test.go`

`Build` loads the snapshot series (feeding Task 1's `forecastSeries`) and measures open-finding exposure windows. Docker-backed. `first_seen` is `timestamptz NOT NULL DEFAULT NOW()`; `status` defaults `'open'`; `reopened_count int NOT NULL DEFAULT 0`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/predict/predict_test.go`:

```go
package predict

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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

// seedFinding inserts one finding whose first_seen is daysAgo days in the past.
func seedFinding(t *testing.T, pool *pgxpool.Pool, id, tech, name, sev, status string, daysAgo, reopened int) {
	t.Helper()
	mustExec(t, pool, `
		INSERT INTO findings (id, agent_id, technique_id, control_class, technique_name,
			tactic, severity, status, reopened_count, first_seen, last_seen)
		VALUES ($1, 'pa-01', $2, 'prevention', $3, 'execution', $4, $5, $6,
			NOW() - ($7::text || ' days')::interval, NOW())`,
		id, tech, name, sev, status, reopened, daysAgo)
}

func TestBuild_EmptyFleet_NoError(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		p, err := Build(context.Background(), pool)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if p.Forecast.Direction != "unknown" {
			t.Errorf("Forecast.Direction = %q, want unknown on 0 snapshots", p.Forecast.Direction)
		}
		if p.Forecast.HasForecast {
			t.Error("HasForecast = true on empty fleet, want false")
		}
		if p.Exposure.HasData {
			t.Error("Exposure.HasData = true on empty fleet, want false")
		}
		if p.Exposure.Worst == nil {
			t.Error("Exposure.Worst must be an empty slice, not nil — the UI iterates it")
		}
	})
}

func TestBuild_ExposureWindows_MeasuresDaysOpen(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedFinding(t, pool, "f-old", "T1059.001", "PowerShell", "High", "open", 90, 2)
		seedFinding(t, pool, "f-mid", "T1078", "Valid Accounts", "Critical", "open", 40, 0)
		seedFinding(t, pool, "f-new", "T1053", "Scheduled Task", "Medium", "open", 5, 0)
		seedFinding(t, pool, "f-done", "T1021", "Remote Services", "High", "resolved", 200, 0)

		p, err := Build(context.Background(), pool)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		exp := p.Exposure
		if !exp.HasData {
			t.Fatal("HasData = false, want true with open findings")
		}
		if exp.OpenCount != 3 {
			t.Errorf("OpenCount = %d, want 3 (resolved excluded)", exp.OpenCount)
		}
		if exp.WorstDaysOpen < 89 || exp.WorstDaysOpen > 91 {
			t.Errorf("WorstDaysOpen = %d, want ~90", exp.WorstDaysOpen)
		}
		if exp.MedianDaysOpen < 39 || exp.MedianDaysOpen > 41 {
			t.Errorf("MedianDaysOpen = %d, want ~40 (median of 3)", exp.MedianDaysOpen)
		}
		if exp.OverThreshold != 2 {
			t.Errorf("OverThreshold = %d, want 2 (>30d: the 90d and 40d)", exp.OverThreshold)
		}
		if len(exp.Worst) == 0 || exp.Worst[0].TechniqueID != "T1059.001" {
			t.Errorf("Worst[0] = %+v, want the 90-day T1059.001 first", exp.Worst)
		}
		if exp.Worst[0].ReopenedCount != 2 {
			t.Errorf("Worst[0].ReopenedCount = %d, want 2", exp.Worst[0].ReopenedCount)
		}
	})
}

func TestBuild_ExposureMedian_EvenCount(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedFinding(t, pool, "e1", "T1", "a", "Low", "open", 10, 0)
		seedFinding(t, pool, "e2", "T2", "b", "Low", "open", 20, 0)
		seedFinding(t, pool, "e3", "T3", "c", "Low", "open", 30, 0)
		seedFinding(t, pool, "e4", "T4", "d", "Low", "open", 40, 0)
		p, err := Build(context.Background(), pool)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		// even count: mean of the two middle (20,30) = 25.
		if p.Exposure.MedianDaysOpen < 24 || p.Exposure.MedianDaysOpen > 26 {
			t.Errorf("MedianDaysOpen = %d, want ~25 (mean of middle two)", p.Exposure.MedianDaysOpen)
		}
	})
}

func TestBuild_Forecast_FromSnapshots(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// 14 consecutive daily snapshots, rising risk score.
		for i := 0; i < 14; i++ {
			mustExec(t, pool, `
				INSERT INTO dashboard_snapshots (snapshot_date, avg_risk_score, exposure_score, detection_coverage)
				VALUES (CURRENT_DATE - $1::int, $2, 0, 0)`, 13-i, 40+i)
		}
		p, err := Build(context.Background(), pool)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if !p.Forecast.HasForecast {
			t.Error("HasForecast = false with 14 snapshots, want true")
		}
		if p.Forecast.Direction != "worsening" {
			t.Errorf("Direction = %q, want worsening on a rising series", p.Forecast.Direction)
		}
		if p.Forecast.SampleDays != 14 {
			t.Errorf("SampleDays = %d, want 14", p.Forecast.SampleDays)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/predict/ -run TestBuild -v`
Expected: FAIL — `undefined: Build`, `undefined: Prediction`.

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/predict/predict.go`:

```go
package predict

import (
	"context"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// exposureThresholdDays is the age past which an open finding counts as
	// overdue. Fixed for this slice (not yet configurable).
	exposureThresholdDays = 30
	// exposureWorstN is how many of the oldest open findings we surface.
	exposureWorstN = 10
)

// Prediction bundles the trend forecast and the measured exposure windows.
type Prediction struct {
	Forecast Forecast        `json:"forecast"`
	Exposure ExposureWindows `json:"exposure"`
}

// ExposureWindows is a measured (not modeled) view of open-finding staleness.
type ExposureWindows struct {
	OpenCount      int            `json:"openCount"`
	WorstDaysOpen  int            `json:"worstDaysOpen"`
	MedianDaysOpen int            `json:"medianDaysOpen"`
	OverThreshold  int            `json:"overThreshold"`
	ThresholdDays  int            `json:"thresholdDays"`
	Worst          []ExposureItem `json:"worst"`
	HasData        bool           `json:"hasData"`
}

type ExposureItem struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	Severity      string `json:"severity"`
	DaysOpen      int    `json:"daysOpen"`
	FirstSeen     string `json:"firstSeen"`
	ReopenedCount int    `json:"reopenedCount"`
}

// Build composes a trend forecast (from dashboard_snapshots) and exposure
// windows (from open findings). Nil-safe: an empty/young fleet returns a
// Prediction whose sub-structs report their own insufficiency, never an error.
func Build(ctx context.Context, pool *pgxpool.Pool) (Prediction, error) {
	fc, err := buildForecast(ctx, pool)
	if err != nil {
		return Prediction{}, err
	}
	exp, err := buildExposure(ctx, pool)
	if err != nil {
		return Prediction{}, err
	}
	return Prediction{Forecast: fc, Exposure: exp}, nil
}

func buildForecast(ctx context.Context, pool *pgxpool.Pool) (Forecast, error) {
	rows, err := pool.Query(ctx, `
		SELECT to_char(snapshot_date, 'YYYY-MM-DD'), avg_risk_score
		FROM dashboard_snapshots
		ORDER BY snapshot_date ASC`)
	if err != nil {
		return Forecast{}, err
	}
	defer rows.Close()
	var dates []string
	var scores []float64
	for rows.Next() {
		var d string
		var v int
		if rows.Scan(&d, &v) != nil {
			continue
		}
		dates = append(dates, d)
		scores = append(scores, float64(v))
	}
	if err := rows.Err(); err != nil {
		return Forecast{}, err
	}
	return forecastSeries("avg_risk_score", dates, scores, forecastHorizon), nil
}

func buildExposure(ctx context.Context, pool *pgxpool.Pool) (ExposureWindows, error) {
	exp := ExposureWindows{ThresholdDays: exposureThresholdDays, Worst: []ExposureItem{}}
	rows, err := pool.Query(ctx, `
		SELECT technique_id, technique_name, severity, reopened_count,
		       to_char(first_seen, 'YYYY-MM-DD'),
		       FLOOR(EXTRACT(EPOCH FROM (NOW() - first_seen)) / 86400)::int
		FROM findings
		WHERE status = 'open'
		ORDER BY first_seen ASC`)
	if err != nil {
		return exp, err
	}
	defer rows.Close()

	var days []int
	for rows.Next() {
		var it ExposureItem
		if rows.Scan(&it.TechniqueID, &it.TechniqueName, &it.Severity,
			&it.ReopenedCount, &it.FirstSeen, &it.DaysOpen) != nil {
			continue
		}
		days = append(days, it.DaysOpen)
		if it.DaysOpen > exposureThresholdDays {
			exp.OverThreshold++
		}
		if len(exp.Worst) < exposureWorstN {
			exp.Worst = append(exp.Worst, it)
		}
	}
	if err := rows.Err(); err != nil {
		return exp, err
	}

	exp.OpenCount = len(days)
	if exp.OpenCount == 0 {
		return exp, nil
	}
	exp.HasData = true
	// first_seen ASC => oldest first => days[0] is the worst.
	exp.WorstDaysOpen = days[0]
	exp.MedianDaysOpen = medianInt(days)
	return exp, nil
}

// medianInt returns the floored median of the values. Copies before sorting so
// the caller's ordering (oldest-first) is preserved.
func medianInt(vals []int) int {
	s := make([]int, len(vals))
	copy(s, vals)
	sort.Ints(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/predict/ -v`
Expected: PASS (Task 1's pure tests + Task 2's 4 Docker-backed tests). Docker must be running.

- [ ] **Step 5: gofmt + vet**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/predict/ && go vet ./internal/predict/`
Expected: no output, no errors.

- [ ] **Step 6: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/predict/predict.go internal/predict/predict_test.go
git commit -m "feat(predict): add Build with exposure-window measurement over open findings

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```

---

## Task 3: API endpoint `GET /api/predict/risk`

**Files:**
- Create: `orchestrator/internal/api/predict_handlers.go`
- Create: `orchestrator/internal/api/predict_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go:189` (after the recommend route)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:104` (after the recommend row)

The RBAC-matrix row is NOT optional: `TestRBACMatrix_NoDrift` fails the entire `internal/api` suite if a registered route is missing from `routeMatrix`. It bit the Executive Dashboards slice — carry it as a first-class step here.

- [ ] **Step 1: Write the failing handler test**

Create `orchestrator/internal/api/predict_handlers_test.go`:

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

func predictHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

type predictResp struct {
	Forecast struct {
		Direction   string `json:"direction"`
		HasForecast bool   `json:"hasForecast"`
	} `json:"forecast"`
	Exposure struct {
		OpenCount int  `json:"openCount"`
		HasData   bool `json:"hasData"`
	} `json:"exposure"`
}

func TestGetPredictRisk_EmptyFleet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := predictHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetPredictRisk(rec, httptest.NewRequest(http.MethodGet, "/api/predict/risk", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		var got predictResp
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
		}
		if got.Forecast.Direction != "unknown" {
			t.Errorf("Forecast.Direction = %q, want unknown", got.Forecast.Direction)
		}
		if got.Forecast.HasForecast {
			t.Error("HasForecast = true on empty fleet, want false")
		}
		if got.Exposure.HasData {
			t.Error("Exposure.HasData = true on empty fleet, want false")
		}
	})
}
```

Note: `sharedDB` is the package-level `*testutil.TestDB` already defined by the `internal/api` suite's `TestMain` — reuse it, do not redeclare.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run TestGetPredictRisk -v`
Expected: FAIL — `h.GetPredictRisk undefined`.

- [ ] **Step 3: Write the handler**

Create `orchestrator/internal/api/predict_handlers.go`:

```go
package api

import (
	"net/http"

	"github.com/audspect/bas/internal/predict"
)

// GetPredictRisk returns the fleet risk-score forecast and open-finding
// exposure windows — Phase 6. Read-only (Viewer+). A young or empty fleet
// returns a well-formed Prediction whose sub-structs report their own
// insufficiency, never an error.
// GET /api/predict/risk
func (h *Handler) GetPredictRisk(w http.ResponseWriter, r *http.Request) {
	p, err := predict.Build(r.Context(), h.db)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, p)
}
```

- [ ] **Step 4: Register the route**

In `orchestrator/internal/api/routes.go`, immediately after line 189 (`r.Get("/api/recommend/simulations", h.GetRecommendedSimulations)`), add:

```go

		// Predictive Risk — Phase 6. Risk-score forecast + exposure windows,
		// read-only (Viewer+).
		r.Get("/api/predict/risk", h.GetPredictRisk)
```

- [ ] **Step 5: Add the RBAC-matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after line 104 (`{http.MethodGet, "/api/recommend/simulations", tierAny, ""},`), add:

```go
	{http.MethodGet, "/api/predict/risk", tierAny, ""},
```

- [ ] **Step 6: Run the new handler test + the drift matrix test**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/ -run 'TestGetPredictRisk|TestRBACMatrix_NoDrift' -v`
Expected: PASS both.

- [ ] **Step 7: Full `internal/api` regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/`
Expected: PASS (this suite runs ~230s; it exercises the whole RBAC + handler surface).

- [ ] **Step 8: gofmt + vet + build**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/api/predict_handlers.go && go vet ./internal/api/ && go build ./...`
Expected: no output, no errors, clean build.

- [ ] **Step 9: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/predict_handlers.go internal/api/predict_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(predict): add GET /api/predict/risk endpoint

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```

---

## Task 4: UI — extend the Executive Dashboard tab

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (edit here)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` (hardlink twin — `git add` both)

Two additions below the existing `#ed-kpi-row` on `tab-exec-dashboard`: a forecast card (inline-SVG history + dashed projection + shaded interval band, honest text when `HasForecast` is false) and an exposure-window table. Reuse existing classes: `.card`, `.badge`, `.kpi-label`, `.kpi-value`, `.tiny`, `.muted`, `.empty`, `.tbl-wrap`. There is NO `.data-table` class — use `.tbl-wrap` wrapping a plain `<table>`, matching the Recommendations tab (index.html ~line 2715).

- [ ] **Step 1: Add the two containers to the tab markup**

In `orchestrator/wwwroot/index.html`, find line 2695:

```html
        <div class="kpi-row" id="ed-kpi-row"><div class="empty">Loading…</div></div>
      </div>
```

Replace it with:

```html
        <div class="kpi-row" id="ed-kpi-row"><div class="empty">Loading…</div></div>
        <div id="ed-forecast"></div>
        <div id="ed-exposure"></div>
      </div>
```

- [ ] **Step 2: Extend `loadExecDashboard` to fetch the prediction**

In `orchestrator/wwwroot/index.html`, find `loadExecDashboard` (line ~4196) and replace its body's `Promise.all` block so it also fetches `/api/predict/risk`:

```js
function loadExecDashboard() {
  var rangeEl = document.getElementById('ed-range');
  var days = rangeEl ? rangeEl.value : '90';
  Promise.all([
    apicall('/api/dashboard/current'),
    apicall('/api/dashboard/trends?days=' + encodeURIComponent(days)),
    apicall('/api/predict/risk')
  ]).then(function(res) {
    renderExecDashboard(res[0], res[1]);
    renderForecast(res[2] && res[2].forecast);
    renderExposure(res[2] && res[2].exposure);
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

- [ ] **Step 3: Add the forecast + exposure render functions**

In `orchestrator/wwwroot/index.html`, immediately after `renderExecDashboard` closes (line ~4255, the `}` before `var REC_SCENARIO = null;`), insert:

```js
function edForecastChart(fc) {
  var hist = (fc && fc.history) || [];
  var proj = (fc && fc.hasForecast && fc.projected) ? fc.projected : [];
  var all = hist.concat(proj);
  if (all.length < 2) return '';
  var w = 520, h = 120, pad = 10;
  var xs = all.map(function(p) { return p.dayIndex; });
  var minX = Math.min.apply(null, xs), maxX = Math.max.apply(null, xs);
  var rangeX = (maxX - minX) || 1;
  var vals = [];
  all.forEach(function(p) {
    vals.push(p.score);
    if (typeof p.high === 'number') vals.push(p.high);
    if (typeof p.low === 'number') vals.push(p.low);
  });
  var minY = Math.min.apply(null, vals), maxY = Math.max.apply(null, vals);
  var rangeY = (maxY - minY) || 1;
  function sx(x) { return pad + ((x - minX) / rangeX) * (w - 2 * pad); }
  function sy(v) { return (h - pad) - ((v - minY) / rangeY) * (h - 2 * pad); }
  var svg = '<svg width="100%" height="' + h + '" viewBox="0 0 ' + w + ' ' + h +
    '" preserveAspectRatio="none" style="max-width:100%;margin-top:0.5rem">';
  if (proj.length) {
    var top = proj.map(function(p) { return sx(p.dayIndex).toFixed(1) + ',' + sy(p.high).toFixed(1); });
    var bot = proj.slice().reverse().map(function(p) { return sx(p.dayIndex).toFixed(1) + ',' + sy(p.low).toFixed(1); });
    svg += '<polygon points="' + top.concat(bot).join(' ') + '" fill="var(--accent)" opacity="0.12"/>';
  }
  var histPts = hist.map(function(p) { return sx(p.dayIndex).toFixed(1) + ',' + sy(p.score).toFixed(1); }).join(' ');
  svg += '<polyline points="' + histPts + '" fill="none" stroke="var(--accent)" stroke-width="1.8"/>';
  if (proj.length && hist.length) {
    var last = hist[hist.length - 1];
    var projPts = [sx(last.dayIndex).toFixed(1) + ',' + sy(last.score).toFixed(1)]
      .concat(proj.map(function(p) { return sx(p.dayIndex).toFixed(1) + ',' + sy(p.score).toFixed(1); })).join(' ');
    svg += '<polyline points="' + projPts + '" fill="none" stroke="var(--accent)" stroke-width="1.6" stroke-dasharray="4 3"/>';
  }
  svg += '</svg>';
  return svg;
}

function edDirectionLabel(fc) {
  var d = (fc && fc.direction) || 'unknown';
  var col = 'var(--muted)';
  if (d === 'improving') col = 'var(--success)';
  else if (d === 'worsening') col = 'var(--danger)';
  return '<span style="color:' + col + ';font-weight:700;text-transform:capitalize">' + x(d) + '</span>';
}

function renderForecast(fc) {
  var el = document.getElementById('ed-forecast');
  if (!el) return;
  if (!fc) { el.innerHTML = ''; return; }
  var conf = (fc.confidence && fc.confidence !== 'none')
    ? '<span class="badge">' + x(fc.confidence) + ' confidence</span>' : '';
  var chart = edForecastChart(fc);
  var note = !fc.hasForecast
    ? '<div class="tiny muted" style="margin-top:0.4rem">' + x(fc.note || 'Insufficient history for a forecast.') + '</div>'
    : '';
  el.innerHTML = '<div class="card" style="margin-top:1rem;padding:1rem">' +
    '<div style="display:flex;justify-content:space-between;align-items:center">' +
      '<div><span class="kpi-label">Risk-score forecast</span> &nbsp;' + edDirectionLabel(fc) + '</div>' +
      conf +
    '</div>' +
    (chart || '<div class="tiny muted" style="margin-top:0.4rem">Not enough data to chart yet.</div>') +
    note +
  '</div>';
}

function renderExposure(exp) {
  var el = document.getElementById('ed-exposure');
  if (!el) return;
  if (!exp || !exp.hasData) {
    el.innerHTML = '<div class="card" style="margin-top:1rem;padding:1rem">' +
      '<span class="kpi-label">Open exposure windows</span>' +
      '<div class="tiny muted" style="margin-top:0.4rem">No open findings.</div></div>';
    return;
  }
  function stat(l, v) { return '<div><div class="kpi-label">' + l + '</div><div class="kpi-value">' + v + '</div></div>'; }
  var strip = '<div style="display:flex;gap:1.75rem;margin:0.5rem 0 0.75rem">' +
    stat('Open', exp.openCount) + stat('Worst days', exp.worstDaysOpen) +
    stat('Median days', exp.medianDaysOpen) + stat('Over ' + exp.thresholdDays + 'd', exp.overThreshold) + '</div>';
  var rows = (exp.worst || []).map(function(it) {
    var over = it.daysOpen > exp.thresholdDays;
    return '<tr>' +
      '<td><div style="font-weight:600">' + x(it.techniqueId) + '</div>' +
        '<div class="tiny muted">' + x(it.techniqueName) + '</div></td>' +
      '<td class="tiny">' + x(it.severity) + '</td>' +
      '<td style="' + (over ? 'color:var(--danger);font-weight:700' : '') + '">' + it.daysOpen + '</td>' +
      '<td class="tiny">' + x(it.firstSeen) + '</td>' +
      '<td>' + (it.reopenedCount
        ? '<span class="badge" style="color:var(--warning);border-color:var(--warning)">&times;' + it.reopenedCount + '</span>'
        : '<span class="tiny muted">&mdash;</span>') + '</td>' +
      '</tr>';
  }).join('');
  el.innerHTML = '<div class="card" style="margin-top:1rem;padding:1rem">' +
    '<span class="kpi-label">Open exposure windows</span>' + strip +
    '<div class="tbl-wrap"><table><thead><tr>' +
      '<th>Technique</th><th>Severity</th><th>Days open</th><th>First seen</th><th>Reopened</th>' +
    '</tr></thead><tbody>' + rows + '</tbody></table></div>' +
  '</div>';
}
```

- [ ] **Step 4: Sync the hardlink twin and verify identical**

The two paths share one inode, so editing `wwwroot/index.html` already changed `cmd/server/wwwroot/index.html`. Confirm — do not assume:

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && diff wwwroot/index.html cmd/server/wwwroot/index.html && echo IDENTICAL`
Expected: `IDENTICAL` (no diff output).

If `diff` shows differences (the hardlink was broken by an editor), copy the working file over the twin:
Run: `cp wwwroot/index.html cmd/server/wwwroot/index.html`
Then re-run the `diff` above and confirm `IDENTICAL`.

- [ ] **Step 5: Sanity-check the JS with a quick syntax parse**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && node --check wwwroot/index.html 2>&1 | head -5 || echo "node --check does not parse HTML; verify the three new functions have balanced braces by eye"`
Expected: `node --check` will reject HTML (it's not a .js file) — that's fine. The real check is Step 6's build embedding the file. Visually confirm `edForecastChart`, `renderForecast`, `renderExposure` each open and close their braces and the `loadExecDashboard` edit is syntactically whole.

- [ ] **Step 6: Build to confirm the embedded UI compiles into the binary**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build (the server embeds `cmd/server/wwwroot`; a broken twin would not fail the build, but this confirms nothing else regressed).

- [ ] **Step 7: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add wwwroot/index.html cmd/server/wwwroot/index.html
git commit -m "feat(predict): surface risk forecast + exposure windows on Executive Dashboard

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
git push
```

---

## Task 5: Final regression + capture

**Files:** none (verification + vault).

- [ ] **Step 1: Package-scoped regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/predict/ ./internal/api/ ./internal/dashboard/ ./internal/recommend/`
Expected: PASS all four. `internal/dashboard` and `internal/recommend` are unchanged but share the snapshot/findings tables — a sanity pass confirms no cross-package breakage.

- [ ] **Step 2: Whole-build + vet**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go vet ./internal/predict/ ./internal/api/`
Expected: clean.

- [ ] **Step 3: Update the vault (outside the git repo)**

The vault at `C:\Users\Administrator\Audspect-Vault` is NOT in the repo — update it directly, do not `git add` it.
- Create `04 Features/Predictive Risk.md` (feature note: scope, the honest-degradation ladder, the attack-likelihood cut, links to spec/plan/`project_platform_roadmap_2026h2`).
- Edit `11 Roadmaps/Roadmap.md`: move "Phase 6, Subsystem 3 — Predictive Risk" from "Next in sequence" to "Done", and note **Phase 6 complete** (all three subsystems).
- Append to `13 Daily Notes/2026-07-17.md`: the Predictive Risk build.
- If an ADR folder exists, draft an ADR capturing the "no breach-probability from control-test data" decision (per the spec's Capture section). If unsure of the ADR numbering/location, leave a note in the daily note flagging it for the user rather than guessing a filename.

- [ ] **Step 4: Update Claude memory**

Edit `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_platform_roadmap_2026h2.md`: mark Phase 6 Subsystem 3 (Predictive Risk) done and Phase 6 complete. Update the `MEMORY.md` index line if its hook text references Phase 6 status.

- [ ] **Step 5: Report completion**

Announce the feature is done, list the commits, and flag the one known gap carried by every Phase 6 slice: **no browser tool is available**, so the extended Executive Dashboard tab (forecast card states, exposure table, threshold flagging) has NOT been manually spot-checked in a browser — the user should verify it visually.

---

## Self-Review

**Spec coverage:**
- Forecast (OLS, ladder, R²-gated confidence, unclear at low, interval widening) → Task 1. ✓
- ExposureWindows (days-open, median, threshold, worst-N, reopened, resolved excluded) → Task 2. ✓
- `Build` composing both → Task 2. ✓
- `GET /api/predict/risk` Viewer+ / `tierAny` + RBAC row → Task 3. ✓
- UI extends existing tab (forecast card + exposure table, honest insufficient state) → Task 4. ✓
- Zero new DB tables → confirmed; the package only reads `dashboard_snapshots` and `findings`. ✓
- Testing split (pure `forecast_test.go` no-Docker + Docker `predict_test.go` + handler test) → Tasks 1–3. ✓
- Capture (vault feature note, roadmap, daily note, ADR for the attack-likelihood cut, memory) → Task 5. ✓

**Placeholder scan:** no TBD/TODO; every code step carries complete code; every command has an expected result. ✓

**Type consistency:** `Forecast`/`Point` defined in Task 1 and consumed unchanged in Tasks 2–4; `Prediction`/`ExposureWindows`/`ExposureItem` defined in Task 2 and consumed in Tasks 3–4. JSON field names in the handler test (`direction`, `hasForecast`, `openCount`, `hasData`) and the JS (`fc.history`, `fc.projected`, `fc.hasForecast`, `exp.worst`, `it.daysOpen`, `it.reopenedCount`) match the struct tags exactly. Handler method name `GetPredictRisk` matches across the handler, route, and test. ✓

**Grounding corrections already applied (from reading real code):** `findings` columns verified (`status`/`first_seen`/`reopened_count`/`severity`/`technique_name`); `dashboard_snapshots` columns verified (`snapshot_date`/`avg_risk_score`); route/RBAC insertion points verified at real line numbers; UI classes verified (`.card`/`.tbl-wrap`/`.badge`/`.kpi-label`/`.kpi-value` exist; `.data-table` does NOT — using `.tbl-wrap` + plain `<table>`); `sharedDB`/`TestMain`/`mustExec`/`RunWithPool` test scaffolding matches `internal/recommend`; handler test builder pattern matches `recommend_handlers_test.go`; hardlink inode confirmed shared.
