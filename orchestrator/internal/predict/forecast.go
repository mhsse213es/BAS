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
