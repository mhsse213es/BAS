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
	// Add a little scatter so the interval has non-zero width. Slope kept
	// shallow (0.8/day) so the 14-day-out projection stays well clear of the
	// [0,100] clamp — a steep slope saturates the far bound and collapses the
	// interval, which would make this assertion about clamping, not widening.
	dates := make([]string, 20)
	scores := make([]float64, 20)
	for i := 0; i < 20; i++ {
		dates[i] = "2026-01-01"
		scores[i] = 30 + 0.8*float64(i)
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
