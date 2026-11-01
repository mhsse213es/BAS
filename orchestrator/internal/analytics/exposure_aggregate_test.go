package analytics

import (
	"testing"

	"github.com/audspect/bas/internal/exposure"
)

// Phase 1: the fleet exposure average must use measured assets only. An
// unmeasured asset's ExposureScore is 100 by construction and must not count.
func TestAggregateExposure_ExcludesUnmeasuredAssets(t *testing.T) {
	assets := []exposure.AssetSummary{
		{ExposureScore: 40, ExposureMeasurable: true},
		{ExposureScore: 60, ExposureMeasurable: true},
		{ExposureScore: 100, ExposureMeasurable: false}, // agent-only, nothing measured
	}
	got := aggregateExposure(assets)
	if got.FleetAvgScore != 50 {
		t.Fatalf("FleetAvgScore = %d, want 50 (unmeasured asset must not raise it)", got.FleetAvgScore)
	}
	if !got.Measurable || got.MeasuredAssets != 2 || got.TotalAssets != 3 {
		t.Fatalf("measured=%d total=%d measurable=%v, want 2/3/true", got.MeasuredAssets, got.TotalAssets, got.Measurable)
	}
	if len(got.Assets) != 3 {
		t.Fatalf("Assets must keep every asset, got %d", len(got.Assets))
	}
}

func TestAggregateExposure_NothingMeasuredIsNotAScore(t *testing.T) {
	got := aggregateExposure([]exposure.AssetSummary{{ExposureScore: 100}, {ExposureScore: 100}})
	if got.Measurable {
		t.Fatal("no measured asset must not be reported as measurable")
	}
	if got.FleetAvgScore != 0 || got.MeasuredAssets != 0 || got.TotalAssets != 2 {
		t.Fatalf("got avg=%d measured=%d total=%d, want 0/0/2", got.FleetAvgScore, got.MeasuredAssets, got.TotalAssets)
	}
}

func TestAggregateExposure_EmptyFleet(t *testing.T) {
	got := aggregateExposure(nil)
	if got.Measurable || got.FleetAvgScore != 0 || got.TotalAssets != 0 {
		t.Fatalf("empty fleet = %+v", got)
	}
}
