package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// TestBuildDetectionSummary_HonorsVerdict verifies detection is measured from
// the explicit DetectionVerdict even when a run carries no raw event IDs.
func TestBuildDetectionSummary_HonorsVerdict(t *testing.T) {
	res := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1003"}, Result: models.ResultFail, DetectionVerdict: "detected"},
		{Technique: models.AttackTechnique{ID: "T1055"}, Result: models.ResultFail, DetectionVerdict: "undetected"},
		{Technique: models.AttackTechnique{ID: "T1071"}, Result: models.ResultFail, DetectionVerdict: "detected"},
		{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultPass, DetectionVerdict: "prevented"},
	}
	s := buildDetectionSummary(res)
	if !s.TelemetryObserved {
		t.Error("verdict-only results should count as telemetry observed")
	}
	if s.ExecutedUnprevented != 3 {
		t.Errorf("ExecutedUnprevented=%d want 3", s.ExecutedUnprevented)
	}
	if s.Detected != 2 || s.Undetected != 1 {
		t.Errorf("Detected=%d Undetected=%d want 2/1", s.Detected, s.Undetected)
	}
	score, measured := detectionScore(s)
	if !measured {
		t.Fatal("expected detection measured")
	}
	if score < 66 || score > 67 { // 2/3 = 66.7%
		t.Errorf("detection score=%.1f want ~66.7", score)
	}
}
