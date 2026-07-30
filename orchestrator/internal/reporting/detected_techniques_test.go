package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

func TestDetectedTechniques_SweepDataMarksDetected(t *testing.T) {
	detRaw := []byte(`{"techniques":[{"techniqueId":"T1059","verdict":"detected"}]}`)
	got := DetectedTechniques(detRaw, nil)
	if !got["T1059"] {
		t.Errorf("DetectedTechniques() = %v, want T1059 marked detected from sweep data", got)
	}
}

func TestDetectedTechniques_NoSweepData_FallsBackToEventClassifier(t *testing.T) {
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1003"}, Result: models.ResultFail, Events: []string{"4688"}},
	}
	got := DetectedTechniques(nil, results)
	want := ClassifyDetectionStatus([]string{"4688"}) == "Detected"
	if got["T1003"] != want {
		t.Errorf("DetectedTechniques() = %v, want T1003=%v matching ClassifyDetectionStatus", got, want)
	}
}

func TestDetectedTechniques_PassResultNeverMarkedDetected(t *testing.T) {
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultPass, Events: []string{"4688"}},
	}
	got := DetectedTechniques(nil, results)
	if got["T1059"] {
		t.Errorf("DetectedTechniques() = %v, want T1059 absent -- Pass results are never classified as Detected, only Fail results", got)
	}
}

func TestDetectedTechniques_SweepDataTakesPrecedenceOverEventClassifier(t *testing.T) {
	// Sweep data already marks T1059 detected -- the event-classifier fallback
	// loop must not run for it a second time (it's gated by !out[id]), but the
	// end result must still be detected regardless of what the events say.
	detRaw := []byte(`{"techniques":[{"techniqueId":"T1059","verdict":"detected"}]}`)
	results := []models.SimulationResult{
		{Technique: models.AttackTechnique{ID: "T1059"}, Result: models.ResultFail, Events: nil},
	}
	got := DetectedTechniques(detRaw, results)
	if !got["T1059"] {
		t.Errorf("DetectedTechniques() = %v, want T1059 detected from sweep data alone", got)
	}
}
