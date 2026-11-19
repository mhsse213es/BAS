package reporting

import "testing"

// A run with no valid (scored) result cannot claim High result confidence, even when none of its steps errored.
func TestBuildReliability_NoValidResultIsNotHighConfidence(t *testing.T) {
	r := buildReliability(ExecutiveSummary{VetoedTechniques: 3, SkippedTechniques: 3})
	if r.Valid != 0 {
		t.Fatalf("Valid = %d, want 0", r.Valid)
	}
	if r.Confidence == "High" || r.Confidence == "Medium" || r.Confidence == "Low" {
		t.Errorf("Confidence = %q for a run with no valid result, want it not assessed", r.Confidence)
	}
}

// A run with valid results keeps the error-share confidence bands.
func TestBuildReliability_ValidRunKeepsConfidenceBand(t *testing.T) {
	r := buildReliability(ExecutiveSummary{PassedTechniques: 4, FailedTechniques: 1})
	if r.Confidence != "High" {
		t.Errorf("Confidence = %q, want High", r.Confidence)
	}
}
