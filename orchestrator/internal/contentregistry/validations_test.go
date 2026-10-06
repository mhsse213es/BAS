package contentregistry

import "testing"

func TestNoDataExcludedFromDenominator(t *testing.T) { // A13
	rate, st := DetectionEffectiveness([]string{"DETECTED", "PREVENTED", "MISSED", "NO_DATA", "NOT_APPLICABLE", "NO_DATA"})
	if st != "OK" || rate < 0.666 || rate > 0.667 {
		t.Fatalf("rate=%v status=%s, want 2/3", rate, st)
	}
	if _, st := DetectionEffectiveness([]string{"NO_DATA", "NOT_APPLICABLE"}); st != "NO_DATA" {
		t.Fatalf("all-excluded must be NO_DATA, got %s", st)
	}
	if _, st := DetectionEffectiveness(nil); st != "NO_DATA" {
		t.Fatalf("empty must be NO_DATA, got %s", st)
	}
	// ERROR is a real outcome (counts in the denominator) but not a success.
	if rate, _ := DetectionEffectiveness([]string{"DETECTED", "ERROR"}); rate != 0.5 {
		t.Fatalf("ERROR counts against: %v", rate)
	}
}
