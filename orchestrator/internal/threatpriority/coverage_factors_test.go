package threatpriority

import (
	"context"
	"testing"
)

func TestSimulationCoverageFactor_Score(t *testing.T) {
	f := SimulationCoverageFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105", "T1566"},
		shared:       &sharedIndexes{simulation: map[string]bool{"T1059": true, "T1105": true}},
	}
	raw, explanation, available, err := f.Score(context.Background(), tctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Fatal("expected available=true")
	}
	wantPct := float64(2) / float64(3) * 100
	if raw != wantPct {
		t.Fatalf("raw = %.2f, want %.2f", raw, wantPct)
	}
	if explanation != "2 of 3 techniques have a simulation" {
		t.Fatalf("explanation = %q", explanation)
	}
}

func TestSimulationCoverageFactor_NoTechniques_Unavailable(t *testing.T) {
	f := SimulationCoverageFactor{}
	_, _, available, err := f.Score(context.Background(), Context{TechniqueIDs: nil, shared: &sharedIndexes{}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if available {
		t.Fatal("expected available=false when actor has no known techniques")
	}
}

func TestDetectionCoverageFactor_Score(t *testing.T) {
	f := DetectionCoverageFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059"},
		shared:       &sharedIndexes{detection: map[string]bool{"T1059": true}},
	}
	raw, _, available, _ := f.Score(context.Background(), tctx)
	if !available || raw != 100 {
		t.Fatalf("raw=%.2f available=%v, want 100/true", raw, available)
	}
}

func TestPurpleCoverageFactor_Score(t *testing.T) {
	f := PurpleCoverageFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059", "T1105"},
		shared:       &sharedIndexes{purple: map[string]bool{"T1059": true}},
	}
	raw, _, available, _ := f.Score(context.Background(), tctx)
	if !available || raw != 50 {
		t.Fatalf("raw=%.2f available=%v, want 50/true", raw, available)
	}
}

func TestComplianceCoverageFactor_Score(t *testing.T) {
	f := ComplianceCoverageFactor{}
	tctx := Context{
		TechniqueIDs: []string{"T1059"},
		shared:       &sharedIndexes{compliance: map[string]bool{}},
	}
	raw, _, available, _ := f.Score(context.Background(), tctx)
	if !available || raw != 0 {
		t.Fatalf("raw=%.2f available=%v, want 0/true", raw, available)
	}
}

func TestCoverageFactors_WeightScalesWithBlend(t *testing.T) {
	f := SimulationCoverageFactor{}
	low := f.Weight(Context{ValidatedCount: 0})    // coverage=0.90 -> 0.90*0.85/4
	high := f.Weight(Context{ValidatedCount: 100}) // coverage=0.20 -> 0.20*0.85/4
	if low <= high {
		t.Fatalf("expected coverage weight to shrink as validated evidence grows: low=%.4f high=%.4f", low, high)
	}
}
