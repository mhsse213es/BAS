package threatpriority

import "testing"

func TestBlendWeights_Bands(t *testing.T) {
	cases := []struct {
		validated      int
		wantCoverage   float64
		wantValidation float64
	}{
		{0, 0.90, 0.10},
		{4, 0.90, 0.10},
		{5, 0.60, 0.40},
		{9, 0.60, 0.40},
		{10, 0.20, 0.80},
		{100, 0.20, 0.80},
	}
	for _, c := range cases {
		cov, val := blendWeights(c.validated)
		if cov != c.wantCoverage || val != c.wantValidation {
			t.Errorf("blendWeights(%d) = (%.2f, %.2f), want (%.2f, %.2f)",
				c.validated, cov, val, c.wantCoverage, c.wantValidation)
		}
	}
}

func TestComposite_AllAvailable_WeightsSumToOne(t *testing.T) {
	results := []FactorResult{
		{Weight: 0.5, RawScore: 100, Weighted: 50, Available: true},
		{Weight: 0.5, RawScore: 0, Weighted: 0, Available: true},
	}
	got := Composite(results)
	if got != 50 {
		t.Fatalf("Composite = %d, want 50", got)
	}
}

func TestComposite_UnavailableFactorsExcludedAndRenormalized(t *testing.T) {
	results := []FactorResult{
		{Weight: 0.5, RawScore: 100, Weighted: 50, Available: true},
		{Weight: 0.5, RawScore: 0, Weighted: 0, Available: false}, // excluded entirely
	}
	got := Composite(results)
	// Only the first factor counts: weightedSum=50, totalWeight=0.5 -> 50/0.5=100.
	if got != 100 {
		t.Fatalf("Composite = %d, want 100 (unavailable factor must not drag score down)", got)
	}
}

func TestComposite_NoFactorsAvailable_ReturnsZero(t *testing.T) {
	results := []FactorResult{
		{Weight: 0.5, Available: false},
		{Weight: 0.5, Available: false},
	}
	if got := Composite(results); got != 0 {
		t.Fatalf("Composite = %d, want 0", got)
	}
}
