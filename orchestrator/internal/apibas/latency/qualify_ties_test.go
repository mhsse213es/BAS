package latency

import (
	"testing"
)

// Tie handling and minimum sample requirements. All inputs are fixed values.

func repeat(n int, v float64) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// Two constant, disjoint groups of ten are fully separated even though every value is tied.
func TestTiedButDisjointGroupsSeparate(t *testing.T) {
	a := repeat(10, 0)
	b := repeat(10, 0.5)
	if p := MannWhitneyP(a, b); p > 0.001 {
		t.Fatalf("disjoint tied groups gave p=%g, want below 0.001", p)
	}
}

// Overlapping groups full of ties are not separable.
func TestHeavilyTiedOverlapIsNotSeparable(t *testing.T) {
	a := append(repeat(8, 0), repeat(2, 0.5)...)
	b := append(repeat(8, 0), repeat(2, 0.5)...)
	if p := MannWhitneyP(a, b); p < 0.9 {
		t.Fatalf("identical tied groups gave p=%g, want near 1", p)
	}
}

// Identical values everywhere: no variance, so no separation, reported explicitly.
func TestAllIdenticalMeasurementsHaveNoResolution(t *testing.T) {
	if p := MannWhitneyP(repeat(10, 0.5), repeat(10, 0.5)); p != 1 {
		t.Fatalf("all-identical samples gave p=%g, want 1", p)
	}
	vuln := buildRounds(3, spread(10, 0.14), uniform(10, 0.5))
	fixed := buildRounds(3, spread(10, 0.14), uniform(10, 0.5))
	q := qpolicy()
	q.MinPooledSamples = 20
	res := Qualify(q, vuln, fixed)
	if res.Qualified || !hasReason(res, QReasonNoResolution) {
		t.Fatalf("all-identical measurements gave %v, want CAL_NO_RESOLUTION", res.Reasons)
	}
}

// Pooled attack samples per build must meet the declared minimum.
func TestPooledMinimumIsEnforced(t *testing.T) {
	vuln := buildRounds(3, spread(10, 0.14), spread(10, 1300))
	fixed := buildRounds(3, spread(10, 0.14), spread(10, 0.1, 0.2))
	q := qpolicy()
	q.MinPooledSamples = 31
	if res := Qualify(q, vuln, fixed); !hasReason(res, QReasonPooledSamples) {
		t.Fatalf("30 pooled samples passed a minimum of 31: %v", res.Reasons)
	}
	q.MinPooledSamples = 30
	if res := Qualify(q, vuln, fixed); hasReason(res, QReasonPooledSamples) {
		t.Fatalf("30 pooled samples failed a minimum of 30: %v", res.Reasons)
	}
}

// The ties-aware statistic is deterministic for identical input.
func TestTieCorrectedStatisticIsDeterministic(t *testing.T) {
	a := []float64{0, 0, 0.5, 0.5, 1300, 1310}
	b := []float64{0, 0.5, 0.5, 0.5, 0.5, 0.5}
	if MannWhitneyP(a, b) != MannWhitneyP(a, b) {
		t.Fatal("tie-corrected p-value differs between runs")
	}
}
