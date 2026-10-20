package latency

import (
	"math"
	"slices"
	"testing"
	"time"
)

// Deterministic qualification tests. No timing is measured here: every input is a
// fixed list of durations, so the grader is validated independently of the machine.

func qpolicy() QualifyPolicy {
	return QualifyPolicy{
		Policy: Policy{CeilingMs: 250, MaxCV: 0.5, MinSamples: 10, BaselineMs: 0.14, Tolerance: 4, AttackMaxMs: 5000, NoiseFloorMs: 1},
		Alpha:  0.01, MinSeparationRatio: 5,
	}
}

// spread returns n durations cycling through the given values in milliseconds.
func spread(n int, vals ...float64) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = ms(vals[i%len(vals)])
	}
	return out
}

// buildRounds returns k rounds with the given baseline and attack samples.
func buildRounds(k int, base, att []time.Duration) []Round {
	out := make([]Round, k)
	for i := range out {
		out[i] = Round{Baseline: base, Attack: att}
	}
	return out
}

func cleanVuln() []Round {
	return buildRounds(3, spread(10, 0.13, 0.14, 0.15), spread(10, 1290, 1300, 1310))
}

func cleanFixed() []Round {
	return buildRounds(3, spread(10, 0.13, 0.14, 0.15), spread(10, 0.1, 0.2, 0.3))
}

func hasReason(q Qualification, reason string) bool {
	return slices.Contains(q.Reasons, reason)
}

func TestQualifiesWhenBothBuildsAreSeparableWithinBudget(t *testing.T) {
	q := Qualify(qpolicy(), cleanVuln(), cleanFixed())
	if !q.Qualified || len(q.Reasons) != 0 {
		t.Fatalf("clean environment not qualified: %v", q.Reasons)
	}
	if q.P > 1e-6 {
		t.Fatalf("clearly separated builds gave p=%g", q.P)
	}
}

func TestQualifyIsDeterministic(t *testing.T) {
	a := Qualify(qpolicy(), cleanVuln(), cleanFixed())
	b := Qualify(qpolicy(), cleanVuln(), cleanFixed())
	if a.P != b.P || a.Qualified != b.Qualified || !slices.Equal(a.Reasons, b.Reasons) {
		t.Fatal("two runs on identical input disagreed")
	}
}

// --- separation: distributions that overlap are not separable -----------------------

func TestSeparationFailsWhenAlphaIsStrict(t *testing.T) {
	p := qpolicy()
	p.Alpha = 1e-300
	q := Qualify(p, cleanVuln(), cleanFixed())
	if q.Qualified || !hasReason(q, QReasonInsufficientSeparation) {
		t.Fatalf("strict alpha gave %v, want insufficient separation", q.Reasons)
	}
}

func TestMannWhitneyIdenticalSamplesAreNotSeparable(t *testing.T) {
	a := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if p := MannWhitneyP(a, a); p < 0.9 {
		t.Fatalf("identical samples gave p=%g, want near 1", p)
	}
}

func TestMannWhitneyDisjointSamplesAreSeparable(t *testing.T) {
	a := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	b := []float64{101, 102, 103, 104, 105, 106, 107, 108, 109, 110}
	if p := MannWhitneyP(a, b); p > 0.001 {
		t.Fatalf("disjoint samples gave p=%g, want below 0.001", p)
	}
}

func TestMannWhitneyEmptySideShowsNothing(t *testing.T) {
	if p := MannWhitneyP(nil, []float64{1, 2}); p != 1 {
		t.Fatalf("empty side gave p=%g, want 1", p)
	}
}

// --- degradation: the minimum meaningful ratio is a declared boundary --------------

func TestMinSeparationRatioBoundary(t *testing.T) {
	vuln := buildRounds(3, spread(10, 0.14), spread(10, 1300))
	fixed := buildRounds(3, spread(10, 0.14), spread(10, 1.0)) // floor is 1 ms, so ratio is 1300
	p := qpolicy()
	p.MinSeparationRatio = 1300
	if q := Qualify(p, vuln, fixed); hasReason(q, QReasonBelowMinDegradation) {
		t.Fatal("ratio exactly at the minimum should qualify")
	}
	p.MinSeparationRatio = 1300.1
	if q := Qualify(p, vuln, fixed); !hasReason(q, QReasonBelowMinDegradation) {
		t.Fatal("ratio just under the minimum should fail")
	}
}

// --- budget reachability: the environment must be able to show both outcomes -------

func TestVulnerableMustReachBudget(t *testing.T) {
	q := Qualify(qpolicy(), buildRounds(3, spread(10, 0.14), spread(10, 240)), cleanFixed())
	if !hasReason(q, QReasonVulnerableBelowBudget) {
		t.Fatalf("vulnerable under budget gave %v", q.Reasons)
	}
}

func TestVulnerableAtCeilingIsReachable(t *testing.T) {
	q := Qualify(qpolicy(), buildRounds(3, spread(10, 0.14), spread(10, 250)), cleanFixed())
	if hasReason(q, QReasonVulnerableBelowBudget) {
		t.Fatal("vulnerable exactly at the ceiling should reach the budget")
	}
}

func TestFixedMustStayWithinBudget(t *testing.T) {
	q := Qualify(qpolicy(), cleanVuln(), buildRounds(3, spread(10, 0.14), spread(10, 250)))
	if !hasReason(q, QReasonFixedOverBudget) {
		t.Fatalf("fixed at the ceiling gave %v, want over-budget", q.Reasons)
	}
}

// --- environment drift and noise -------------------------------------------------

func TestBaselineDriftIsRecorded(t *testing.T) {
	vuln := buildRounds(3, spread(10, 1.0), spread(10, 1300))
	q := Qualify(qpolicy(), vuln, cleanFixed())
	if q.Qualified || !hasReason(q, QReasonBaselineOutOfBand) {
		t.Fatalf("baseline drift gave %v", q.Reasons)
	}
}

func TestAttackOutOfBandIsRecorded(t *testing.T) {
	q := Qualify(qpolicy(), buildRounds(3, spread(10, 0.14), spread(10, 6000)), cleanFixed())
	if !hasReason(q, QReasonAttackOutOfBand) {
		t.Fatalf("attack over band gave %v", q.Reasons)
	}
}

func TestNoisyRunIsRecorded(t *testing.T) {
	noisy := buildRounds(3, spread(10, 0.14), []time.Duration{ms(10), ms(2000), ms(10), ms(2000), ms(10), ms(2000), ms(10), ms(2000), ms(10), ms(2000)})
	q := Qualify(qpolicy(), noisy, cleanFixed())
	if !hasReason(q, QReasonExcessiveVariance) {
		t.Fatalf("noisy run gave %v", q.Reasons)
	}
}

// Sub-floor jitter on the fixed build is timer resolution, not noise.
func TestSubFloorFixedJitterDoesNotDisqualify(t *testing.T) {
	fixed := buildRounds(3, spread(10, 0.14), spread(10, 0.1, 0.9))
	q := Qualify(qpolicy(), cleanVuln(), fixed)
	if hasReason(q, QReasonExcessiveVariance) {
		t.Fatalf("sub-floor jitter disqualified: %v", q.Reasons)
	}
}

// --- sample counts ---------------------------------------------------------------

func TestTooFewSamplesIsRecorded(t *testing.T) {
	short := buildRounds(3, spread(9, 0.14), spread(9, 1300))
	q := Qualify(qpolicy(), short, cleanFixed())
	if q.Qualified || !hasReason(q, QReasonInsufficientSamples) {
		t.Fatalf("short rounds gave %v", q.Reasons)
	}
}

func TestMissingBuildIsRecorded(t *testing.T) {
	q := Qualify(qpolicy(), nil, cleanFixed())
	if q.Qualified || !hasReason(q, QReasonInsufficientSamples) {
		t.Fatalf("missing vulnerable build gave %v", q.Reasons)
	}
}

// --- every failure is recorded, not just the first --------------------------------

func TestAllFailedChecksAreReported(t *testing.T) {
	q := Qualify(qpolicy(), buildRounds(3, spread(10, 1.0), spread(10, 6000)), cleanFixed())
	for _, want := range []string{QReasonBaselineOutOfBand, QReasonAttackOutOfBand} {
		if !hasReason(q, want) {
			t.Errorf("missing reason %s in %v", want, q.Reasons)
		}
	}
}

// --- ratio edge: a fixed median below the noise floor uses the floor ---------------

// A zero fixed median is timer resolution. The ratio uses the noise floor instead, so it is
// finite and never overstates the degradation the clock can resolve.
func TestSubFloorFixedMedianUsesNoiseFloor(t *testing.T) {
	fixed := buildRounds(3, spread(10, 0.14), spread(10, 0))
	q := Qualify(qpolicy(), cleanVuln(), fixed)
	want := q.VulnMedianMs / 1.0
	if math.IsInf(q.Ratio, 0) || math.Abs(q.Ratio-want) > 1e-9 {
		t.Fatalf("ratio = %v, want vulnerable median over the 1 ms floor = %v", q.Ratio, want)
	}
}
