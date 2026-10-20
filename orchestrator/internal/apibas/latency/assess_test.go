package latency

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/grade"
)

// These tests are deterministic. They feed fixed durations to Assess and never touch a
// network, so the grader is validated independently of live timing.

// policy matches the ABUSE-002 declared values: ceiling 250 ms, minimum ratio 5, max CV
// 0.5, 10 trials per round, baseline 0.15 ms within a 4x band, attack valid up to 5000 ms.
func policy() Policy {
	return Policy{CeilingMs: 250, MinRatio: 5, MaxCV: 0.5, MinSamples: 10, BaselineMs: 0.15, Tolerance: 4, AttackMaxMs: 5000, NoiseFloorMs: 1}
}

func ms(v float64) time.Duration { return time.Duration(v * float64(time.Millisecond)) }

// uniform returns n samples of the same duration.
func uniform(n int, v float64) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = ms(v)
	}
	return out
}

// round builds one round of n samples on each side, all identical.
func round(n int, baselineMs, attackMs float64) Round {
	return Round{Baseline: uniform(n, baselineMs), Attack: uniform(n, attackMs)}
}

func rounds(k int, r Round) []Round {
	out := make([]Round, k)
	for i := range out {
		out[i] = r
	}
	return out
}

func assertResult(t *testing.T, v Verdict, result grade.Result, reason string) {
	t.Helper()
	if v.Outcome.Result != result || v.Outcome.Reason != reason {
		t.Fatalf("got %s / %q (stage %s), want %s / %q", v.Outcome.Result, v.Outcome.Reason, v.Stage, result, reason)
	}
}

// --- vulnerable and fixed variants -------------------------------------------------

func TestVulnerableVariantReproduciblyFails(t *testing.T) {
	v := Assess(rounds(3, round(10, 0.15, 1340)), policy())
	if v.Outcome.Result != grade.FAIL || v.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("vulnerable got %s / %s, want FAIL / exploited", v.Outcome.Result, v.Outcome.Exploitability)
	}
	if v.Stage != "decision" {
		t.Fatalf("stage = %s, want decision", v.Stage)
	}
}

func TestFixedVariantStaysWithinBudgetAndPasses(t *testing.T) {
	v := Assess(rounds(3, round(10, 0.15, 0.5)), policy())
	if v.Outcome.Result != grade.PASS || v.Outcome.Exploitability != grade.NotExploited {
		t.Fatalf("fixed got %s / %s, want PASS / not_exploited", v.Outcome.Result, v.Outcome.Exploitability)
	}
}

// --- baseline drift: the environment is not the calibrated one -> ERROR -------------

func TestBaselineDriftIsErrorNeverPass(t *testing.T) {
	cases := map[string]float64{"slow machine": 1.0, "fast machine": 0.01}
	for name, base := range cases {
		v := Assess(rounds(3, round(10, base, 0.5)), policy())
		assertResult(t, v, grade.ERROR, grade.ReasonEnvironmentMismatch)
		if v.Stage != "baseline" {
			t.Errorf("%s: stage = %s, want baseline", name, v.Stage)
		}
	}
}

func TestBaselineDriftInOneRoundIsError(t *testing.T) {
	rs := []Round{round(10, 0.15, 0.5), round(10, 1.0, 0.5), round(10, 0.15, 0.5)}
	assertResult(t, Assess(rs, policy()), grade.ERROR, grade.ReasonEnvironmentMismatch)
}

// --- attack-side drift: the measurement is outside its valid band -> ERROR ---------

func TestAttackMedianAboveValidBandIsError(t *testing.T) {
	v := Assess(rounds(3, round(10, 0.15, 6000)), policy())
	assertResult(t, v, grade.ERROR, grade.ReasonAttackMeasurementInvalid)
}

func TestAttackP95AboveValidBandIsError(t *testing.T) {
	// Nine fast samples and one slow sample: median is valid, p95 is not.
	att := append(uniform(9, 300), ms(6000))
	rs := rounds(3, Round{Baseline: uniform(10, 0.15), Attack: att})
	assertResult(t, Assess(rs, policy()), grade.ERROR, grade.ReasonAttackMeasurementInvalid)
}

// --- noisy samples -> INCONCLUSIVE (SKIPPED), never PASS or FAIL -------------------

func TestNoisyAttackIsInconclusive(t *testing.T) {
	att := []time.Duration{ms(10), ms(2000), ms(10), ms(2000), ms(10), ms(2000), ms(10), ms(2000), ms(10), ms(2000)}
	rs := rounds(3, Round{Baseline: uniform(10, 0.15), Attack: att})
	v := Assess(rs, policy())
	assertResult(t, v, grade.SKIPPED, grade.ReasonExcessiveVariance)
	if v.Outcome.Exploitability != grade.ExploitInconclusive {
		t.Fatalf("noisy exploitability = %s, want inconclusive", v.Outcome.Exploitability)
	}
}

func TestNoisyBaselineIsInconclusive(t *testing.T) {
	base := append(uniform(9, 0.05), ms(9))
	rs := rounds(3, Round{Baseline: base, Attack: uniform(10, 0.5)})
	assertResult(t, Assess(rs, policy()), grade.SKIPPED, grade.ReasonExcessiveVariance)
}

// --- sample counts -> INCONCLUSIVE --------------------------------------------------

func TestTooFewSamplesIsInconclusive(t *testing.T) {
	rs := rounds(3, round(9, 0.15, 1340))
	assertResult(t, Assess(rs, policy()), grade.SKIPPED, grade.ReasonInsufficientSamples)
}

func TestTooFewAttackSamplesIsInconclusive(t *testing.T) {
	rs := rounds(3, Round{Baseline: uniform(10, 0.15), Attack: uniform(4, 1340)})
	assertResult(t, Assess(rs, policy()), grade.SKIPPED, grade.ReasonInsufficientSamples)
}

func TestNoRoundsIsInconclusive(t *testing.T) {
	assertResult(t, Assess(nil, policy()), grade.SKIPPED, grade.ReasonInsufficientSamples)
}

// --- threshold boundaries -----------------------------------------------------------

// The ceiling is inclusive on the crossing side: an attack at exactly 250 ms has crossed.
func TestCeilingBoundary(t *testing.T) {
	if v := Assess(rounds(3, round(10, 0.15, 250)), policy()); v.Outcome.Result != grade.FAIL {
		t.Fatalf("attack at ceiling = %s, want FAIL", v.Outcome.Result)
	}
	if v := Assess(rounds(3, round(10, 0.15, 249.9)), policy()); v.Outcome.Result != grade.PASS {
		t.Fatalf("attack just under ceiling = %s, want PASS", v.Outcome.Result)
	}
}

// The attack band is inclusive: 5000 ms is valid, 5001 ms is not.
func TestAttackBandBoundary(t *testing.T) {
	if v := Assess(rounds(3, round(10, 0.15, 5000)), policy()); v.Outcome.Reason == grade.ReasonAttackMeasurementInvalid {
		t.Fatal("attack at the band edge should be valid")
	}
	assertResult(t, Assess(rounds(3, round(10, 0.15, 5001)), policy()), grade.ERROR, grade.ReasonAttackMeasurementInvalid)
}

// The baseline band is inclusive: 0.6 ms (4x) is valid, 0.601 ms is not.
func TestBaselineBandBoundary(t *testing.T) {
	if v := Assess(rounds(3, round(10, 0.6, 0.5)), policy()); v.Outcome.Reason == grade.ReasonEnvironmentMismatch {
		t.Fatal("baseline at the band edge should be valid")
	}
	assertResult(t, Assess(rounds(3, round(10, 0.601, 0.5)), policy()), grade.ERROR, grade.ReasonEnvironmentMismatch)
}

// A crossing below the minimum effect size is INCONCLUSIVE. The declared policy
// cannot be met by the frozen band alone, so this uses an explicit higher minimum.
func TestBelowEffectSizeIsInconclusive(t *testing.T) {
	p := policy()
	p.MinRatio = 1e9
	assertResult(t, Assess(rounds(3, round(10, 0.15, 260)), p), grade.SKIPPED, grade.ReasonBelowEffectSize)
}

// Rounds that disagree are not reproducible, so they are INCONCLUSIVE, never FAIL.
func TestMixedRoundsAreInconsistent(t *testing.T) {
	rs := []Round{round(10, 0.15, 1340), round(10, 0.15, 0.5), round(10, 0.15, 1340)}
	assertResult(t, Assess(rs, policy()), grade.SKIPPED, grade.ReasonInconsistentRounds)
}

// --- invariant: a validity failure is never a PASS ----------------------------------

func TestValidityFailuresNeverPass(t *testing.T) {
	cases := map[string][]Round{
		"baseline drift":      rounds(3, round(10, 1.0, 0.5)),
		"attack over band":    rounds(3, round(10, 0.15, 6000)),
		"too few samples":     rounds(3, round(9, 0.15, 0.5)),
		"noisy attack":        rounds(3, Round{Baseline: uniform(10, 0.15), Attack: []time.Duration{ms(1), ms(900), ms(1), ms(900), ms(1), ms(900), ms(1), ms(900), ms(1), ms(900)}}),
		"no rounds":           nil,
		"mixed across rounds": {round(10, 0.15, 1340), round(10, 0.15, 0.5), round(10, 0.15, 1340)},
	}
	for name, rs := range cases {
		if v := Assess(rs, policy()); v.Outcome.Result == grade.PASS || v.Outcome.Result == grade.FAIL {
			t.Errorf("%s produced %s, want ERROR or SKIPPED", name, v.Outcome.Result)
		}
	}
}

// Identical inputs give identical verdicts. Grading has no hidden state.
func TestAssessIsDeterministic(t *testing.T) {
	rs := rounds(3, round(10, 0.15, 1340))
	a, b := Assess(rs, policy()), Assess(rs, policy())
	if a.Outcome != b.Outcome || a.Stage != b.Stage {
		t.Fatal("two runs on identical input disagreed")
	}
}

// Sub-millisecond answers with timer-tick jitter have a high CV but a spread far below
// the noise floor. The fixed-build refusal is this shape, and it must not be INCONCLUSIVE.
func TestTimerResolutionJitterBelowFloorIsNotNoise(t *testing.T) {
	att := []time.Duration{ms(0.1), ms(0.9), ms(0.1), ms(0.9), ms(0.1), ms(0.9), ms(0.1), ms(0.9), ms(0.1), ms(0.9)}
	rs := rounds(3, Round{Baseline: uniform(10, 0.15), Attack: att})
	v := Assess(rs, policy())
	if v.Outcome.Result != grade.PASS {
		t.Fatalf("sub-floor jitter got %s / %q, want PASS", v.Outcome.Result, v.Outcome.Reason)
	}
}
