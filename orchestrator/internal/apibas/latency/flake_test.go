package latency

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/grade"
)

// Deterministic grader tests for the ABUSE-002 flake. The rounds are synthetic, so these do not depend
// on the host's timing. Each expectation is written from the rule before the case is run.
//
// The rules under test:
//   - A PASS needs every round's median and p95 under the ceiling. The attack's spread does not gate a PASS.
//   - A FAIL needs every round's median and p95 at or over the ceiling, with a stable attack spread.
//   - The baseline spread gates every verdict, because the environment check depends on it.

func flakePolicy() Policy {
	return Policy{
		CeilingMs:    250,
		MinRatio:     5,
		MaxCV:        0.5,
		MinSamples:   10,
		BaselineMs:   0.18,
		Tolerance:    4,
		AttackMaxMs:  5000,
		NoiseFloorMs: 1,
	}
}

func flakeRepeat(d time.Duration, n int) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = d
	}
	return out
}

func flakeRound(baseline, attack []time.Duration) Round {
	return Round{Baseline: baseline, Attack: attack}
}

// A sub-millisecond attack under the ceiling, with one 6ms scheduler outlier, is a PASS. This is the
// case that flaked: the outlier pushed the CV over the gate and the verdict became inconclusive.
func TestSubMillisecondPassSurvivesAnOutlier(t *testing.T) {
	attack := flakeRepeat(100*time.Microsecond, 19)
	attack = append(attack, 6*time.Millisecond)
	rounds := []Round{flakeRound(flakeRepeat(120*time.Microsecond, 50), attack),
		flakeRound(flakeRepeat(120*time.Microsecond, 50), attack),
		flakeRound(flakeRepeat(120*time.Microsecond, 50), attack)}
	v := Assess(rounds, flakePolicy())
	if v.Outcome.Result != grade.PASS || v.Outcome.Control != grade.Enforced {
		t.Fatalf("outlier on a fast request = %s/%s, want PASS/enforced", v.Outcome.Result, v.Outcome.Reason)
	}
}

// A slow attack that crosses the ceiling in every round, with a stable spread, is a FAIL.
func TestStableCrossingIsFail(t *testing.T) {
	rounds := []Round{}
	for i := 0; i < 3; i++ {
		rounds = append(rounds, flakeRound(flakeRepeat(200*time.Microsecond, 50), flakeRepeat(1200*time.Millisecond, 10)))
	}
	v := Assess(rounds, flakePolicy())
	if v.Outcome.Result != grade.FAIL || v.Outcome.Exploitability != grade.Exploited {
		t.Fatalf("stable crossing = %s/%s, want FAIL/exploited", v.Outcome.Result, v.Outcome.Reason)
	}
}

// A crossing with an unstable attack spread is not a FAIL. The ratio cannot be trusted, so the verdict
// is inconclusive, not exploited.
func TestUnstableCrossingIsInconclusive(t *testing.T) {
	spread := []time.Duration{}
	for i := 0; i < 10; i++ {
		if i%2 == 0 {
			spread = append(spread, 100*time.Millisecond)
		} else {
			spread = append(spread, 1000*time.Millisecond)
		}
	}
	rounds := []Round{}
	for i := 0; i < 3; i++ {
		rounds = append(rounds, flakeRound(flakeRepeat(200*time.Microsecond, 50), spread))
	}
	v := Assess(rounds, flakePolicy())
	if v.Outcome.Result == grade.FAIL {
		t.Fatalf("unstable crossing graded FAIL, want inconclusive")
	}
	if v.Outcome.Result != grade.SKIPPED || v.Outcome.Reason != grade.ReasonExcessiveVariance {
		t.Fatalf("unstable crossing = %s/%s, want SKIPPED/EXCESSIVE_VARIANCE", v.Outcome.Result, v.Outcome.Reason)
	}
}

// An unstable baseline gates every verdict, including a PASS, because the environment check depends on it.
func TestUnstableBaselineGatesPass(t *testing.T) {
	base := []time.Duration{}
	for i := 0; i < 50; i++ {
		if i%5 == 0 {
			base = append(base, 5*time.Millisecond)
		} else {
			base = append(base, 100*time.Microsecond)
		}
	}
	rounds := []Round{flakeRound(base, flakeRepeat(100*time.Microsecond, 10)), flakeRound(base, flakeRepeat(100*time.Microsecond, 10)), flakeRound(base, flakeRepeat(100*time.Microsecond, 10))}
	v := Assess(rounds, flakePolicy())
	if v.Outcome.Result != grade.SKIPPED || v.Outcome.Reason != grade.ReasonExcessiveVariance {
		t.Fatalf("unstable baseline = %s/%s, want SKIPPED/EXCESSIVE_VARIANCE", v.Outcome.Result, v.Outcome.Reason)
	}
}
