package latency

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/apibas/grade"
)

func ms(vals ...int) []time.Duration {
	out := make([]time.Duration, len(vals))
	for i, v := range vals {
		out[i] = time.Duration(v) * time.Millisecond
	}
	return out
}

func crossingRound() Round {
	return Round{Baseline: ms(2, 2, 2, 2, 2), Attack: ms(900, 950, 920, 940, 960)}
}

func withinRound() Round {
	return Round{Baseline: ms(2, 2, 2, 2, 2), Attack: ms(3, 3, 4, 3, 3)}
}

func TestEveryRoundCrossingIsExploitation(t *testing.T) {
	out, _ := Grade([]Round{crossingRound(), crossingRound()}, 500*time.Millisecond, 5, 0.5)
	if out.Result != grade.FAIL || out.Exploitability != grade.Exploited {
		t.Fatalf("got %s / %s, want FAIL / exploited", out.Result, out.Exploitability)
	}
}

func TestEveryRoundWithinBudgetPasses(t *testing.T) {
	out, _ := Grade([]Round{withinRound(), withinRound()}, 500*time.Millisecond, 5, 0.5)
	if out.Result != grade.PASS {
		t.Fatalf("got %s, want PASS", out.Result)
	}
}

// Rounds that disagree are never a pass: one crossing and one within budget is ERROR.
func TestDisagreeingRoundsAreError(t *testing.T) {
	out, _ := Grade([]Round{crossingRound(), withinRound()}, 500*time.Millisecond, 5, 0.5)
	if out.Result != grade.ERROR || out.Reason != grade.ReasonInconsistentRounds {
		t.Fatalf("got %s / %s, want ERROR / INCONSISTENT_ACROSS_ROUNDS", out.Result, out.Reason)
	}
}

// A noisy round is ERROR even when its median looks like a crossing.
func TestNoisyRoundIsErrorNotPass(t *testing.T) {
	noisy := Round{Baseline: ms(2, 2, 2), Attack: ms(10, 900, 10, 900, 10)}
	out, _ := Grade([]Round{noisy, noisy}, 500*time.Millisecond, 5, 0.5)
	if out.Result != grade.ERROR || out.Reason != grade.ReasonNoisyMeasurement {
		t.Fatalf("got %s / %s, want ERROR / NOISY_MEASUREMENT", out.Result, out.Reason)
	}
}

func TestNoRoundsIsError(t *testing.T) {
	out, _ := Grade(nil, 500*time.Millisecond, 5, 0.5)
	if out.Result != grade.ERROR {
		t.Fatalf("got %s, want ERROR", out.Result)
	}
}

func TestPercentileAndMedian(t *testing.T) {
	r := Round{Baseline: ms(1), Attack: ms(1, 2, 3, 4, 100)}
	s := Summarize(r)
	if s.MedianAttackMs != 3 {
		t.Errorf("median = %v, want 3", s.MedianAttackMs)
	}
	if s.P95AttackMs != 100 {
		t.Errorf("p95 = %v, want 100", s.P95AttackMs)
	}
}
