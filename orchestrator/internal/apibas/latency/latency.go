// Package latency grades timing evidence from repeated trials. A timing result is
// FAIL only when every round crosses the frozen ceiling. A noisy or inconsistent
// set of rounds is ERROR, never PASS.
package latency

import (
	"math"
	"sort"
	"time"

	"github.com/audspect/bas/internal/apibas/grade"
)

// Round is one repeated measurement: baseline and attack samples taken together.
type Round struct {
	Baseline []time.Duration
	Attack   []time.Duration
}

// Summary holds the statistics for one round.
type Summary struct {
	MedianAttackMs   float64 `json:"median_attack_ms"`
	P95AttackMs      float64 `json:"p95_attack_ms"`
	MedianBaselineMs float64 `json:"median_baseline_ms"`
	Ratio            float64 `json:"ratio"`
	CV               float64 `json:"cv"`
}

// Summarize computes the statistics for one round.
func Summarize(r Round) Summary {
	att := toMs(r.Attack)
	base := toMs(r.Baseline)
	s := Summary{
		MedianAttackMs:   median(att),
		P95AttackMs:      percentile(att, 0.95),
		MedianBaselineMs: median(base),
		CV:               coefficientOfVariation(att),
	}
	if s.MedianBaselineMs > 0 {
		s.Ratio = s.MedianAttackMs / s.MedianBaselineMs
	}
	return s
}

// Grade applies the frozen policy to every round. A round is noisy when its
// coefficient of variation exceeds maxCV. A round crosses when its attack median
// and p95 are at or above the ceiling and the attack median is at least minRatio
// times the baseline median. A round is within budget when both attack statistics
// are below the ceiling. Every round must agree before a result is returned.
func Grade(rounds []Round, ceiling time.Duration, minRatio, maxCV float64) (grade.Outcome, []Summary) {
	sums := make([]Summary, 0, len(rounds))
	for _, rd := range rounds {
		sums = append(sums, Summarize(rd))
	}
	if len(sums) == 0 {
		return grade.Error(grade.ReasonInconsistentRounds), sums
	}
	ceilMs := float64(ceiling) / float64(time.Millisecond)
	crossed, within := 0, 0
	for _, s := range sums {
		switch {
		case s.CV > maxCV:
			return grade.Error(grade.ReasonNoisyMeasurement), sums
		case s.MedianAttackMs >= ceilMs && s.P95AttackMs >= ceilMs && s.Ratio >= minRatio:
			crossed++
		case s.MedianAttackMs < ceilMs && s.P95AttackMs < ceilMs:
			within++
		}
	}
	switch {
	case crossed == len(sums):
		return grade.Outcome{
			Result:         grade.FAIL,
			Exploitability: grade.Exploited,
			Control:        grade.Failed,
			Detection:      "not_evaluated",
			Confidence:     grade.ConfidenceEvidenceBacked,
		}, sums
	case within == len(sums):
		return grade.Outcome{
			Result:         grade.PASS,
			Exploitability: grade.NotExploited,
			Control:        grade.Enforced,
			Detection:      "not_evaluated",
			Confidence:     grade.ConfidenceEvidenceBacked,
		}, sums
	default:
		return grade.Error(grade.ReasonInconsistentRounds), sums
	}
}

func toMs(ds []time.Duration) []float64 {
	out := make([]float64, len(ds))
	for i, d := range ds {
		out[i] = float64(d) / float64(time.Millisecond)
	}
	return out
}

func sorted(xs []float64) []float64 {
	c := append([]float64(nil), xs...)
	sort.Float64s(c)
	return c
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	c := sorted(xs)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

// percentile uses the nearest-rank method.
func percentile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	c := sorted(xs)
	idx := int(math.Ceil(q*float64(len(c)))) - 1
	if idx < 0 {
		idx = 0
	}
	return c[idx]
}

func coefficientOfVariation(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	mean := 0.0
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))
	if mean == 0 {
		return 0
	}
	varSum := 0.0
	for _, x := range xs {
		varSum += (x - mean) * (x - mean)
	}
	return math.Sqrt(varSum/float64(len(xs))) / mean
}

// CalibrationOK reports whether the measured baseline, the median of every round's
// baseline samples, lies within [expectedMs/tolerance, expectedMs*tolerance]. Outside
// that band the frozen threshold was not calibrated for these conditions, so timing
// must not be graded.
func CalibrationOK(rounds []Round, expectedMs, tolerance float64) bool {
	var all []float64
	for _, r := range rounds {
		all = append(all, toMs(r.Baseline)...)
	}
	if len(all) == 0 || expectedMs <= 0 || tolerance <= 1 {
		return false
	}
	m := median(all)
	return m >= expectedMs/tolerance && m <= expectedMs*tolerance
}
