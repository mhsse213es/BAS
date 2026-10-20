// Package latency grades timing evidence from repeated trials.
//
// Grading runs in a fixed order, and a security result is reached only when every
// earlier check passes:
//
//  1. Baseline band. Each round's baseline median must lie inside the calibrated band.
//     Outside it the environment is not the one the threshold was calibrated for: ERROR.
//  2. Sample sufficiency. Every round needs at least the declared trial count: INCONCLUSIVE.
//  3. Attack measurement band. Each round's attack median and p95 must lie at or below
//     the declared attack ceiling of the measurement, so a harness fault cannot pass
//     as a result: ERROR.
//  4. Variance. Excessive coefficient of variation on either side: INCONCLUSIVE.
//  5. Effect size and consistency. A crossing round must also show at least the
//     minimum ratio over baseline, and every round must agree: otherwise INCONCLUSIVE.
//  6. Decision. Every round crossed the budget: FAIL. Every round stayed within: PASS.
//
// Nothing here widens a threshold. A PASS can only come from step 6.
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
	P95BaselineMs    float64 `json:"p95_baseline_ms"`
	Ratio            float64 `json:"ratio"`
	CV               float64 `json:"cv"`
	BaselineCV       float64 `json:"baseline_cv"`
	StdevMs          float64 `json:"stdev_ms"`
	BaselineStdevMs  float64 `json:"baseline_stdev_ms"`
}

// Policy is the frozen timing configuration a round set is graded against. Each value
// comes from the scenario's declared policy and calibration record, never from the
// measurements themselves.
type Policy struct {
	CeilingMs    float64 // attack budget; at or above it the attack has crossed
	MinRatio     float64 // minimum attack/baseline ratio for a crossing to count as an effect
	MaxCV        float64 // coefficient of variation above which a round is too noisy
	MinSamples   int     // minimum baseline and attack samples per round
	BaselineMs   float64 // calibrated baseline median
	Tolerance    float64 // multiplicative baseline band around BaselineMs
	AttackMaxMs  float64 // upper bound of a valid attack measurement
	NoiseFloorMs float64 // spread at or below this is timer resolution, not noise
}

// Verdict is the graded result of one round set.
type Verdict struct {
	Outcome grade.Outcome
	Stage   string // the first check that decided the verdict
	Rounds  []Summary
}

// Summarize computes the statistics for one round.
func Summarize(r Round) Summary {
	att := toMs(r.Attack)
	base := toMs(r.Baseline)
	s := Summary{
		MedianAttackMs:   median(att),
		P95AttackMs:      percentile(att, 0.95),
		MedianBaselineMs: median(base),
		P95BaselineMs:    percentile(base, 0.95),
		CV:               coefficientOfVariation(att),
		BaselineCV:       coefficientOfVariation(base),
		StdevMs:          stdev(att),
		BaselineStdevMs:  stdev(base),
	}
	if s.MedianBaselineMs > 0 {
		s.Ratio = s.MedianAttackMs / s.MedianBaselineMs
	}
	return s
}

// Assess grades a round set against a policy. See the package comment for the order.
func Assess(rounds []Round, p Policy) Verdict {
	if len(rounds) == 0 {
		return inconclusive("sample", grade.ReasonInsufficientSamples, nil)
	}
	sums := make([]Summary, 0, len(rounds))
	for _, rd := range rounds {
		sums = append(sums, Summarize(rd))
	}
	for _, rd := range rounds {
		if len(rd.Baseline) < p.MinSamples || len(rd.Attack) < p.MinSamples {
			return inconclusive("sample", grade.ReasonInsufficientSamples, sums)
		}
	}
	for _, s := range sums {
		if !inBand(s.MedianBaselineMs, p.BaselineMs, p.Tolerance) {
			return verdictError("baseline", grade.ReasonEnvironmentMismatch, sums)
		}
	}
	for _, s := range sums {
		if s.MedianAttackMs > p.AttackMaxMs || s.P95AttackMs > p.AttackMaxMs {
			return verdictError("attack", grade.ReasonAttackMeasurementInvalid, sums)
		}
	}
	// The baseline must be stable for the environment check and the ratio to mean anything. This gate
	// applies to every verdict.
	for _, s := range sums {
		if noisy(s.BaselineCV, s.BaselineStdevMs, p) {
			return inconclusive("variance", grade.ReasonExcessiveVariance, sums)
		}
	}
	crossed, within := 0, 0
	for _, s := range sums {
		switch {
		case s.MedianAttackMs >= p.CeilingMs && s.P95AttackMs >= p.CeilingMs:
			// A FAIL rests on the ratio, so the attack's own spread must be stable before it counts.
			// A PASS does not rest on the spread: it needs only that every round stays under the
			// ceiling, and one outlier cannot move a sub-millisecond request above it. So the attack
			// spread gates FAIL only.
			if noisy(s.CV, s.StdevMs, p) {
				return inconclusive("variance", grade.ReasonExcessiveVariance, sums)
			}
			if s.Ratio < p.MinRatio {
				return inconclusive("effect", grade.ReasonBelowEffectSize, sums)
			}
			crossed++
		case s.MedianAttackMs < p.CeilingMs && s.P95AttackMs < p.CeilingMs:
			within++
		}
	}
	switch {
	case crossed == len(sums):
		return Verdict{Stage: "decision", Rounds: sums, Outcome: grade.Outcome{
			Result:         grade.FAIL,
			Exploitability: grade.Exploited,
			Control:        grade.Failed,
			Detection:      "not_evaluated",
			Confidence:     grade.ConfidenceEvidenceBacked,
		}}
	case within == len(sums):
		return Verdict{Stage: "decision", Rounds: sums, Outcome: grade.Outcome{
			Result:         grade.PASS,
			Exploitability: grade.NotExploited,
			Control:        grade.Enforced,
			Detection:      "not_evaluated",
			Confidence:     grade.ConfidenceEvidenceBacked,
		}}
	}
	return inconclusive("consistency", grade.ReasonInconsistentRounds, sums)
}

// BaselineInBand reports whether one baseline median lies within
// [expectedMs/tolerance, expectedMs*tolerance].
func BaselineInBand(medianMs, expectedMs, tolerance float64) bool {
	return inBand(medianMs, expectedMs, tolerance)
}

func inBand(m, expected, tol float64) bool {
	if expected <= 0 || tol <= 1 {
		return false
	}
	return m >= expected/tol && m <= expected*tol
}

// noisy reports excessive variance. A relative spread only counts when its absolute
// spread is above the noise floor. Below the floor the spread is timer resolution, and
// it cannot move a comparison against a ceiling of hundreds of milliseconds.
func noisy(cv, stdevMs float64, p Policy) bool {
	return cv > p.MaxCV && stdevMs > p.NoiseFloorMs
}

func verdictError(stage, reason string, sums []Summary) Verdict {
	return Verdict{Stage: stage, Rounds: sums, Outcome: grade.Error(reason)}
}

// inconclusive is a SKIPPED result with an inconclusive exploitability. It never
// counts as a pass.
func inconclusive(stage, reason string, sums []Summary) Verdict {
	return Verdict{Stage: stage, Rounds: sums, Outcome: grade.Outcome{
		Result:         grade.SKIPPED,
		Exploitability: grade.ExploitInconclusive,
		Control:        grade.ControlInconclusive,
		Detection:      "not_evaluated",
		Confidence:     grade.ConfidenceInconclusive,
		Reason:         reason,
	}}
}

func toMs(ds []time.Duration) []float64 {
	out := make([]float64, len(ds))
	for i, d := range ds {
		out[i] = float64(d) / float64(time.Millisecond)
	}
	return out
}

// Pooled returns the median, p95 and coefficient of variation over every sample in
// the rounds, for calibration records.
func Pooled(rounds []Round) (medianMs, p95Ms, cv float64) {
	var all []float64
	for _, r := range rounds {
		all = append(all, toMs(r.Baseline)...)
	}
	return median(all), percentile(all, 0.95), coefficientOfVariation(all)
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

func stdev(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	mean := 0.0
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))
	varSum := 0.0
	for _, x := range xs {
		varSum += (x - mean) * (x - mean)
	}
	return math.Sqrt(varSum / float64(len(xs)))
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
