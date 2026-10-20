package latency

import (
	"math"
	"sort"
)

// Qualification reasons. Each names the check that failed. A failed qualification
// means the environment cannot support a security verdict for this scenario.
const (
	QReasonInsufficientSamples    = "CAL_INSUFFICIENT_SAMPLES"
	QReasonPooledSamples          = "CAL_INSUFFICIENT_POOLED_SAMPLES"
	QReasonBaselineOutOfBand      = "CAL_BASELINE_OUT_OF_BAND"
	QReasonAttackOutOfBand        = "CAL_ATTACK_OUT_OF_BAND"
	QReasonExcessiveVariance      = "CAL_EXCESSIVE_VARIANCE"
	QReasonNoResolution           = "CAL_NO_RESOLUTION"
	QReasonVulnerableBelowBudget  = "CAL_VULNERABLE_BELOW_BUDGET"
	QReasonFixedOverBudget        = "CAL_FIXED_OVER_BUDGET"
	QReasonInsufficientSeparation = "CAL_INSUFFICIENT_SEPARATION"
	QReasonBelowMinDegradation    = "CAL_BELOW_MIN_DEGRADATION"
)

// QualifyPolicy holds the declared values qualification is checked against. Every
// value is set before measurement. Calibration characterises the environment against
// them; it never changes them.
type QualifyPolicy struct {
	Policy
	Alpha              float64 // acceptable false-positive rate for the separation test
	MinSeparationRatio float64 // minimum meaningful degradation: vulnerable median / fixed median
	MinPooledSamples   int     // minimum attack samples per build, pooled over rounds, for the test
}

// Qualification is the result of qualifying one environment for one scenario.
type Qualification struct {
	Qualified     bool
	Reasons       []string // every failed check, in check order; empty when qualified
	P             float64  // two-sided Mann-Whitney p-value, tie-corrected, vulnerable vs fixed
	Ratio         float64  // vulnerable median / max(fixed median, noise floor)
	VulnMedianMs  float64
	FixedMedianMs float64
}

// Qualify checks one environment against the declared policy using measurements of
// the vulnerable and fixed builds taken under the same workload and interleaved on
// the same machine. Every failed check is recorded, so the reasons can be audited.
func Qualify(q QualifyPolicy, vuln, fixed []Round) Qualification {
	var out Qualification
	fail := func(reason string) {
		for _, r := range out.Reasons {
			if r == reason {
				return
			}
		}
		out.Reasons = append(out.Reasons, reason)
	}
	if len(vuln) == 0 || len(fixed) == 0 {
		fail(QReasonInsufficientSamples)
	}
	all := append(append([]Round(nil), vuln...), fixed...)
	for _, rd := range all {
		if len(rd.Baseline) < q.MinSamples || len(rd.Attack) < q.MinSamples {
			fail(QReasonInsufficientSamples)
		}
	}
	sumVuln, sumFixed := summarizeAll(vuln), summarizeAll(fixed)
	for _, s := range append(append([]Summary(nil), sumVuln...), sumFixed...) {
		if !inBand(s.MedianBaselineMs, q.BaselineMs, q.Tolerance) {
			fail(QReasonBaselineOutOfBand)
		}
		if s.MedianAttackMs > q.AttackMaxMs || s.P95AttackMs > q.AttackMaxMs {
			fail(QReasonAttackOutOfBand)
		}
		if noisy(s.CV, s.StdevMs, q.Policy) || noisy(s.BaselineCV, s.BaselineStdevMs, q.Policy) {
			fail(QReasonExcessiveVariance)
		}
	}

	vulnAtt, fixedAtt := attackSamples(vuln), attackSamples(fixed)
	if len(vulnAtt) < q.MinPooledSamples || len(fixedAtt) < q.MinPooledSamples {
		fail(QReasonPooledSamples)
	}
	out.VulnMedianMs, out.FixedMedianMs = median(vulnAtt), median(fixedAtt)
	ceil := q.CeilingMs
	if out.VulnMedianMs < ceil {
		fail(QReasonVulnerableBelowBudget)
	}
	if out.FixedMedianMs >= ceil {
		fail(QReasonFixedOverBudget)
	}
	// A fixed median below the noise floor is timer resolution, not a measurement. The
	// denominator is floored at the noise floor, so the ratio stays finite and never claims
	// more degradation than the clock can resolve.
	out.Ratio = out.VulnMedianMs / math.Max(out.FixedMedianMs, q.NoiseFloorMs)
	if allEqual(vulnAtt, fixedAtt) {
		// Identical measurements on both builds carry no information about separation.
		fail(QReasonNoResolution)
		out.P = 1
	} else {
		out.P = MannWhitneyP(vulnAtt, fixedAtt)
		if len(vulnAtt) > 0 && len(fixedAtt) > 0 && out.P > q.Alpha {
			fail(QReasonInsufficientSeparation)
		}
	}
	if out.Ratio < q.MinSeparationRatio {
		fail(QReasonBelowMinDegradation)
	}
	out.Qualified = len(out.Reasons) == 0
	return out
}

func summarizeAll(rs []Round) []Summary {
	out := make([]Summary, 0, len(rs))
	for _, r := range rs {
		out = append(out, Summarize(r))
	}
	return out
}

func attackSamples(rs []Round) []float64 {
	var out []float64
	for _, r := range rs {
		out = append(out, toMs(r.Attack)...)
	}
	return out
}

func allEqual(a, b []float64) bool {
	if len(a)+len(b) == 0 {
		return false
	}
	first := append(append([]float64(nil), a...), b...)[0]
	for _, x := range a {
		if x != first {
			return false
		}
	}
	for _, x := range b {
		if x != first {
			return false
		}
	}
	return true
}

// MannWhitneyP returns the two-sided p-value of the Mann-Whitney U test with the tie
// correction. Tied values receive their average rank, and the variance is reduced by the
// tie term, so measurements that repeat (timer ticks, clamped responses) are not treated as
// independent. The normal approximation is used, so callers must meet a minimum sample size;
// Qualify enforces one. The result is 1 when a side is empty or the variance is zero, which
// includes every case where all values are identical, because no separation can be shown.
func MannWhitneyP(a, b []float64) float64 {
	n1, n2 := len(a), len(b)
	if n1 == 0 || n2 == 0 {
		return 1
	}
	type obs struct {
		v    float64
		from int // 0 for a, 1 for b
	}
	all := make([]obs, 0, n1+n2)
	for _, x := range a {
		all = append(all, obs{x, 0})
	}
	for _, y := range b {
		all = append(all, obs{y, 1})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v < all[j].v })

	N := float64(n1 + n2)
	rankSumA := 0.0
	tieTerm := 0.0
	for i := 0; i < len(all); {
		j := i
		for j < len(all) && all[j].v == all[i].v {
			j++
		}
		// Positions i..j-1 share the average rank of (i+1 .. j).
		avg := float64(i+1+j) / 2
		for k := i; k < j; k++ {
			if all[k].from == 0 {
				rankSumA += avg
			}
		}
		t := float64(j - i)
		tieTerm += t*t*t - t
		i = j
	}
	u := rankSumA - float64(n1*(n1+1))/2
	mean := float64(n1) * float64(n2) / 2
	variance := float64(n1) * float64(n2) / 12 * ((N + 1) - tieTerm/(N*(N-1)))
	if variance <= 0 {
		return 1
	}
	z := (u - mean) / math.Sqrt(variance)
	return math.Erfc(math.Abs(z) / math.Sqrt2)
}
