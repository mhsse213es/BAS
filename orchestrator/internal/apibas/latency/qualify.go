package latency

import (
	"math"
)

// Qualification reasons. Each names the check that failed. A failed qualification
// means the environment cannot support a security verdict for this scenario.
const (
	QReasonInsufficientSamples    = "CAL_INSUFFICIENT_SAMPLES"
	QReasonBaselineOutOfBand      = "CAL_BASELINE_OUT_OF_BAND"
	QReasonAttackOutOfBand        = "CAL_ATTACK_OUT_OF_BAND"
	QReasonExcessiveVariance      = "CAL_EXCESSIVE_VARIANCE"
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
}

// Qualification is the result of qualifying one environment for one scenario.
type Qualification struct {
	Qualified     bool
	Reasons       []string // every failed check, in check order; empty when qualified
	P             float64  // two-sided Mann-Whitney p-value, vulnerable vs fixed attack samples
	Ratio         float64  // vulnerable median / fixed median of pooled attack samples
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
	out.P = MannWhitneyP(vulnAtt, fixedAtt)
	if len(vulnAtt) > 0 && len(fixedAtt) > 0 && out.P > q.Alpha {
		fail(QReasonInsufficientSeparation)
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

// MannWhitneyP returns the two-sided p-value of the Mann-Whitney U test, using the
// normal approximation without a tie correction. Samples are timing measurements in
// nanosecond resolution, so exact ties are rare. The result is 1 when either side is
// empty or the variance is zero, because no separation can be shown then.
func MannWhitneyP(a, b []float64) float64 {
	n1, n2 := float64(len(a)), float64(len(b))
	if n1 == 0 || n2 == 0 {
		return 1
	}
	u := 0.0
	for _, x := range a {
		for _, y := range b {
			switch {
			case x > y:
				u++
			case x == y:
				u += 0.5
			}
		}
	}
	mean := n1 * n2 / 2
	sd := math.Sqrt(n1 * n2 * (n1 + n2 + 1) / 12)
	if sd == 0 {
		return 1
	}
	z := (u - mean) / sd
	return math.Erfc(math.Abs(z) / math.Sqrt2)
}
