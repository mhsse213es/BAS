// Package driftanalytics derives stability/drift metrics from a control's
// technique-verification history. Every function here is pure -- no
// database or network access -- so the algorithm is fully unit-testable
// without a container. Callers (internal/api) build the ordered,
// normalized sequence from technique_verification_runs and pass it in.
package driftanalytics

import "time"

// VerificationOutcome is one already-normalized, binary result in a
// control's ordered history. Result is always "pass" or "fail" --
// models.ResultBlocked normalizes to "pass" (the control prevented the
// technique from running, a security win) and
// models.ResultError/ResultSkipped rows are dropped entirely before
// building this slice.
type VerificationOutcome struct {
	Result string
	At     time.Time
}

// DriftStats is the full set of derived stability metrics for one
// (agent_id, check_id) pair's pooled history, across every remediation
// request ever made for it.
type DriftStats struct {
	TotalRuns              int
	PassCount              int
	FailCount              int
	StabilityPercent       float64 // PassCount / TotalRuns * 100; 0 if TotalRuns == 0
	DriftCount             int     // count of PASS -> FAIL transitions
	LongestPassStreak      int
	LongestFailStreak      int
	CurrentStreakResult    string // "pass" or "fail"; "" if TotalRuns == 0
	CurrentStreakLength    int
	CurrentStreakStartedAt *time.Time  // when the current (still-open) streak began
	AverageDaysUntilDrift  float64     // mean duration (days) of every PASS-streak that ended in a drift; 0 if DriftCount == 0
	DriftEvents            []time.Time // the timestamp of the FAIL that caused each drift, one per DriftCount, in order
	FirstVerifiedAt        *time.Time
	LastVerifiedAt         *time.Time
}

// ComputeDriftStats derives DriftStats from an ordered (oldest-first)
// binary sequence via a single linear walk. Drift is strictly a
// PASS->FAIL transition -- a bare FAIL streak with no preceding PASS is
// never counted (there's nothing to drift from).
func ComputeDriftStats(runs []VerificationOutcome) DriftStats {
	var s DriftStats
	s.TotalRuns = len(runs)
	if s.TotalRuns == 0 {
		return s
	}
	s.FirstVerifiedAt = &runs[0].At
	s.LastVerifiedAt = &runs[len(runs)-1].At

	streakResult := runs[0].Result
	streakStart := runs[0].At
	streakLen := 0
	var driftDurationsDays []float64

	flushStreak := func() {
		if streakResult == "pass" && streakLen > s.LongestPassStreak {
			s.LongestPassStreak = streakLen
		}
		if streakResult == "fail" && streakLen > s.LongestFailStreak {
			s.LongestFailStreak = streakLen
		}
	}

	for i, r := range runs {
		if r.Result == "pass" {
			s.PassCount++
		} else {
			s.FailCount++
		}

		if i > 0 && runs[i-1].Result != r.Result {
			if runs[i-1].Result == "pass" && r.Result == "fail" {
				s.DriftCount++
				driftDurationsDays = append(driftDurationsDays, r.At.Sub(streakStart).Hours()/24)
				s.DriftEvents = append(s.DriftEvents, r.At)
			}
			flushStreak()
			streakResult = r.Result
			streakStart = r.At
			streakLen = 0
		}
		streakLen++
	}
	flushStreak() // close out the final (current) streak

	s.CurrentStreakResult = streakResult
	s.CurrentStreakLength = streakLen
	s.CurrentStreakStartedAt = &streakStart
	s.StabilityPercent = float64(s.PassCount) / float64(s.TotalRuns) * 100
	if len(driftDurationsDays) > 0 {
		var sum float64
		for _, d := range driftDurationsDays {
			sum += d
		}
		s.AverageDaysUntilDrift = sum / float64(len(driftDurationsDays))
	}
	return s
}
