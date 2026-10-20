package killchain

// StageResult is one stage's state and verdict as read from storage.
type StageResult struct {
	Key     string
	State   StageState
	Verdict Verdict // empty until the stage reaches a terminal verdict
}

// Rollup summarises a campaign. It is derived from stage results and is never
// stored as the source of truth.
type Rollup struct {
	// Status is "partial" (some stage has no terminal verdict), "failed" (an
	// ALLOWED or ERROR stage exists) or "completed". It never says "passed".
	Status string          `json:"status"`
	Counts map[Verdict]int `json:"counts"`
	Total  int             `json:"total"`
	// Reached excludes NOT_TESTED stages, so an unreached stage never improves a figure.
	Reached int  `json:"reached"`
	Failed  bool `json:"failed"`
}

// Roll derives the campaign rollup. Any ALLOWED or ERROR stage makes the
// campaign failed, regardless of the others. Any stage without a terminal
// verdict makes it partial, and partial takes precedence over failed so that
// an incomplete run is never reported as settled.
func Roll(results []StageResult) Rollup {
	r := Rollup{Counts: map[Verdict]int{}, Total: len(results)}
	partial := false
	for _, s := range results {
		if s.State == StateInterrupted {
			// An interrupted run is never settled, even when it has a verdict.
			partial = true
		}
		if s.Verdict == "" {
			partial = true
			continue
		}
		r.Counts[s.Verdict]++
		if s.Verdict != VerdictNotTested {
			r.Reached++
		}
		if s.Verdict == VerdictAllowed || s.Verdict == VerdictError {
			r.Failed = true
		}
	}
	switch {
	case partial:
		r.Status = "partial"
	case r.Failed:
		r.Status = "failed"
	default:
		r.Status = "completed"
	}
	return r
}
