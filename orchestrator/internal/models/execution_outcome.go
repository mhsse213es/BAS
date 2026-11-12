package models

// ExecutionOutcome is what happened when a step was asked to run. It is separate from the security verdict: an outcome
// that is not "executed" or "prevented" produced no evidence about the customer's controls.
type ExecutionOutcome string

const (
	OutcomeExecuted          ExecutionOutcome = "executed"           // ran to a result: the control did or did not stop it
	OutcomePrevented         ExecutionOutcome = "prevented"          // a security control stopped the technique
	OutcomePartiallyExecuted ExecutionOutcome = "partially_executed" // started, produced output, did not finish
	OutcomeNotExecuted       ExecutionOutcome = "not_executed"       // a prerequisite was missing or policy vetoed it
	OutcomeUnsupported       ExecutionOutcome = "unsupported"        // this technique cannot run on this platform or content
	OutcomeTimedOut          ExecutionOutcome = "timed_out"          // exceeded its permitted duration with no output
	OutcomeExecutionError    ExecutionOutcome = "execution_error"    // unexpected failure
	OutcomeCancelled         ExecutionOutcome = "cancelled"          // stopped because the run was cancelled
	OutcomeSkipped           ExecutionOutcome = "skipped"            // intentionally excluded by a scenario condition
)

// ExecutionOutcomeOf maps one step's result to its outcome.
//
// Rulings made here, each a judgement call:
//   - A vetoed step is not_executed: policy stopped it before it ran.
//   - A timeout that produced output is partially_executed, not timed_out: it started, so it is not a clean no-run.
//   - A skip for an unavailable platform or missing content is unsupported; every other skip is intentional.
//   - A step with no recorded result is not_executed, never counted as covered.
func ExecutionOutcomeOf(r SimulationResult) ExecutionOutcome {
	switch r.Result {
	case ResultPass, ResultFail:
		return OutcomeExecuted
	case ResultBlocked:
		return OutcomePrevented
	case ResultVetoed:
		return OutcomeNotExecuted
	case ResultSkipped:
		switch r.SkipReason {
		case SkipReasonPlatformUnavailable, SkipReasonMissingContent:
			return OutcomeUnsupported
		}
		return OutcomeSkipped
	case ResultError:
		if r.ExecutionFailure == nil {
			return OutcomeExecutionError
		}
		switch r.ExecutionFailure.ExecutionStatus {
		case "not_executed":
			return OutcomeNotExecuted
		case "timed_out":
			if r.RawOutput != "" {
				return OutcomePartiallyExecuted
			}
			return OutcomeTimedOut
		case "cancelled":
			return OutcomeCancelled
		default:
			return OutcomeExecutionError
		}
	}
	return OutcomeNotExecuted
}

// ExecutionCoverage counts every scheduled step by outcome.
type ExecutionCoverage struct {
	Scheduled         int     `json:"scheduled"`
	Executed          int     `json:"executed"`
	Prevented         int     `json:"prevented"`
	PartiallyExecuted int     `json:"partiallyExecuted"`
	NotExecuted       int     `json:"notExecuted"`
	Unsupported       int     `json:"unsupported"`
	TimedOut          int     `json:"timedOut"`
	ExecutionError    int     `json:"executionError"`
	Cancelled         int     `json:"cancelled"`
	Skipped           int     `json:"skipped"`
	CoveragePct       float64 `json:"coveragePct"`
}

// Covered is the number of steps that produced a security result: executed or prevented.
func (c ExecutionCoverage) Covered() int { return c.Executed + c.Prevented }

// ComputeExecutionCoverage tallies the outcomes of a run's steps. Coverage is covered over scheduled, so a step the
// endpoint could not run lowers the figure rather than disappearing from it.
func ComputeExecutionCoverage(results []SimulationResult) ExecutionCoverage {
	var c ExecutionCoverage
	for _, r := range results {
		c.Scheduled++
		switch ExecutionOutcomeOf(r) {
		case OutcomeExecuted:
			c.Executed++
		case OutcomePrevented:
			c.Prevented++
		case OutcomePartiallyExecuted:
			c.PartiallyExecuted++
		case OutcomeNotExecuted:
			c.NotExecuted++
		case OutcomeUnsupported:
			c.Unsupported++
		case OutcomeTimedOut:
			c.TimedOut++
		case OutcomeExecutionError:
			c.ExecutionError++
		case OutcomeCancelled:
			c.Cancelled++
		case OutcomeSkipped:
			c.Skipped++
		}
	}
	if c.Scheduled > 0 {
		c.CoveragePct = float64(c.Covered()) * 100 / float64(c.Scheduled)
	}
	return c
}
