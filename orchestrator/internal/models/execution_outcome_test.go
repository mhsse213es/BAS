package models

import (
	"math"
	"testing"
)

func step(result CheckResult) SimulationResult { return SimulationResult{Result: result} }

func failed(status string, raw string) SimulationResult {
	return SimulationResult{
		Result:           ResultError,
		ExecutionFailure: &ExecutionFailure{ExecutionStatus: status, SecurityVerdict: "not_assessed"},
		RawOutput:        raw,
	}
}

func TestExecutionOutcomeOf(t *testing.T) {
	cases := []struct {
		name string
		r    SimulationResult
		want ExecutionOutcome
	}{
		{"pass ran", step(ResultPass), OutcomeExecuted},
		{"fail ran", step(ResultFail), OutcomeExecuted},
		{"blocked by a control", step(ResultBlocked), OutcomePrevented},
		{"vetoed by policy", step(ResultVetoed), OutcomeNotExecuted},
		{"missing prerequisite", failed("not_executed", ""), OutcomeNotExecuted},
		{"timed out with no output", failed("timed_out", ""), OutcomeTimedOut},
		{"timed out after producing output", failed("timed_out", "partial output"), OutcomePartiallyExecuted},
		{"execution error", failed("execution_error", ""), OutcomeExecutionError},
		{"cancelled mid-run", failed("cancelled", ""), OutcomeCancelled},
		{"error without a normalised failure", SimulationResult{Result: ResultError}, OutcomeExecutionError},
		{"skipped: platform unavailable", SimulationResult{Result: ResultSkipped, SkipReason: "platform-unavailable"}, OutcomeUnsupported},
		{"skipped: content missing", SimulationResult{Result: ResultSkipped, SkipReason: "missing-content"}, OutcomeUnsupported},
		{"skipped: condition false", SimulationResult{Result: ResultSkipped, SkipReason: "condition_false"}, OutcomeSkipped},
		{"no result recorded", SimulationResult{}, OutcomeNotExecuted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ExecutionOutcomeOf(c.r); got != c.want {
				t.Errorf("ExecutionOutcomeOf = %q, want %q", got, c.want)
			}
		})
	}
}

// The worked example from execut.txt: 100 scheduled, 80 executed, 10 not executed, 5 timed out, 3 execution errors,
// 2 intentionally skipped. Coverage is executed over scheduled, so it is 80%.
func TestComputeExecutionCoverage_DocExample(t *testing.T) {
	var results []SimulationResult
	for i := 0; i < 80; i++ {
		results = append(results, step(ResultPass))
	}
	for i := 0; i < 10; i++ {
		results = append(results, failed("not_executed", ""))
	}
	for i := 0; i < 5; i++ {
		results = append(results, failed("timed_out", ""))
	}
	for i := 0; i < 3; i++ {
		results = append(results, failed("execution_error", ""))
	}
	for i := 0; i < 2; i++ {
		results = append(results, SimulationResult{Result: ResultSkipped, SkipReason: "condition_false"})
	}
	c := ComputeExecutionCoverage(results)
	if c.Scheduled != 100 || c.Executed != 80 || c.NotExecuted != 10 || c.TimedOut != 5 || c.ExecutionError != 3 || c.Skipped != 2 {
		t.Errorf("counts = %+v", c)
	}
	if math.Abs(c.CoveragePct-80) > 1e-9 {
		t.Errorf("CoveragePct = %v, want 80", c.CoveragePct)
	}
}

// A blocked technique was attempted and gave the control a chance to act, so it counts as covered. Unsupported steps
// stay in the denominator: a step the endpoint could not run is a coverage gap, not a free pass.
func TestComputeExecutionCoverage_PreventedCountsAsCovered(t *testing.T) {
	results := []SimulationResult{
		step(ResultBlocked),
		step(ResultPass),
		{Result: ResultSkipped, SkipReason: "platform-unavailable"},
		failed("timed_out", "half output"),
	}
	c := ComputeExecutionCoverage(results)
	if c.Prevented != 1 || c.Executed != 1 || c.Unsupported != 1 || c.PartiallyExecuted != 1 {
		t.Errorf("counts = %+v", c)
	}
	if c.Covered() != 2 {
		t.Errorf("Covered() = %d, want 2 (executed + prevented)", c.Covered())
	}
	if math.Abs(c.CoveragePct-50) > 1e-9 {
		t.Errorf("CoveragePct = %v, want 50", c.CoveragePct)
	}
}

func TestComputeExecutionCoverage_EmptyRunIsZeroNotNaN(t *testing.T) {
	c := ComputeExecutionCoverage(nil)
	if c.Scheduled != 0 || c.CoveragePct != 0 || math.IsNaN(c.CoveragePct) {
		t.Errorf("empty = %+v", c)
	}
}
