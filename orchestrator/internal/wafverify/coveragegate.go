package wafverify

import "fmt"

// CoverageGateScenario is the claim that the testing program's own
// scenario coverage meets a declared minimum ratio.
type CoverageGateScenario struct {
	ID              string
	Description     string
	Provenance      string
	MinimumCoverage float64
}

// NewCoverageGateScenario validates at construction time, never at
// render time. minimumCoverage must be in [0.0, 1.0] inclusive.
func NewCoverageGateScenario(id string, description string, provenance string, minimumCoverage float64) (CoverageGateScenario, error) {
	if id == "" {
		return CoverageGateScenario{}, fmt.Errorf("id must not be empty")
	}
	if description == "" {
		return CoverageGateScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return CoverageGateScenario{}, fmt.Errorf("provenance must not be empty")
	}
	if minimumCoverage < 0.0 || minimumCoverage > 1.0 {
		return CoverageGateScenario{}, fmt.Errorf("minimumCoverage must be in [0.0, 1.0], got %v", minimumCoverage)
	}
	return CoverageGateScenario{ID: id, Description: description, Provenance: provenance, MinimumCoverage: minimumCoverage}, nil
}

// CoverageGateStatus is the outcome of comparing exercised scenarios
// against total scenarios for a declared minimum ratio.
type CoverageGateStatus string

const (
	CoverageGatePass         CoverageGateStatus = "pass"
	CoverageGateFail         CoverageGateStatus = "fail"
	CoverageGateInconclusive CoverageGateStatus = "inconclusive"
)

// EvaluateCoverageGate errors on an invalid count pair (a caller bug,
// not a measurable outcome) but returns CoverageGateInconclusive as a
// normal status -- not an error -- for the degenerate totalScenarios<=0
// case, since a catalog of size zero is a real, if degenerate, state.
func EvaluateCoverageGate(scenario CoverageGateScenario, totalScenarios int, exercisedScenarios int) (CoverageGateStatus, string, error) {
	if exercisedScenarios < 0 {
		return "", "", fmt.Errorf("exercisedScenarios must not be negative, got %d", exercisedScenarios)
	}
	if exercisedScenarios > totalScenarios {
		return "", "", fmt.Errorf("exercisedScenarios (%d) must not exceed totalScenarios (%d)", exercisedScenarios, totalScenarios)
	}
	if totalScenarios <= 0 {
		return CoverageGateInconclusive, "totalScenarios is zero or negative; there is nothing to measure", nil
	}
	ratio := float64(exercisedScenarios) / float64(totalScenarios)
	if ratio >= scenario.MinimumCoverage {
		return CoverageGatePass, fmt.Sprintf("coverage ratio %.4f meets the minimum %.4f", ratio, scenario.MinimumCoverage), nil
	}
	return CoverageGateFail, fmt.Sprintf("coverage ratio %.4f is below the minimum %.4f", ratio, scenario.MinimumCoverage), nil
}
