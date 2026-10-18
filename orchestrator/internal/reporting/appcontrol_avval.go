package reporting

import (
	"github.com/audspect/bas/internal/avval"
)

// AppControlToAVVal maps one application-control path result onto the AV
// Mastery correlation model. Prevention and telemetry visibility stay separate
// facts: Prevention and Execution come from the enforcement outcome, while
// Coverage comes from whether the independent sensor recorded the attempt.
//
// Sysmon process-creation telemetry is an independent sensor's observation,
// not a control's detection verdict, so Detection is always DetectionUnknown.
// "not_visible" maps to search_incomplete, never to a negative finding, because
// a process-creation sensor cannot prove that nothing happened.
func AppControlToAVVal(row AppControlPathResult) avval.CollectionResult {
	return avval.CollectionResult{
		ControlSource: avval.ControlSourceIndependentSensor,
		Coverage:      appControlCoverage(row.Visibility),
		Observations: []avval.Observation{{
			ControlSource: avval.ControlSourceIndependentSensor,
			Provider:      "sysmon_process_create",
			Prevention:    appControlPrevention(row.Outcome),
			Detection:     avval.DetectionUnknown,
			Execution:     appControlExecution(row.Outcome),
			Response:      avval.ResponseNotApplicable,
			EvidenceKind:  avval.EvidenceObserved,
			Detail:        "family=" + row.Family + " technique=" + row.Technique + " telemetry=" + row.Visibility,
		}},
	}
}

func appControlPrevention(outcome string) avval.PreventionOutcome {
	switch outcome {
	case AppCtlBlockedAsExpected:
		return avval.PreventionBlocked
	case AppCtlAllowedUnexpected, AppCtlNotEnforced, AppCtlAllowedByPolicy:
		return avval.PreventionAllowed
	}
	return avval.PreventionUnknown
}

func appControlExecution(outcome string) avval.ExecutionObservation {
	switch outcome {
	case AppCtlBlockedAsExpected:
		// The launch was prevented, so the payload process was not observed.
		return avval.ExecutionNotObserved
	case AppCtlAllowedUnexpected, AppCtlNotEnforced, AppCtlAllowedByPolicy:
		return avval.ExecutionExecuted
	}
	return avval.ExecutionUnknown
}

func appControlCoverage(visibility string) avval.Coverage {
	switch visibility {
	case "visible":
		return avval.CoverageFound
	case "not_visible":
		return avval.CoverageSearchIncomplete
	}
	return avval.CoverageSourceUnavailable
}
