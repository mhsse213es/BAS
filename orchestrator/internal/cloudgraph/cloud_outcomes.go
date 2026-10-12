package cloudgraph

import "time"

// CloudControlOutcome bridges graph prediction (evaluator) and execution observation
// (event correlation), surfacing where the two agree and where they diverge.
type CloudControlOutcome struct {
	// Prediction (from graph)
	PrerequisiteState PathState // Candidate/Conditional/PolicySupported/Blocked/Unknown

	// Execution outcome (from evidence)
	ExecutionOutcome string // "Allowed", "Blocked", "MFAChallenged", "Terminated", "Unknown"

	// Control information
	ControlName          string
	ControlVerdictReason string // Why the verdict was reached

	// Evidence and observation
	EventCorrelation string        // "perfect", "partial", "delayed", "none"
	CorrelatedEvents []*CloudEvent // Events matched
	TelemetryDelay   time.Duration // Time from action to event logged
	MissingTelemetry []string      // ["cloudtrail-disabled", "logs-old"] if partial/none

	// Prediction vs. reality
	GraphVsExecutionMatch bool   // true if prediction matched reality
	Mismatch              string // Description if mismatch (why prediction was wrong)
}

// NewCloudControlOutcome creates an outcome by matching evaluation result to correlation result.
// Evidence quality governs the claim: no events found means ExecutionOutcome is Unknown,
// never inferred as Allowed or Blocked from the graph prediction alone.
func NewCloudControlOutcome(evalResult *EvaluationResult, corrResult *EventSearchResult, controlName string) *CloudControlOutcome {
	outcome := &CloudControlOutcome{
		PrerequisiteState: evalResult.State,
		ControlName:       controlName,
		EventCorrelation:  corrResult.MatchQuality,
		TelemetryDelay:    corrResult.TelemetryDelay,
		MissingTelemetry:  corrResult.MissingTelemetry,
	}

	if len(corrResult.EventsFound) == 0 {
		outcome.ExecutionOutcome = "Unknown"
		outcome.ControlVerdictReason = "no audit trail found; outcome cannot be assessed"
		outcome.GraphVsExecutionMatch = false
		outcome.Mismatch = "prediction: " + string(evalResult.State) + "; execution: Unknown (no evidence)"
		return outcome
	}

	event := corrResult.EventsFound[0]
	switch event.Result {
	case "Success":
		outcome.ExecutionOutcome = "Allowed"
	case "Failure":
		outcome.ExecutionOutcome = "Blocked"
	case "MFAChallenge":
		outcome.ExecutionOutcome = "MFAChallenged"
	default:
		outcome.ExecutionOutcome = "Unknown"
	}
	outcome.CorrelatedEvents = corrResult.EventsFound

	switch {
	case evalResult.State == PolicySupported && outcome.ExecutionOutcome == "Allowed":
		outcome.GraphVsExecutionMatch = true
	case evalResult.State == Blocked && outcome.ExecutionOutcome == "Blocked":
		outcome.GraphVsExecutionMatch = true
	default:
		outcome.GraphVsExecutionMatch = false
		outcome.Mismatch = "prediction: " + string(evalResult.State) + "; execution: " + outcome.ExecutionOutcome
	}

	return outcome
}
