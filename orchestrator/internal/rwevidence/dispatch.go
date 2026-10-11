package rwevidence

import "strings"

// StepInput is the minimal shape EvaluateStep needs from one dispatched
// scenario step's outcome. The caller (internal/api) maps its own
// scenario.Step/models.SimulationResult onto this -- rwevidence never
// imports scenario or models, keeping it a pure evidence/logic package.
type StepInput struct {
	RunID       string
	Action      string // scenario.TaskID(step.TechniqueID, step.Name), built by the caller
	TechniqueID string
	StepName    string
	CheckResult string // "pass"/"fail"/"skipped"/"error"/"vetoed", mirrors models.CheckResult's string values
	Details     string // the step's raw output/detail text, for skip-pattern matching
}

// reconnaissanceStepNames are the modeled-technique steps that only
// enumerate/observe and never attempt the destructive behavior. Matched
// against StepInput.StepName.
var reconnaissanceStepNames = map[string]bool{
	"VSS Snapshot Enumeration":         true,
	"VSS + Backup Catalog Enumeration": true,
}

// classifyRansomwareStep is the first stage of EvaluateStep's decision tree
// (spec section B, rules 1-3). modeled reports whether TechniqueID is one of
// the 3 this package supports. isAttempt reports whether this step tried
// the destructive/attempted behavior (false for recon and for unmodeled
// techniques). specificReason is set whenever this function alone can
// already determine the row's fate without calling any evaluator --
// "technique_not_mapped", "not_an_attempt", "gate_not_confirmed",
// "no_target_precondition", or "skip_unclassified". It is empty when the
// attempt genuinely ran and needs real evaluation (Task 3).
func classifyRansomwareStep(in StepInput) (modeled bool, isAttempt bool, specificReason string) {
	switch in.TechniqueID {
	case "T1490", "T1486", "T1567.002":
		modeled = true
	default:
		return false, false, "technique_not_mapped"
	}

	if reconnaissanceStepNames[in.StepName] {
		return true, false, "not_an_attempt"
	}

	if in.CheckResult != "skipped" {
		return true, true, ""
	}

	lower := strings.ToLower(in.Details)
	switch {
	case strings.Contains(lower, "bas_confirm_vss_delete not set"):
		return true, true, "gate_not_confirmed"
	case strings.Contains(lower, "no c: vss shadow copies exist"):
		return true, true, "no_target_precondition"
	default:
		return true, true, "skip_unclassified"
	}
}
