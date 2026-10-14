package rwevidence

import "github.com/audspect/bas/internal/controlval"

// PreventionExpectationFor builds the controlval.Expectation for tech's
// Prevention capability: an authorized test identity's destructive attempt
// is expected to be Blocked by the deployed control.
func PreventionExpectationFor(tech Technique) controlval.Expectation {
	return controlval.Expectation{
		Expected:      controlval.OutcomeBlocked,
		MinConfidence: controlval.ConfidenceHigh,
	}
}

// PreventionFromValidation adapts an existing controlval.Validation
// (already produced by controlval.Evaluate against some Provider) into a
// Prevention CapabilityResult. It only translates -- it never recomputes or
// overrides what Evaluate already decided.
func PreventionFromValidation(tech Technique, v controlval.Validation) CapabilityResult {
	return CapabilityResult{
		Capability:  CapabilityPrevention,
		TechniqueID: tech.MitreID,
		Verdict:     v.Verdict,
		SkipReason:  v.SkipReason,
		Reason:      v.Reason,
		Provenance:  v.Key,
	}
}
