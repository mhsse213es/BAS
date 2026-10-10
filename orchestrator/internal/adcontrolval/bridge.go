// Package adcontrolval bridges AD primitives into the product-neutral
// controlval model and surfaces the result as admatrix's sixth
// (control-efficacy) axis. It depends one-way on controlval, adprimitive and
// admatrix; none of those gains AD- or controlval-awareness in return (admatrix
// and controlval do not import this package -- a back-edge would be an import
// cycle and would not compile).
//
// Lab-gated boundary: this package ships the MAPPING only. Nothing here is
// wired into admatrix.CapabilityStates() or the execution path (dispatchRun),
// so the control-efficacy axis stays unevaluated in live capability output
// until genuine lab-backed provider observations exist (spec section 10).
//
// Evaluated=true means a validation RESULT exists -- not that a real security
// control was tested. A synthetic or fake-backed validation is still
// Evaluated=true; it is the provider's EvidenceKind/Confidence and the
// lab-gated boundary, not the Evaluated flag, that distinguish verified
// protection from a seam exercise.
package adcontrolval

import (
	"github.com/audspect/bas/internal/admatrix"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
)

// ActionForPrimitive maps a primitive to the opaque controlval Action id. The
// mapping is the primitive id VERBATIM -- no normalization or regeneration --
// so the correlation key stays stable across the four evidence streams.
func ActionForPrimitive(p adprimitive.Primitive) string { return p.ID }

// CorrelationKeyFor builds the controlval key for checking p's control response
// in a given run/target/time window. p carries no run context, so the caller
// supplies it (mirrors addetect.VerifyRequestFor). Every field is carried
// verbatim.
func CorrelationKeyFor(p adprimitive.Primitive, runID, target string, window controlval.TimeWindow) controlval.CorrelationKey {
	return controlval.CorrelationKey{
		RunID:  runID,
		Target: target,
		Action: ActionForPrimitive(p),
		Window: window,
	}
}

// ToEfficacyState maps a controlval.Validation to the admatrix-local axis view.
// A produced validation is always Evaluated. A nil observation contributes no
// provider/outcome/evidenceKind/confidence -- those stay empty, never
// manufactured.
func ToEfficacyState(v controlval.Validation) admatrix.ControlEfficacyState {
	s := admatrix.ControlEfficacyState{
		Evaluated: true,
		Verdict:   string(v.Verdict),
		Expected:  string(v.Expectation.Expected),
		Reason:    v.Reason,
	}
	if v.Observation != nil {
		s.Provider = v.Observation.Provider
		s.Observed = string(v.Observation.Outcome)
		s.EvidenceKind = string(v.Observation.EvidenceKind)
		s.Confidence = string(v.Observation.Confidence)
	}
	return s
}

// Attach returns a COPY of cs with its control-efficacy axis set from v. It
// never touches the five existing axes.
func Attach(cs admatrix.CapabilityState, v controlval.Validation) admatrix.CapabilityState {
	cs.ControlEfficacy = ToEfficacyState(v)
	return cs
}
