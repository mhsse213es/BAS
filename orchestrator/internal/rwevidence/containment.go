package rwevidence

import (
	"context"

	"github.com/audspect/bas/internal/controlval"
)

// ContainmentResult is whether the host/process targeted by an authorized
// attempt was actually isolated/contained afterward -- a verified
// postcondition, never inferred from a response-action dispatch succeeding.
// Dispatching an isolate command (e.g. the existing actions package's
// endpoint.isolate, Status=="completed") proves only that the vendor API
// accepted the request, not that the host is actually contained -- that
// distinction is the entire reason this capability gets its own observer
// contract instead of a thin adapter over that status.
type ContainmentResult string

const (
	ContainmentConfirmed     ContainmentResult = "confirmed"     // targeted host/process verified isolated/contained
	ContainmentFailed        ContainmentResult = "failed"        // verified NOT contained -- blast radius unconstrained
	ContainmentIndeterminate ContainmentResult = "indeterminate" // could not verify either way
)

// ContainmentObserver observes whether the host/process targeted by an
// authorized attempt was actually contained. No real implementation ships
// in this slice -- verifying live isolation state needs a real EPP/EDR
// endpoint, not the response-action dispatch status alone.
type ContainmentObserver interface {
	ObserveContainment(ctx context.Context, key AttemptKey) (ContainmentResult, error)
}

// FakeContainmentObserver is the only observer in this slice, keyed by
// RunID+"/"+TechniqueID. An uncaptured key returns ContainmentIndeterminate
// -- never guessed Confirmed or Failed from another key's data.
type FakeContainmentObserver struct {
	Results map[string]ContainmentResult
	Err     map[string]error
}

func containmentKey(key AttemptKey) string {
	return key.RunID + "/" + key.TechniqueID
}

func (f *FakeContainmentObserver) ObserveContainment(_ context.Context, key AttemptKey) (ContainmentResult, error) {
	k := containmentKey(key)
	if err, ok := f.Err[k]; ok {
		return "", err
	}
	if r, ok := f.Results[k]; ok {
		return r, nil
	}
	return ContainmentIndeterminate, nil
}

// containmentScopeNote is appended to every Containment Reason so no caller
// can read a Confirmed/Failed result as a claim about overall containment
// posture.
const containmentScopeNote = "scoped to the specific host/process targeted by this authorized attempt -- not a claim about overall containment posture"

// ContainmentFromObservation grades the Containment capability for tech from
// a ContainmentResult. corroboratingDetail rides along in Reason as
// supporting detail ONLY -- it never changes the Verdict by itself, same
// invariant as Recovery's corroboratingDetail.
func ContainmentFromObservation(tech Technique, result ContainmentResult, corroboratingDetail string) CapabilityResult {
	cr := CapabilityResult{Capability: CapabilityContainment, TechniqueID: tech.MitreID}
	switch result {
	case ContainmentConfirmed:
		cr.Verdict = controlval.VerdictPass
		cr.Reason = "targeted host/process was contained (" + containmentScopeNote + ")"
	case ContainmentFailed:
		cr.Verdict = controlval.VerdictFail
		cr.Reason = "targeted host/process was not contained (" + containmentScopeNote + ")"
	default:
		cr.Verdict = controlval.VerdictSkipped
		cr.SkipReason = controlval.SkipInsufficientEvidence
		cr.Reason = "could not verify containment either way (" + containmentScopeNote + ")"
	}
	if corroboratingDetail != "" {
		cr.Reason += "; corroboration: " + corroboratingDetail
	}
	return cr
}

// ContainmentResultFor combines an observer's outcome and technical error
// into a Containment CapabilityResult. An operational error takes
// precedence over any ContainmentResult, same error-precedence rule
// RecoveryResultFor and controlval.Evaluate enforce for opErr.
func ContainmentResultFor(tech Technique, result ContainmentResult, obsErr error, corroboratingDetail string) CapabilityResult {
	if obsErr != nil {
		return CapabilityResult{
			Capability:  CapabilityContainment,
			TechniqueID: tech.MitreID,
			Verdict:     controlval.VerdictError,
			Reason:      "containment observation failed: " + obsErr.Error(),
		}
	}
	return ContainmentFromObservation(tech, result, corroboratingDetail)
}
