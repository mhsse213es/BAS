// Vertical 1b: rights-gating control-efficacy for WMI remote process
// creation. This is the one file in `latmove` that depends on `controlval` --
// an intentional, planned coupling (spec section 1 sequencing), not scope
// creep: it reuses the generic engine exactly as `adefficacy` reused it for
// DCSync, rather than inventing a second expectation/verdict model.
package latmove

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/controlval"
)

// Principal roles for the rights-gating pair. Generic across techniques: the
// pairing shape (an identity that holds the required rights vs. one that
// doesn't) is the same for every technique this package validates.
const (
	PrincipalAuthorized   = "authorized"   // holds the rights the technique requires on the destination
	PrincipalUnprivileged = "unprivileged" // lacks those rights
)

// NegativeExpectationFor: the unprivileged principal's attempt at tech must be
// denied. Generic across techniques -- PolicyBasis names the technique so the
// rationale stays specific without a per-technique function.
func NegativeExpectationFor(tech Technique) controlval.Expectation {
	return controlval.Expectation{
		Expected:       controlval.OutcomeBlocked,
		PolicyBasis:    fmt.Sprintf("unprivileged principal lacks the rights %s requires on the destination", tech.Name),
		PolicyVerified: false,
		MinConfidence:  controlval.ConfidenceHigh,
	}
}

// PositiveExpectationFor: the authorized principal's attempt at tech must
// succeed (the positive control that makes a negative denial trustworthy).
func PositiveExpectationFor(tech Technique) controlval.Expectation {
	return controlval.Expectation{
		Expected:       controlval.OutcomeAllowed,
		PolicyBasis:    fmt.Sprintf("authorized principal holds the rights %s requires on the destination (positive control)", tech.Name),
		PolicyVerified: false,
		MinConfidence:  controlval.ConfidenceHigh,
	}
}

// NegativeExpectation/PositiveExpectation: WMI-specific convenience wrappers
// kept for Vertical 1b's existing call sites; equivalent to calling the *For
// functions with WMIRemoteProcessCreation().
func NegativeExpectation() controlval.Expectation {
	return NegativeExpectationFor(WMIRemoteProcessCreation())
}
func PositiveExpectation() controlval.Expectation {
	return PositiveExpectationFor(WMIRemoteProcessCreation())
}

// ControlProvider adapts an ExecutionObserver + ClassifyAttempt to
// controlval.Provider. It performs no attempt itself. ProviderName identifies
// which technique's provider this is (e.g. "latmove-wmi",
// "latmove-remote-service"); a zero value is invalid for a real caller but
// harmless for tests that don't assert on Name().
type ControlProvider struct {
	Obs          ExecutionObserver
	ProviderName string
}

func (p *ControlProvider) Name() string { return p.ProviderName }

// Observe maps a controlval.CorrelationKey to a latmove.AttemptKey (RunID and
// Action/Technique carry straight through; Target becomes Destination -- the
// correlation key has no Source field, mirroring adefficacy's DCSync key,
// where the principal under test is distinguished by RunID, not by a key
// field), classifies the resulting Observation, and maps the result to a
// controlval.Observation. ClassifyAttempt's ambiguity rules (spec section 2)
// are the sole source of Outcome/Confidence here -- never re-derived.
func (p *ControlProvider) Observe(ctx context.Context, key controlval.CorrelationKey) (controlval.Observation, error) {
	ak := AttemptKey{
		RunID:       key.RunID,
		Destination: key.Target,
		Technique:   key.Action,
		Window:      TimeWindow{Start: key.Window.Start, End: key.Window.End},
	}
	obs, err := p.Obs.Observe(ctx, ak)
	if err != nil {
		return controlval.Observation{}, err
	}
	result := ClassifyAttempt(obs)
	out := controlval.Observation{
		Key:          key,
		Provider:     p.Name(),
		EvidenceKind: controlval.EvidenceObserved,
		Source:       "wmi-marker+call-outcome",
		Detail:       obs.Detail,
	}
	switch result {
	case ResultExecuted:
		out.Outcome = controlval.OutcomeAllowed
		out.Confidence = controlval.ConfidenceHigh
	case ResultAccessDenied:
		out.Outcome = controlval.OutcomeBlocked
		out.Confidence = controlval.ConfidenceHigh
	default: // ResultIndeterminate
		out.Outcome = controlval.OutcomeUnknown
		out.Confidence = controlval.ConfidenceNone
	}
	return out, nil
}

// Pair holds the two independent principal results. Mirrors adefficacy.Pair:
// the raw Validations are never mutated; acceptance is a separate derivation.
type Pair struct {
	Positive controlval.Validation // authorized, expected allowed
	Negative controlval.Validation // unprivileged, expected blocked
}

// AcceptedNegativeVerdict returns the TRUSTWORTHY verdict for the negative
// control: a negative PASS is downgraded to SKIPPED unless the positive
// control cleanly PASSed in the same build. Never upgrades, never mutates.
func (p Pair) AcceptedNegativeVerdict() (controlval.Verdict, string) {
	if p.Negative.Verdict == controlval.VerdictPass && p.Positive.Verdict != controlval.VerdictPass {
		return controlval.VerdictSkipped,
			"negative-control denial not trustworthy: positive control did not succeed (harness not shown capable of an authorized WMI execution)"
	}
	return p.Negative.Verdict, p.Negative.Reason
}
