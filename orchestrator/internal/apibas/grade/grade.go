// Package grade turns captured evidence into an outcome. It is pure logic with
// no I/O, so every grading rule can be tested directly.
//
// Three axes are kept separate (blueprint section 5): exploitability, control
// and detection. Result follows the existing PASS / FAIL / ERROR / SKIPPED
// layer. Detection is not evaluated yet and is reported that way.
package grade

import "slices"

// Result is the scenario outcome in the existing Audspect vocabulary.
type Result string

const (
	PASS    Result = "PASS"
	FAIL    Result = "FAIL"
	ERROR   Result = "ERROR"
	SKIPPED Result = "SKIPPED"
)

// Exploitability is whether the weakness could be exploited.
type Exploitability string

const (
	Exploited            Exploitability = "exploited"
	NotExploited         Exploitability = "not_exploited"
	ExploitInconclusive  Exploitability = "inconclusive"
	ExploitNotApplicable Exploitability = "not_applicable" // skipped before any traffic
)

// Control is whether the preventive control held.
type Control string

const (
	Enforced             Control = "enforced"
	Failed               Control = "failed"
	ControlInconclusive  Control = "inconclusive"
	ControlNotApplicable Control = "not_applicable"
)

// Confidence is the evidence strength behind the outcome.
type Confidence string

const (
	ConfidenceEvidenceBacked Confidence = "evidence-backed"
	ConfidenceInconclusive   Confidence = "inconclusive"
)

// Machine-readable skip and error reasons (blueprint section 3.1).
const (
	ReasonAdapterUnavailable   = "ADAPTER_UNAVAILABLE"
	ReasonPreconditionMissing  = "PRECONDITION_MISSING"
	ReasonNotCrossIdentity     = "NOT_CROSS_IDENTITY"
	ReasonEvidenceInconclusive = "EVIDENCE_INCONCLUSIVE"
	ReasonTargetUnreachable    = "TARGET_UNREACHABLE"
	ReasonTargetFault          = "TARGET_FAULT"
	ReasonAdapterReadFailed    = "ADAPTER_READ_FAILED"
	ReasonLabConfigMismatch    = "LAB_CONFIG_MISMATCH"
)

// Exchange is one captured request/response pair, after redaction.
type Exchange struct {
	Status int
	// LeakedProtected counts how many of the owner's protected values appear
	// in the response body. Computed by the runner, which holds the fixture.
	LeakedProtected int
	// ForbiddenHeaders counts response headers the scenario declares as exposure
	// (for example a reflected untrusted origin). Computed by the runner.
	ForbiddenHeaders int
	// Accepted counts attack responses that were neither denied nor a server fault.
	Accepted int
	// Oversized counts attack responses that granted a page larger than the
	// scenario allows.
	Oversized int
}

// Evidence is everything the grader is allowed to look at. It is assembled by
// the runner from independent sources: HTTP exchanges and the state adapter.
type Evidence struct {
	// Transport is true when the target could not be reached or timed out.
	// It is never treated as a block.
	Transport bool
	Baseline  Exchange
	Attack    Exchange
	// Denied lists the status codes the scenario declares as enforcement.
	// Each scenario sets its own list, so a 400 can count as a block for
	// property validation but not for authentication.
	Denied []int
	// StateChanged is the state adapter's diff between the snapshot taken after
	// the baseline and the snapshot taken after the attack.
	StateChanged bool
	// MaxAccepted is the number of accepted attack responses the control tolerates.
	// Zero means the scenario does not count attempts.
	MaxAccepted int
	// CleanIsEnforcement marks a scenario where a 2xx response with no leak and
	// no state change is the correct behaviour, because the control is a
	// projection (for example, the field is removed) rather than a refusal.
	// The runner sets it only for scenarios whose contract declares it, and
	// only when the response adapter is part of the ground truth.
	CleanIsEnforcement bool
}

// Outcome is the graded result with every axis reported separately.
type Outcome struct {
	Result         Result
	Exploitability Exploitability
	Control        Control
	Detection      string // always "not_evaluated" for now
	Confidence     Confidence
	Reason         string // machine-readable reason, empty for PASS and FAIL
}

// Skip returns a SKIPPED outcome with no traffic-derived claims.
func Skip(reason string) Outcome {
	return Outcome{
		Result:         SKIPPED,
		Exploitability: ExploitNotApplicable,
		Control:        ControlNotApplicable,
		Detection:      "not_evaluated",
		Confidence:     ConfidenceInconclusive,
		Reason:         reason,
	}
}

// Error returns an ERROR outcome for an infrastructure fault. An ERROR is never
// a block and never a pass.
func Error(reason string) Outcome {
	return Outcome{
		Result:         ERROR,
		Exploitability: ExploitInconclusive,
		Control:        ControlInconclusive,
		Detection:      "not_evaluated",
		Confidence:     ConfidenceInconclusive,
		Reason:         reason,
	}
}

// Assess applies the grading rules in order. The first matching rule decides.
//
//  1. Transport failure                               -> ERROR   (never a block)
//  2. Baseline 5xx or attack 5xx                      -> ERROR   (target fault)
//  3. Baseline not 200                                -> SKIPPED (precondition not met)
//  4. State changed by the attack                     -> FAIL, exploited
//  5. Protected values in the attack body             -> FAIL, exploited
//  6. Attack 2xx with no leak, when CleanIsEnforcement -> PASS, control enforced
//  7. Attack status in the scenario's Denied list     -> PASS, control enforced
//  8. Anything else (2xx without leak, other 4xx)     -> SKIPPED, inconclusive
func Assess(ev Evidence) Outcome {
	if ev.Transport {
		return Error(ReasonTargetUnreachable)
	}
	if ev.Baseline.Status >= 500 || ev.Attack.Status >= 500 {
		return Error(ReasonTargetFault)
	}
	if ev.Baseline.Status != 200 {
		return Skip(ReasonPreconditionMissing)
	}
	if ev.StateChanged || ev.Attack.LeakedProtected > 0 || ev.Attack.ForbiddenHeaders > 0 ||
		(ev.MaxAccepted > 0 && ev.Attack.Accepted > ev.MaxAccepted) || ev.Attack.Oversized > 0 {
		return Outcome{
			Result:         FAIL,
			Exploitability: Exploited,
			Control:        Failed,
			Detection:      "not_evaluated",
			Confidence:     ConfidenceEvidenceBacked,
		}
	}
	if ev.CleanIsEnforcement && ev.Attack.Status/100 == 2 {
		return Outcome{
			Result:         PASS,
			Exploitability: NotExploited,
			Control:        Enforced,
			Detection:      "not_evaluated",
			Confidence:     ConfidenceEvidenceBacked,
		}
	}
	if slices.Contains(ev.Denied, ev.Attack.Status) {
		return Outcome{
			Result:         PASS,
			Exploitability: NotExploited,
			Control:        Enforced,
			Detection:      "not_evaluated",
			Confidence:     ConfidenceEvidenceBacked,
		}
	}
	// A status outside the denial list proves neither that the control held
	// nor that it failed. It is reported as inconclusive, never PASS.
	return Outcome{
		Result:         SKIPPED,
		Exploitability: ExploitInconclusive,
		Control:        ControlInconclusive,
		Detection:      "not_evaluated",
		Confidence:     ConfidenceInconclusive,
		Reason:         ReasonEvidenceInconclusive,
	}
}
