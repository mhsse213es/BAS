// Package controlval is a product-neutral, AD- and vendor-agnostic model for
// validating what a DEPLOYED security control did about an already-executed
// attack attempt. It grades an observed control response against a per-case
// expected outcome. It imports stdlib only.
//
// Lab-gated boundary: this package ships fake-backed only (see FakeProvider).
// A real provider adapter (Silverfort first) and any wiring into the execution
// path are deferred until a lab/client environment with the control inline is
// available -- no prevention claim may rest on mocks, configuration presence,
// or detection telemetry alone.
package controlval

import "time"

// Outcome is what a deployed control did about an attack attempt.
type Outcome string

const (
	OutcomeAllowed       Outcome = "allowed"
	OutcomeBlocked       Outcome = "blocked"
	OutcomeMFAChallenged Outcome = "mfa_challenged"
	OutcomeTerminated    Outcome = "terminated"
	OutcomeQuarantined   Outcome = "quarantined"
	OutcomeUnknown       Outcome = "unknown"
)

// IsPrevention reports whether the outcome asserts the control actively
// stopped or interrupted the attempt (as opposed to allowing it).
func (o Outcome) IsPrevention() bool {
	switch o {
	case OutcomeBlocked, OutcomeMFAChallenged, OutcomeTerminated, OutcomeQuarantined:
		return true
	default:
		return false
	}
}

// EvidenceKind separates a directly observed control response from an inferred
// one. Recorded on every observation; it is NOT automatically trustworthy.
type EvidenceKind string

const (
	EvidenceObserved EvidenceKind = "observed" // the control itself reported the response
	EvidenceInferred EvidenceKind = "inferred" // derived from side effects / attack-side postcondition
)

// Confidence is the correlation + evidence-quality grade, SEPARATE from
// EvidenceKind: an observed outcome can still be low-confidence.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)

// effectiveFloor resolves the required confidence floor. Locked ruling: an
// UNSET (empty) MinConfidence is STRICT -- it resolves to ConfidenceHigh so a
// forgotten floor fails safe rather than accepting weak evidence for a
// security verdict. An explicit value (including ConfidenceNone, a deliberate
// opt-out) is used as given.
func effectiveFloor(c Confidence) Confidence {
	if c == "" {
		return ConfidenceHigh
	}
	return c
}

// confidenceRank orders confidence levels. ConfidenceNone and the zero value
// both rank 0 (no confidence).
func confidenceRank(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// TimeWindow bounds when the attempt occurred, for correlation.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// CorrelationKey ties the four evidence streams (attempt, execution/
// postcondition, control response, detection) together WITHOUT requiring all
// four to exist.
type CorrelationKey struct {
	RunID  string
	Target string
	Action string // opaque action id; the AD bridge maps primitive.ID -> Action
	Window TimeWindow
}

// Observation is ONE record from the control-response evidence stream.
type Observation struct {
	Key          CorrelationKey
	Provider     string
	Outcome      Outcome
	EvidenceKind EvidenceKind
	Confidence   Confidence
	Source       string
	ObservedAt   time.Time
	Detail       string
}

// Expectation is declared per validation case. It does NOT verify policy; it
// only identifies the policy the expectation derives from. PolicyVerified is
// false whenever the policy was merely supplied as test input.
type Expectation struct {
	Expected       Outcome
	PolicyBasis    string
	PolicyVerified bool
	MinConfidence  Confidence
}

// Verdict reuses the existing scoring taxonomy.
type Verdict string

const (
	VerdictPass    Verdict = "PASS"
	VerdictFail    Verdict = "FAIL"
	VerdictError   Verdict = "ERROR"
	VerdictSkipped Verdict = "SKIPPED"
)

// SkipReason explains WHY a SKIPPED verdict occurred -- canonical, shared
// across every consumer of this taxonomy. It always rides on top of
// VerdictSkipped; it is never a verdict value on its own, and it never
// fragments the taxonomy into a second one.
type SkipReason string

const (
	SkipInsufficientEvidence SkipReason = "insufficient_evidence" // evidence exists but does not establish the outcome
	SkipNotApplicable        SkipReason = "not_applicable"        // the capability genuinely does not apply here -- Evaluate never sets this itself; only a caller does, for an attempt it never ran
	SkipNotTested            SkipReason = "not_tested"            // no evaluation was ever attempted
)

// Validation is the graded result of comparing an observation to an
// expectation. Observation is nil when the control-response stream is
// explicitly missing.
type Validation struct {
	Key         CorrelationKey
	Expectation Expectation
	Observation *Observation
	Verdict     Verdict
	SkipReason  SkipReason `json:"skipReason,omitempty"`
	Reason      string
}

// Evaluate grades an observed control response against an expectation. It is
// pure over its inputs and reads NO other evidence stream -- no provider calls,
// clocks, database access or hidden state. Outcome alone never decides the
// verdict.
//
// Invariant A: inferred-only evidence can never establish prevention.
// Invariant B: a nil observation is SKIPPED, never fabricated from another
// stream. Error precedence: a technical opErr yields ERROR even when an
// observation is present.
//
// Locked ruling: correlation (that obs really belongs to this action/target/
// run) is enforced UPSTREAM -- the provider returns only observations it
// correlated and the bridge builds the key. Evaluate does not re-check obs.Key;
// Confidence is where correlation quality is graded.
func Evaluate(exp Expectation, obs *Observation, opErr error) Validation {
	v := Validation{Expectation: exp, Observation: obs}
	if obs != nil {
		v.Key = obs.Key
	}
	switch {
	case opErr != nil:
		v.Verdict, v.Reason = VerdictError, "provider/validation operation failed: "+opErr.Error()
	case obs == nil:
		v.Verdict, v.SkipReason, v.Reason = VerdictSkipped, SkipNotTested, "control response not recorded"
	case obs.Outcome == OutcomeUnknown:
		v.Verdict, v.SkipReason, v.Reason = VerdictSkipped, SkipInsufficientEvidence, "control outcome unknown"
	case confidenceRank(obs.Confidence) == 0 || confidenceRank(obs.Confidence) < confidenceRank(effectiveFloor(exp.MinConfidence)):
		v.Verdict, v.SkipReason, v.Reason = VerdictSkipped, SkipInsufficientEvidence, "below required confidence threshold"
	case exp.Expected.IsPrevention() && obs.EvidenceKind == EvidenceInferred:
		v.Verdict, v.SkipReason, v.Reason = VerdictSkipped, SkipInsufficientEvidence, "inferred-only evidence cannot establish prevention"
	case obs.Outcome == exp.Expected:
		v.Verdict, v.Reason = VerdictPass, "observed outcome matches expectation"
	case exp.Expected.IsPrevention() && obs.Outcome == OutcomeAllowed:
		v.Verdict, v.Reason = VerdictFail, "expected prevention, observed allowed (control gap)"
	case exp.Expected == OutcomeAllowed && obs.Outcome.IsPrevention():
		v.Verdict, v.Reason = VerdictFail, "unexpected denial"
	default:
		v.Verdict, v.Reason = VerdictFail, "observed outcome contradicts expectation"
	}
	return v
}
