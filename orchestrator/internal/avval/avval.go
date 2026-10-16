// Package avval is a vendor-neutral, I/O-free model for grading what an
// AV/NGAV control (or EDR/network control acting in its place) did about a
// controlled endpoint test. It models evidence as four orthogonal axes
// (prevention, detection, execution, response) plus first-class collection
// coverage, correlates raw observations into a per-axis resolved view, and
// derives one of three terminal finding classifications deterministically
// per claim type. Telemetry completeness and configuration compliance/drift
// are evaluated independently (av.txt §4) -- they qualify how much to trust
// a finding, never substitute for one. It imports stdlib + time only and
// does NOT depend on internal/controlval, internal/wafval, or any vendor
// type. Vendor adapters are a separate, deferred package.
package avval

import (
	"fmt"
	"time"
)

// ControlSource is the evidence source that produced an observation. It is
// the independence tag AND the attribution tag: two observations that share
// a ControlSource are never treated as independent corroboration of each
// other, and a finding must never credit a control that did not produce the
// agreeing evidence (av.txt §4: "if an EDR product blocks a process before
// the AV engine acts, the report must attribute the outcome to the EDR
// control unless independent evidence establishes AV involvement").
type ControlSource string

const (
	ControlSourceAVEngine          ControlSource = "av_engine"
	ControlSourceNGAVBehavioral    ControlSource = "ngav_behavioral"
	ControlSourceEDR               ControlSource = "edr"
	ControlSourceNetworkControl    ControlSource = "network_control"
	ControlSourceIndependentSensor ControlSource = "independent_sensor"
)

// PreventionOutcome is what happened to the malicious artifact/behavior,
// independent of whether it was detected. It is claim-agnostic: whether
// "blocked" is the correct or incorrect outcome depends on the claim
// (ClaimPrevention vs ClaimFalsePositive), decided in evaluate.go.
type PreventionOutcome string

const (
	PreventionBlocked          PreventionOutcome = "blocked"
	PreventionAllowed          PreventionOutcome = "allowed"
	PreventionPartiallyBlocked PreventionOutcome = "partially_blocked"
	PreventionUnknown          PreventionOutcome = "unknown"
)

// DetectionOutcome is whether the control recognized the artifact/behavior
// as suspicious, independent of whether it enforced anything.
type DetectionOutcome string

const (
	DetectionDetected            DetectionOutcome = "detected"
	DetectionNotObservedInWindow DetectionOutcome = "not_observed_within_window" // assertable ONLY under verified-complete coverage
	DetectionUnknown             DetectionOutcome = "unknown"
)

// ExecutionObservation is whether the malicious artifact/behavior actually
// ran on the endpoint, independent of what the control claims. "not_observed"
// must never be read as "did not happen" (mirrors wafval's OriginObservation
// discipline).
type ExecutionObservation string

const (
	ExecutionExecuted    ExecutionObservation = "executed"
	ExecutionNotObserved ExecutionObservation = "not_observed"
	ExecutionUnknown     ExecutionObservation = "unknown"
)

// ResponseOutcome is what happened after detection: remediation, containment,
// or neither. NotApplicable is a legitimate outcome when nothing required a
// response.
type ResponseOutcome string

const (
	ResponseRemediated    ResponseOutcome = "remediated"
	ResponseContained     ResponseOutcome = "contained"
	ResponseFailed        ResponseOutcome = "failed"
	ResponseNotApplicable ResponseOutcome = "not_applicable"
	ResponseUnknown       ResponseOutcome = "unknown"
)

// TelemetryState describes how completely the evidence-collection pipeline
// itself worked for one test -- evaluated independently of any finding (see
// EvaluateTelemetryCompleteness).
type TelemetryState string

const (
	TelemetryComplete    TelemetryState = "complete"
	TelemetryPartial     TelemetryState = "partial"
	TelemetryUnavailable TelemetryState = "unavailable"
)

// ConfigurationState describes whether an endpoint's active configuration
// complies with a required baseline, or drifts from a centrally managed
// policy -- evaluated independently of any finding (see
// EvaluateConfigurationSnapshot / EvaluateConfigurationDrift).
type ConfigurationState string

const (
	ConfigurationCompliant ConfigurationState = "compliant"
	ConfigurationPolicyGap ConfigurationState = "policy_gap"
	ConfigurationDrift     ConfigurationState = "drift"
	ConfigurationUnknown   ConfigurationState = "unknown"
)

// EvidenceKind separates a directly observed signal from an inferred one.
type EvidenceKind string

const (
	EvidenceObserved EvidenceKind = "observed"
	EvidenceInferred EvidenceKind = "inferred"
)

// Coverage records what a search of one control source actually established.
// A negative detection (DetectionNotObservedInWindow) is only assertable
// under CoverageSearchedVerifiedNone.
type Coverage string

const (
	CoverageFound                Coverage = "found"
	CoverageSearchedVerifiedNone Coverage = "searched_verified_none"
	CoverageSearchIncomplete     Coverage = "search_incomplete"
	CoverageSourceUnavailable    Coverage = "source_unavailable"
)

// Present reports whether a search of this control source actually
// established coverage. search_incomplete and source_unavailable do not
// count as present and can never establish a negative finding.
func (c Coverage) Present() bool {
	return c == CoverageFound || c == CoverageSearchedVerifiedNone
}

// EvidenceCompleteness describes evidence coverage for a claim, never truth.
type EvidenceCompleteness string

const (
	CompletenessComplete     EvidenceCompleteness = "complete"
	CompletenessPartial      EvidenceCompleteness = "partial"
	CompletenessInsufficient EvidenceCompleteness = "insufficient"
)

// Confidence is how much the collected evidence supports the conclusion,
// separate from completeness. It is capped by completeness and only ever
// downgraded.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)

// ClaimType is the question asked of the evidence.
type ClaimType string

const (
	ClaimPrevention    ClaimType = "prevention"
	ClaimFalsePositive ClaimType = "false_positive"
)

// FindingClassification is the top-level finding (av.txt §4 step 5: confirmed
// gap, verified protection, or inconclusive). Untested is intentionally NOT
// here -- same discipline as wafval.Verdict: it is a catalog/execution status
// assigned above the evaluator, never a value this package can produce.
type FindingClassification string

const (
	FindingVerifiedProtection FindingClassification = "verified_protection"
	FindingConfirmedGap       FindingClassification = "confirmed_gap"
	FindingInconclusive       FindingClassification = "inconclusive"
)

// TimeWindow bounds when the test occurred, for correlation.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// CorrelationKey ties a test execution to the raw events.
type CorrelationKey struct {
	TestExecutionID string
	EndpointID      string
	Target          string
	Window          TimeWindow
}

// Observation is one control source's raw report about one test. Its
// EventID and ObservedAt are preserved verbatim; observations are never
// merged away.
type Observation struct {
	ControlSource ControlSource
	Provider      string
	EventID       string
	EndpointID    string
	ObservedAt    time.Time
	Prevention    PreventionOutcome
	Detection     DetectionOutcome
	Execution     ExecutionObservation
	Response      ResponseOutcome
	MatchedRule   string
	EvidenceKind  EvidenceKind
	Detail        string
}

// CollectionResult is one control source's search result for one correlation
// key: its coverage plus every raw observation the search returned.
type CollectionResult struct {
	ControlSource ControlSource
	Coverage      Coverage
	Observations  []Observation
}

// Expectation declares what a claim expects and the policy basis it derives
// from. PolicyVerified is false whenever the policy was merely supplied as
// test input (never confirmed in force).
type Expectation struct {
	Claim          ClaimType
	PolicyBasis    string
	PolicyVerified bool
}

// Valid rejects a finding/claim/completeness combination that violates the
// taxonomy's invariants. A well-typed value can still be an invalid state;
// this is the single place that catches it.
func Valid(claim ClaimType, f FindingClassification, c EvidenceCompleteness) error {
	// Inconclusive is always valid.
	if f == FindingInconclusive {
		return nil
	}
	// Any non-Inconclusive finding requires more than insufficient evidence.
	if c == CompletenessInsufficient {
		return fmt.Errorf("finding %q requires evidence beyond insufficient", f)
	}
	allowed := map[ClaimType]map[FindingClassification]bool{
		ClaimPrevention:    {FindingVerifiedProtection: true, FindingConfirmedGap: true},
		ClaimFalsePositive: {FindingVerifiedProtection: true, FindingConfirmedGap: true},
	}
	if byClaim, ok := allowed[claim]; ok && byClaim[f] {
		return nil
	}
	return fmt.Errorf("finding %q is not producible by claim %q", f, claim)
}
