// Package wafval is a vendor-neutral, I/O-free model for grading what a WAF
// did about a controlled test request. It models evidence as three orthogonal
// axes (enforcement, detection, origin) plus first-class collection coverage,
// correlates raw observations into a per-axis resolved view, and derives one
// of seven terminal verdicts deterministically per claim type. It imports
// stdlib + time only and does NOT depend on internal/controlval, any AD type,
// or any WAF-vendor type. The lab adapter that produces observations is a
// separate, deferred package.
package wafval

import (
	"fmt"
	"time"
)

// Mechanism is the evidence source that produced an observation. It is the
// independence tag: two observations that share a Mechanism are never treated
// as independent corroboration of each other.
type Mechanism string

const (
	MechanismWAFEngine         Mechanism = "waf_engine"
	MechanismOriginApp         Mechanism = "origin_app"
	MechanismIndependentSensor Mechanism = "independent_sensor"
)

// EnforcementAction is what the WAF (or origin) did about the request.
type EnforcementAction string

const (
	EnforcementBlocked    EnforcementAction = "blocked"
	EnforcementAllowed    EnforcementAction = "allowed"
	EnforcementChallenged EnforcementAction = "challenged"
	EnforcementTerminated EnforcementAction = "terminated"
	EnforcementUnknown    EnforcementAction = "unknown"
)

// DetectionOutcome is whether the WAF recognized the request as matching a
// rule/signature, independent of whether it enforced anything.
type DetectionOutcome string

const (
	DetectionMatched    DetectionOutcome = "matched"
	DetectionNotMatched DetectionOutcome = "not_matched" // assertable ONLY under verified-complete coverage
	DetectionUnknown    DetectionOutcome = "unknown"
)

// OriginObservation is whether the protected application actually received /
// processed the request. "not_observed" must never be read as "did not happen".
type OriginObservation string

const (
	OriginReceived    OriginObservation = "received"
	OriginNotObserved OriginObservation = "not_observed"
	OriginUnknown     OriginObservation = "unknown"
)

// EvidenceKind separates a directly observed signal from an inferred one.
type EvidenceKind string

const (
	EvidenceObserved EvidenceKind = "observed"
	EvidenceInferred EvidenceKind = "inferred"
)

// Coverage records what a search of one mechanism actually established. A
// negative detection (DetectionNotMatched) is only assertable under
// CoverageSearchedVerifiedNone.
type Coverage string

const (
	CoverageFound                Coverage = "found"
	CoverageSearchedVerifiedNone Coverage = "searched_verified_none"
	CoverageSearchIncomplete     Coverage = "search_incomplete"
	CoverageSourceUnavailable    Coverage = "source_unavailable"
)

// Present reports whether a search of this mechanism actually established
// coverage. search_incomplete and source_unavailable do not count as present
// and can never establish a negative finding.
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
	ClaimPolicyGap     ClaimType = "policy_gap"
)

// Verdict is one of the seven terminal states. NotTested is intentionally NOT
// here -- it is a catalog/execution status assigned above the evaluator.
type Verdict string

const (
	VerdictBlocked            Verdict = "blocked"
	VerdictDetectedButAllowed Verdict = "detected_but_allowed"
	VerdictMissed             Verdict = "missed"
	VerdictIncorrectlyBlocked Verdict = "incorrectly_blocked"
	VerdictAllowed            Verdict = "allowed" // legitimate request correctly permitted
	VerdictInconclusive       Verdict = "inconclusive"
)

// TimeWindow bounds when the request occurred, for correlation.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// CorrelationKey ties a test execution to the raw events. RequestID is the
// token carried on the HTTP request itself, so a raw log line can be matched
// back without already knowing the internal execution id.
type CorrelationKey struct {
	TestExecutionID string
	RequestID       string
	Target          string
	Window          TimeWindow
}

// Observation is one mechanism's raw report about one request. Its EventID and
// ObservedAt are preserved verbatim; observations are never merged away.
type Observation struct {
	Mechanism    Mechanism
	Provider     string
	EventID      string
	RequestID    string
	ObservedAt   time.Time
	Enforcement  EnforcementAction
	Detection    DetectionOutcome
	Origin       OriginObservation
	MatchedRule  string
	EvidenceKind EvidenceKind
	Detail       string
}

// CollectionResult is one mechanism's search result for one correlation key:
// its coverage plus every raw observation the search returned.
type CollectionResult struct {
	Mechanism    Mechanism
	Coverage     Coverage
	Observations []Observation
}

// Expectation declares what a claim expects and the policy basis it derives
// from. PolicyVerified is false whenever the policy was merely supplied as
// test input (never confirmed in force).
type Expectation struct {
	Claim          ClaimType
	PolicyBasis    string
	PolicyVerified bool
}

// Valid rejects a verdict/claim/completeness combination that violates the
// taxonomy's invariants. A well-typed value can still be an invalid state;
// this is the single place that catches it.
func Valid(claim ClaimType, v Verdict, c EvidenceCompleteness) error {
	// Inconclusive is always valid.
	if v == VerdictInconclusive {
		return nil
	}
	// Any non-Inconclusive verdict requires more than insufficient evidence.
	if c == CompletenessInsufficient {
		return fmt.Errorf("verdict %q requires evidence beyond insufficient", v)
	}
	allowed := map[ClaimType]map[Verdict]bool{
		ClaimPrevention: {
			VerdictBlocked: true, VerdictDetectedButAllowed: true, VerdictMissed: true,
		},
		ClaimFalsePositive: {
			VerdictAllowed: true, VerdictIncorrectlyBlocked: true,
		},
		ClaimPolicyGap: {
			VerdictBlocked: true, VerdictDetectedButAllowed: true, VerdictMissed: true,
		},
	}
	if byClaim, ok := allowed[claim]; ok && byClaim[v] {
		return nil
	}
	return fmt.Errorf("verdict %q is not producible by claim %q", v, claim)
}
