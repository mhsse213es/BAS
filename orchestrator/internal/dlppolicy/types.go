// Package dlppolicy owns DLP-POL evidence: whether a DLP policy's own
// declared configuration (scope, mode, deployment state, exceptions,
// propagation) matches what it should be. It never tests enforcement
// outcome -- whether a real exfiltration attempt was actually blocked
// is internal/reporting's job (DLP-ENF's eventual territory), never
// merged into this package's evidence model.
//
// Architecturally independent of internal/emailgwefficacy,
// internal/webgwefficacy, internal/dlpfixture, and internal/reporting
// -- no import of any of them. Any cross-package relationship this
// package ever takes on borrows a structural pattern (declared
// Expectation, fixture-backed EvidenceProvider, single-dimension
// VerdictDetail), never a shared type -- locked in
// docs/superpowers/specs/2026-10-18-dlp-pol-design.md.
package dlppolicy

import "time"

// DLPPOLVerdict is this package's own verdict vocabulary -- locked,
// never unified with any other domain's taxonomy already in this
// codebase (emailgwefficacy's EmailGWVerdict, webgwefficacy's own,
// internal/controlval's four-verdict system).
type DLPPOLVerdict string

const (
	VerdictConfirmedFailure DLPPOLVerdict = "confirmed-failure"
	VerdictConfirmedSuccess DLPPOLVerdict = "confirmed-success"
	VerdictInconclusive     DLPPOLVerdict = "inconclusive"
	VerdictNotTested        DLPPOLVerdict = "not-tested"
	VerdictNotApplicable    DLPPOLVerdict = "not-applicable"
)

// VerdictDetail is one independently-scored dimension's result.
// Reason is required whenever Verdict is not VerdictConfirmedSuccess.
type VerdictDetail struct {
	Verdict DLPPOLVerdict `json:"verdict"`
	Reason  string        `json:"reason,omitempty"`
}

// EvidenceSource records how a piece of evidence was obtained --
// synthetic, fixture, or live -- the same discipline as
// emailgwefficacy.EvidenceSource/webgwefficacy.EvidenceSource,
// independently defined (no import): a fixture result must never be
// mistaken for proof that a real DLP product behaved a certain way.
type EvidenceSource string

const (
	SourceSynthetic EvidenceSource = "synthetic"
	SourceFixture   EvidenceSource = "recorded-fixture"
	SourceLive      EvidenceSource = "live" // not produced by any provider in Slice 1; reserved for a future real connector
)

// ProvenanceKind records whether an evidence record's content was
// directly observed or inferred from something else.
type ProvenanceKind string

const (
	ProvenanceObserved ProvenanceKind = "observed"
	ProvenanceInferred ProvenanceKind = "inferred"
)

// Confidence is how much an inferred (or, less often, observed but
// incomplete) piece of evidence should be trusted.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Provenance is attached to every evidence record individually.
// Basis is required whenever Kind is ProvenanceInferred.
type Provenance struct {
	Kind       ProvenanceKind `json:"kind"`
	Confidence Confidence     `json:"confidence"`
	Basis      string         `json:"basis,omitempty"`
}

// TimeWindow bounds the time range evidence must fall within to count
// as relevant to a check. Inclusive on both ends.
type TimeWindow struct {
	Start, End time.Time
}

// ScopeID identifies an OU/site/business-unit/tenant a policy
// expectation or evidence record applies to. Always a lab-synthetic
// value (e.g. "lab-ou-finance-eu"), never a real customer org path.
type ScopeID string

// DLPPolicyMode is whether a rule is declared to actively enforce its
// action or only audit/log it.
type DLPPolicyMode string

const (
	ModeEnforce   DLPPolicyMode = "enforce"
	ModeAuditOnly DLPPolicyMode = "audit-only"
)

// DLPPolicyScopeDeclaration says who/where/what a rule is declared to
// cover. Each field is compared as a set, order-independent -- see
// scopesEqual in rulebaseline.go.
type DLPPolicyScopeDeclaration struct {
	IncludedLocations []string `json:"includedLocations,omitempty"`
	ExcludedLocations []string `json:"excludedLocations,omitempty"`
	IncludedUsers     []string `json:"includedUsers,omitempty"`
	ExcludedUsers     []string `json:"excludedUsers,omitempty"`
	IncludedDevices   []string `json:"includedDevices,omitempty"`
	ExcludedDevices   []string `json:"excludedDevices,omitempty"`
	IncludedGroups    []string `json:"includedGroups,omitempty"`
	ExcludedGroups    []string `json:"excludedGroups,omitempty"`
}
