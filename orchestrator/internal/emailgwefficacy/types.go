// Package emailgwefficacy owns email-gateway control-efficacy
// evidence (Microsoft Defender for Office 365, Proofpoint, Mimecast,
// Cisco Secure Email, FortiMail, ...). It is architecturally
// independent of internal/controlval, internal/webgwefficacy,
// internal/networkefficacy, internal/adefficacy, and
// internal/detectverify -- no import of any of them. Locked in
// docs/superpowers/specs/2026-10-15-emailgw-mastery-architecture-design.md
// §1-2; any cross-package relationship this initiative ever takes on
// borrows a structural pattern, never a shared type.
package emailgwefficacy

import (
	"encoding/json"
	"time"
)

// ExpectedMailAction is what an email-security policy was declared to
// be expected to do for a message profile -- never inferred from
// observed behavior.
type ExpectedMailAction string

const (
	ExpectedDeliver    ExpectedMailAction = "deliver"
	ExpectedQuarantine ExpectedMailAction = "quarantine"
	ExpectedReject     ExpectedMailAction = "reject"
	ExpectedRewrite    ExpectedMailAction = "rewrite-link"
	ExpectedEncrypt    ExpectedMailAction = "encrypt"
	ExpectedTagWarning ExpectedMailAction = "tag-warning"
)

// MessageRef identifies the test message an evidence lookup should
// correlate against. No JSON tags -- in-process only, matching
// webgwefficacy.HTTPRequestRef's own precedent.
type MessageRef struct {
	SenderProfile string
	Recipient     string
	MessageClass  string
}

// TimeWindow bounds the time range evidence must fall within to count
// as relevant to a check. No JSON tags, same precedent as
// webgwefficacy.TimeWindow.
type TimeWindow struct {
	Start, End time.Time
}

// MailExpectation is one declared "what should this gateway have
// done" for one message profile. emailGW.txt's taxonomy areas A-F
// each produce these; there is no shared generic fixture across
// areas.
type MailExpectation struct {
	SenderProfile  string             `json:"senderProfile"`
	Recipient      string             `json:"recipient"`
	MessageClass   string             `json:"messageClass"`
	ExpectedAction ExpectedMailAction `json:"expectedAction"`
	ControlProduct string             `json:"controlProduct"`
	Note           string             `json:"note,omitempty"`
}

// Ref returns the MessageRef an evidence provider must be queried
// with to find evidence for this expectation.
func (e MailExpectation) Ref() MessageRef {
	return MessageRef{SenderProfile: e.SenderProfile, Recipient: e.Recipient, MessageClass: e.MessageClass}
}

// EvidenceSource records how a piece of evidence was obtained --
// synthetic, fixture, or live -- identical discipline to
// webgwefficacy.EvidenceSource, independently defined (no import): a
// mock result must never be mistaken for proof that a real gateway
// behaved a certain way.
type EvidenceSource string

const (
	SourceSynthetic EvidenceSource = "synthetic"
	SourceFixture   EvidenceSource = "recorded-fixture"
	SourceLive      EvidenceSource = "live"
)

// ProvenanceKind records whether an evidence record's content was
// directly observed or inferred from something else (e.g. a timeout
// with no corroborating log).
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

// Provenance is emailGW.txt's observation-model item 5, attached to
// every evidence record individually rather than once per result --
// distinct evidence items feeding the same result can carry different
// provenance (e.g. enforcement observed directly, detection inferred
// from a correlation-ID timeout).
type Provenance struct {
	Kind       ProvenanceKind `json:"kind"`
	Confidence Confidence     `json:"confidence"`
	Basis      string         `json:"basis,omitempty"` // required whenever Kind is ProvenanceInferred
}

// OriginDeliveryObservation is emailGW.txt's observation-model item
// 3: what the authorized test sender actually transmitted, and what
// the receiving system actually observed -- two independent legs,
// never merged into one "it arrived" boolean.
type OriginDeliveryObservation struct {
	SenderPayloadHash string    `json:"senderPayloadHash"`
	ObservedOutcome   string    `json:"observedOutcome"` // "delivered" | "not-received" | "quarantined" | ...
	DeliveryRoute     string    `json:"deliveryRoute,omitempty"`
	Timestamp         time.Time `json:"timestamp"`
}

// EnforcementEvidence is observation-model item 1: was the message
// accepted, rejected, quarantined, rewritten, encrypted, or
// remediated, and which control made the decision.
type EnforcementEvidence struct {
	Message        MessageRef      `json:"-"`
	Action         string          `json:"action"` // the gateway's own observed action
	PolicyRule     string          `json:"policyRule,omitempty"`
	ControlProduct string          `json:"controlProduct,omitempty"`
	Timestamp      time.Time       `json:"timestamp"`
	Source         EvidenceSource  `json:"source"`
	Provenance     Provenance      `json:"provenance"`
	RawEvent       json.RawMessage `json:"rawEvent,omitempty"`
}

// DetectionEvidence is observation-model item 2: was the expected
// alert generated, with which product, rule, event, timestamp, and
// correlation identifier. AlertGenerated is a positive assertion from
// the provider ("this was checked, and here is the answer") -- it is
// distinct from the provider returning zero records at all, which
// means the check could not be made ([[VerifyMailExpectation]]'s own
// Inconclusive-vs-ConfirmedFailure distinction).
type DetectionEvidence struct {
	Message        MessageRef     `json:"-"`
	AlertGenerated bool           `json:"alertGenerated"`
	Product        string         `json:"product,omitempty"`
	Rule           string         `json:"rule,omitempty"`
	CorrelationID  string         `json:"correlationId,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
	Source         EvidenceSource `json:"source"`
	Provenance     Provenance     `json:"provenance"`
}

// ResponseEvidence is observation-model item 4: did quarantine,
// recall, account containment, or another required action actually
// complete, and how long did it take. Containment is modeled here,
// not as a fourth independent verdict axis -- locked in the
// architecture spec, see EfficacyResult.
type ResponseEvidence struct {
	Message            MessageRef     `json:"-"`
	ActionRequired     string         `json:"actionRequired"` // "quarantine" | "recall" | "account-containment" | ...
	Completed          bool           `json:"completed"`
	DurationToComplete time.Duration  `json:"durationToComplete,omitempty"`
	Timestamp          time.Time      `json:"timestamp"`
	Source             EvidenceSource `json:"source"`
	Provenance         Provenance     `json:"provenance"`
}

// EmailGWVerdict uses emailGW.txt §3's own naming exactly -- locked,
// never renamed to match webgwefficacy's wording, never unified with
// any other domain's taxonomy already in this codebase.
type EmailGWVerdict string

const (
	VerdictConfirmedFailure EmailGWVerdict = "confirmed-failure"
	VerdictConfirmedSuccess EmailGWVerdict = "confirmed-success"
	VerdictInconclusive     EmailGWVerdict = "inconclusive"
	VerdictNotTested        EmailGWVerdict = "not-tested"
	VerdictNotApplicable    EmailGWVerdict = "not-applicable"
)

// VerdictDetail is one independently-scored dimension's result.
// Reason is required whenever Verdict is not VerdictConfirmedSuccess.
type VerdictDetail struct {
	Verdict EmailGWVerdict `json:"verdict"`
	Reason  string         `json:"reason,omitempty"`
}

// EfficacyResult keeps Prevention, DetectionVerdict, and
// ResponseVerdict as three independently-verdicted dimensions.
// emailGW.txt §7 names "prevention, detection, containment and
// response" as four things a finding must distinguish -- locked
// decision: containment is scored inside ResponseVerdict
// (ResponseEvidence already groups quarantine/recall/account
// containment together, per the source document's own observation
// model item 4), not as a fourth independent verdict axis.
type EfficacyResult struct {
	Expectation      MailExpectation           `json:"expectation"`
	Observation      OriginDeliveryObservation `json:"observation"`
	Enforcement      []EnforcementEvidence     `json:"enforcement,omitempty"`
	Detection        []DetectionEvidence       `json:"detection,omitempty"`
	Response         []ResponseEvidence        `json:"response,omitempty"`
	Prevention       VerdictDetail             `json:"prevention"`
	DetectionVerdict VerdictDetail             `json:"detectionVerdict"`
	ResponseVerdict  VerdictDetail             `json:"responseVerdict"`
}
