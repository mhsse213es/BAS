package webgwefficacy

import (
	"encoding/json"
	"time"
)

// ExpectedGatewayAction is what a web-gateway policy was declared to
// be expected to do for a request shape -- never inferred from
// observed behavior.
type ExpectedGatewayAction string

const (
	ExpectedAllow      ExpectedGatewayAction = "allow"
	ExpectedBlock      ExpectedGatewayAction = "block"
	ExpectedChallenge  ExpectedGatewayAction = "challenge"
	ExpectedQuarantine ExpectedGatewayAction = "quarantine"
)

// HTTPExpectation is one declared "what should this gateway have
// done" for one request shape.
type HTTPExpectation struct {
	RequestURL     string                `json:"requestUrl"`
	URLCategory    string                `json:"urlCategory,omitempty"`
	User           string                `json:"user,omitempty"`
	ExpectedAction ExpectedGatewayAction `json:"expectedAction"`
	ControlProduct string                `json:"controlProduct"`
	Note           string                `json:"note,omitempty"`
}

// EvidenceSource records how a piece of gateway evidence was
// obtained. Always explicit, never implied by which fields are
// populated -- synthetic or fixture data must never be mistaken for
// live proof that a real gateway behaved a certain way.
type EvidenceSource string

const (
	SourceSynthetic EvidenceSource = "synthetic"
	SourceFixture   EvidenceSource = "recorded-fixture"
	SourceLive      EvidenceSource = "live"
)

// GatewayEvidence is one normalized gateway log/policy-decision
// record, however it was obtained.
type GatewayEvidence struct {
	RequestURL string          `json:"requestUrl"`
	User       string          `json:"user,omitempty"`
	Action     string          `json:"action"`
	Category   string          `json:"category,omitempty"`
	PolicyRule string          `json:"policyRule,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
	Source     EvidenceSource  `json:"source"`
	RawEvent   json.RawMessage `json:"rawEvent,omitempty"`
}

// HTTPObservation is what the client-side test itself actually
// attempted/saw, independent of the gateway's own evidence.
type HTTPObservation struct {
	RequestURL   string    `json:"requestUrl"`
	ClientResult string    `json:"clientResult"`
	Timestamp    time.Time `json:"timestamp"`
}

// HTTPRequestRef identifies the request an evidence lookup should
// correlate against. No JSON tags -- in-process only, matching
// networkefficacy.Flow's own precedent.
type HTTPRequestRef struct {
	URL  string
	User string
}

// TimeWindow bounds the time range evidence must fall within to count
// as relevant to a check. No JSON tags, same precedent as
// networkefficacy.TimeWindow.
type TimeWindow struct {
	Start, End time.Time
}

// WebGWVerdict is the 5-state verdict every WebGW domain uses --
// never 3-state or 4-state, never unified with any other domain's
// taxonomy already in this codebase.
type WebGWVerdict string

const (
	VerdictPass          WebGWVerdict = "pass"
	VerdictFail          WebGWVerdict = "fail"
	VerdictInconclusive  WebGWVerdict = "inconclusive"
	VerdictUnsupported   WebGWVerdict = "unsupported"
	VerdictNotApplicable WebGWVerdict = "not-applicable"
)

// VerdictDetail is one independently-scored dimension's result.
// Reason should be set whenever Verdict is not VerdictPass.
type VerdictDetail struct {
	Verdict WebGWVerdict `json:"verdict"`
	Reason  string       `json:"reason,omitempty"`
}

// EfficacyResult keeps prevention, detection, and response as three
// independently-verdicted dimensions -- never collapsed into one
// overall pass/fail, per webGW.txt's own explicit requirement that a
// gateway "can block an action but fail to alert" and both are
// material findings.
type EfficacyResult struct {
	Expectation HTTPExpectation   `json:"expectation"`
	Observation HTTPObservation   `json:"observation"`
	Evidence    []GatewayEvidence `json:"evidence,omitempty"`
	Prevention  VerdictDetail     `json:"prevention"`
	Detection   VerdictDetail     `json:"detection"`
	Response    VerdictDetail     `json:"response"`
}
