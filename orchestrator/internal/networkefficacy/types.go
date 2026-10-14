// Package networkefficacy correlates a declared expected network-control
// outcome against a real firewall/IDS-IPS product's own evidence for a
// flow Network BAS has already modeled (internal/networkpolicy) and
// tested (internal/networkgraph), producing a provenance-linked
// efficacy verdict. It is deliberately independent of
// internal/detectverify -- see
// docs/superpowers/specs/2026-10-14-network-bas-phase4-control-efficacy-design.md
// §2 for why the two are not merged. It imports internal/networkpolicy
// and internal/networkgraph read-only, and internal/cloudgraph only for
// its existing PathState values (never a new one). It does not import
// internal/networktopology or internal/detectverify.
package networkefficacy

import (
	"encoding/json"
	"time"

	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// MaxExpectationsPerImport caps the number of declared expectations a
// single ControlExpectationImport may carry, mirroring the 500-scale
// cap every prior phase's import uses.
const MaxExpectationsPerImport = 500

// ExpectedControlAction is what a control product was declared to be
// expected to do for a flow. Never inferred from a PolicyEvaluation --
// a permit verdict and "no control test declared" are different things.
type ExpectedControlAction string

const (
	ExpectedBlock ExpectedControlAction = "block"
	ExpectedAlert ExpectedControlAction = "alert"
)

// EvidenceSource records how a piece of control-product evidence was
// obtained. Always explicit, never implied by which fields are
// populated -- synthetic or fixture data must never be mistaken for
// live proof that a real product behaved a certain way.
type EvidenceSource string

const (
	SourceSynthetic EvidenceSource = "synthetic"
	SourceFixture   EvidenceSource = "recorded-fixture"
	SourceLive      EvidenceSource = "live"
)

// ControlExpectation is one declared "what should this control have
// done" for one flow.
type ControlExpectation struct {
	ID             string                `json:"id,omitempty"`
	FlowSourceCIDR string                `json:"flowSourceCidr"`
	FlowDestCIDR   string                `json:"flowDestCidr"`
	FlowPort       int                   `json:"flowPort"`
	FlowProtocol   string                `json:"flowProtocol,omitempty"`
	ExpectedAction ExpectedControlAction `json:"expectedAction"`
	ControlProduct string                `json:"controlProduct"`
	Note           string                `json:"note,omitempty"`
}

// ControlExpectationImport is one auditable, versioned set of declared
// expectations -- same shape discipline as networkpolicy.PolicyImport
// and networktopology.TopologyImport.
type ControlExpectationImport struct {
	ID            string               `json:"id,omitempty"`
	SourceType    string               `json:"sourceType"`
	ImportedBy    string               `json:"importedBy,omitempty"`
	ImportedAt    time.Time            `json:"importedAt,omitempty"`
	ConfigVersion string               `json:"configVersion,omitempty"`
	Expectations  []ControlExpectation `json:"expectations"`
	Limitations   []string             `json:"limitations,omitempty"`
}

// FirewallEvidence is one firewall log entry's normalized shape.
type FirewallEvidence struct {
	SourceIP  string          `json:"sourceIp"`
	DestIP    string          `json:"destIp"`
	Port      int             `json:"port"`
	Protocol  string          `json:"protocol,omitempty"`
	Action    string          `json:"action"` // "block" | "permit"
	Timestamp time.Time       `json:"timestamp"`
	Source    EvidenceSource  `json:"source"`
	RawEvent  json.RawMessage `json:"rawEvent,omitempty"`
}

// IDSEvidence is one IDS/IPS alert's normalized shape (e.g. parsed from
// a Suricata EVE JSON "alert" event).
type IDSEvidence struct {
	SourceIP  string          `json:"sourceIp"`
	DestIP    string          `json:"destIp"`
	Port      int             `json:"port"`
	Protocol  string          `json:"protocol,omitempty"`
	AlertName string          `json:"alertName"`
	Severity  string          `json:"severity,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Source    EvidenceSource  `json:"source"`
	RawEvent  json.RawMessage `json:"rawEvent,omitempty"`
}

// EfficacyVerdict is the outcome of comparing a ControlExpectation
// against the control product's own evidence.
type EfficacyVerdict string

const (
	VerdictMet          EfficacyVerdict = "met"
	VerdictNotMet       EfficacyVerdict = "not-met"
	VerdictInconclusive EfficacyVerdict = "inconclusive" // Reason is required
)

// EfficacyResult keeps all four evidence dimensions visible and
// separately attributable -- never collapsed into just Verdict.
// Observation is required (not a pointer): it is what proves the test
// flow was actually attempted, and it is load-bearing for Contradiction
// detection.
type EfficacyResult struct {
	Expectation      ControlExpectation              `json:"expectation"`
	PolicyEval       *networkpolicy.PolicyEvaluation `json:"policyEvaluation,omitempty"`
	Observation      networkgraph.NetworkObservation `json:"observation"`
	FirewallEvidence *FirewallEvidence               `json:"firewallEvidence,omitempty"`
	IDSEvidence      *IDSEvidence                    `json:"idsEvidence,omitempty"`
	Verdict          EfficacyVerdict                 `json:"verdict"`
	Reason           string                          `json:"reason,omitempty"`
	Contradiction    string                          `json:"contradiction,omitempty"`
}
