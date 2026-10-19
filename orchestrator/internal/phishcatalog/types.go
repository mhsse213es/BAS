// Package phishcatalog is a vendor-neutral, I/O-free, versioned Phishing
// BAS Mastery scenario catalog (phishing.txt §3's PH-* scenario IDs). It
// depends on internal/phishval for the outcome-model vocabulary a
// scenario's Expectation is phrased in; phishval never depends on it --
// same one-way shape as internal/avcatalog -> internal/avval.
//
// Per phishing.txt's own non-negotiable quality gate ("do not label
// phishing mastery complete merely because the catalogue exists"), every
// Scenario carries MappedImplementation and Coverage honestly: a catalog
// entry with CoverageCatalogOnly and an empty MappedImplementation is a
// genuine, unbuilt gap, not a placeholder to quietly fill in later with a
// claim of completeness. See
// docs/superpowers/specs/2026-10-18-phishing-bas-mastery-phase0-roadmap-design.md
// §2-3 for the full reuse-and-gap matrix this catalog is seeded from.
package phishcatalog

import "github.com/audspect/bas/internal/phishval"

// Area is one of phishing.txt §3's six scenario-catalogue areas.
type Area string

const (
	AreaAuth                  Area = "email_authentication_and_sender_trust" // area A
	AreaBEC                   Area = "business_email_compromise"             // area B
	AreaURLCredentialIdentity Area = "url_browser_credential_identity"       // area C
	AreaAttachment            Area = "attachments_and_payload_delivery"      // area D
	AreaCrossChannel          Area = "collaboration_mobile_cross_channel"    // area E
	AreaEvasionDetectionIR    Area = "evasion_detection_incident_response"   // area F
)

// CoverageState is phishing.txt §1 "Upgrade" item 1's "Coverage
// declaration" requirement: implemented, fixture-tested,
// integration-tested or live-validated. CoverageCatalogOnly is the
// explicit "exists as a definition, nothing executes it yet" state --
// never silently promoted.
type CoverageState string

const (
	CoverageCatalogOnly   CoverageState = "catalog_only"
	CoverageFixtureTested CoverageState = "fixture_tested"
	CoverageAdapterTested CoverageState = "adapter_tested"
	CoverageLiveValidated CoverageState = "live_validated"
)

// StandardsMapping ties a scenario to MITRE ATT&CK, mirroring
// avcatalog.StandardsMapping's ATTACKTechniques field exactly (no CWE
// equivalent needed here, so not carried over).
type StandardsMapping struct {
	ATTACKTechniques []string
}

// VariantAxis is one dimension phishing.txt's "Adversarial variant
// engine" capability (#3, P0) varies a base Scenario along: "external
// versus internal sender, authenticated versus spoofed identity, first
// delivery versus post-delivery verdict change, different supported
// languages." VariantAxisNarrative is this catalog's own addition,
// needed for PH-BEC-003/007: phishing.txt's own narrative framing
// (invoice-diversion vs. urgent-wire-transfer) that exercises the
// identical underlying control test as its base scenario, distinguished
// only by pretext content, not by a control-relevant condition.
type VariantAxis string

const (
	VariantAxisSenderOrigin VariantAxis = "sender_origin" // external vs internal
	VariantAxisIdentity     VariantAxis = "identity"      // authenticated vs spoofed
	VariantAxisTiming       VariantAxis = "timing"        // pre-delivery vs post-delivery verdict change
	VariantAxisLanguage     VariantAxis = "language"      // supported language
	VariantAxisNarrative    VariantAxis = "narrative"     // pretext framing only
)

// Variant is a stable PH-* ID that shares its BaseScenarioID's
// implementation rather than duplicating it -- phishing.txt capability
// #3's own acceptance bar: "Variants share a common scenario definition
// and produce comparable results without duplicating the entire
// implementation." A Variant carries no Coverage/MappedImplementation of
// its own; it inherits its base Scenario's, by construction (see
// ValidateCatalog).
type Variant struct {
	ID               string
	BaseScenarioID   string
	Axis             VariantAxis
	Value            string
	Name             string
	PrimaryObjective string
}

// Scenario is one versioned PH-* catalog entry.
type Scenario struct {
	ID               string
	Version          int
	Area             Area
	Name             string
	PrimaryObjective string
	Sectors          []string // sector profiles this scenario applies to; empty means "generic, all sectors"
	Preconditions    string
	Limitations      string
	Provenance       string
	Standards        StandardsMapping
	Expectation      phishval.Expectation
	// MappedImplementation names the existing package.Function this
	// scenario reuses (e.g. "emailgwcampaign.BECSupplierFraudTemplate").
	// Empty means no implementation exists yet -- a genuine gap, per this
	// package's own doc comment.
	MappedImplementation string
	Coverage             CoverageState
	Variants             []Variant
	// FalsePositiveRisk documents, where genuinely applicable, how this
	// scenario's own control could over-trigger against legitimate
	// business traffic, and names the paired business-continuity proof
	// (if one has been wired) that the control does not do so. Empty
	// for the great majority of scenarios -- it is never populated
	// speculatively, only when a real known-good/false-positive pair
	// exists or has been identified upstream.
	FalsePositiveRisk string

	// Experimental marks a best-effort heuristic that is not a documented
	// detection. The library shows it as experimental even when the registry runs it.
	Experimental bool
}
