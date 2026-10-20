// Package panosexposure correlates one PAN-OS appliance's reported state with a
// vendor advisory and returns an exposure verdict for a single CVE.
//
// It is pure logic: no network, no database, no vendor data embedded. Affected
// version ranges and exposure conditions come from the advisory the caller
// supplies, so this package never asserts a vendor fact that the advisory does
// not state. A verdict of Vulnerable means the supplied advisory's exposure
// conditions are met by the supplied asset data. It does not mean the appliance
// has been exploited, and it does not replace the vendor's own advisory.
package panosexposure

import "time"

// Product is the only product this package handles.
const Product = "pan-os"

// Tri is a three-valued configuration fact. A missing fact is Unknown, never
// assumed to be No or Yes.
type Tri string

const (
	TriYes     Tri = "yes"
	TriNo      Tri = "no"
	TriUnknown Tri = "unknown"
)

// Verdict is the exposure outcome for one asset and one advisory.
type Verdict string

const (
	// VerdictVulnerable: version affected and every exposure condition the
	// advisory names is confirmed present.
	VerdictVulnerable Verdict = "vulnerable"
	// VerdictMitigated: version affected, but a condition the advisory names is
	// confirmed absent (for example GlobalProtect disabled). Not reachable by
	// that path until the condition changes.
	VerdictMitigated Verdict = "mitigated"
	// VerdictNotAffected: version outside every affected range in the advisory.
	VerdictNotAffected Verdict = "not_affected"
	// VerdictUnknown: a fact needed for the decision is missing or unparseable.
	// Never reported as safe.
	VerdictUnknown Verdict = "unknown"
	// VerdictNotApplicable: the asset is not PAN-OS.
	VerdictNotApplicable Verdict = "not_applicable"
)

// Asset is one PAN-OS appliance as reported by the caller (inventory import,
// config export, or manual entry). Facts the caller cannot establish are Unknown.
type Asset struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname,omitempty"`
	Product  string `json:"product"`
	// Version as reported, for example "10.2.3" or "10.2.3-h1".
	Version string `json:"version"`
	// GlobalProtect portal or gateway enabled.
	GlobalProtect Tri `json:"globalProtect"`
	// Authentication override feature enabled on the GlobalProtect portal.
	AuthOverride Tri `json:"authOverride"`
	// The authentication-override cookie uses the same certificate as the
	// GlobalProtect HTTPS service.
	SharedOverrideCert Tri `json:"sharedOverrideCert"`
}

// VersionRange is a half-open range [Introduced, FixedIn). Both bounds are
// PAN-OS version strings in the same format as Asset.Version. An empty FixedIn
// means the advisory gives no fixed release for that range.
type VersionRange struct {
	Introduced string `json:"introduced"`
	FixedIn    string `json:"fixedIn"`
	// Note records the advisory wording behind a range that needs context.
	Note string `json:"note,omitempty"`
}

// Conditions lists which exposure conditions the advisory names. A condition
// is checked only when its flag is true.
type Conditions struct {
	RequireGlobalProtect bool `json:"requireGlobalProtect"`
	RequireAuthOverride  bool `json:"requireAuthOverride"`
	RequireSharedCert    bool `json:"requireSharedCert"`
}

// Advisory is the vendor data for one CVE, supplied by the caller. Source is
// the advisory URL or identifier, so every verdict can cite where its ranges
// came from.
type Advisory struct {
	CVE string `json:"cve"`
	// Version identifies this advisory record, so verdicts can say which
	// version of the data they used. Empty for caller-supplied advisories.
	Version    string         `json:"version,omitempty"`
	Source     string         `json:"source"`
	Affected   []VersionRange `json:"affected"`
	Conditions Conditions     `json:"conditions"`
	// Coverage lists the "major.minor" release branches the advisory addresses.
	// A release on a branch that is neither covered nor inside an affected range
	// is unknown, never not-affected. Empty means no coverage check is made.
	Coverage []string `json:"coverage,omitempty"`
	// Unresolved lists exact release strings whose advisory statements conflict.
	// They return unknown until the vendor clarifies.
	Unresolved []string `json:"unresolved,omitempty"`
	// VerifiedFrom records how and when the ranges were checked against the
	// vendor page, so the data's provenance is visible to anyone reading it.
	VerifiedFrom string `json:"verifiedFrom,omitempty"`
}

// Result is the verdict plus the evidence and limits behind it.
type Result struct {
	AssetID string  `json:"assetId"`
	CVE     string  `json:"cve"`
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason"`
	// ReasonCodes are stable, machine-readable explanations. Reason is prose
	// for people; codes are for filtering, reporting and tests.
	ReasonCodes []string `json:"reasonCodes"`
	// MissingEvidence names each fact that could not be established. It is
	// populated for every unknown verdict, so the gap is always visible.
	MissingEvidence []string `json:"missingEvidence"`
	Evidence        []string `json:"evidence"`
	Limitations     []string `json:"limitations,omitempty"`
	// AdvisoryVersion is the version of the advisory record used, empty for
	// caller-supplied advisories that carry none.
	AdvisoryVersion string `json:"advisoryVersion,omitempty"`
	// AdvisoryStatus is the verification status of the advisory data used:
	// "verified", "unverified", or "caller-supplied" (Audspect did not check it).
	// It is kept separate from the verdict: a correct verdict from unverified
	// data is still a verdict on unverified data.
	AdvisoryStatus string `json:"advisoryStatus,omitempty"`
	// AssessedAt is the timestamp supplied by the caller (UTC).
	AssessedAt time.Time `json:"assessedAt"`
}

// Reason codes. These strings are part of the API, so do not rename them.
const (
	CodeNotPANOS              = "NOT_PAN_OS"
	CodeVersionUnparseable    = "VERSION_UNPARSEABLE"
	CodeNoAffectedRanges      = "NO_AFFECTED_RANGES"
	CodeRangeNoFixedRelease   = "RANGE_NO_FIXED_RELEASE"
	CodeRangeInvalid          = "RANGE_INVALID"
	CodeReleaseUnresolved     = "RELEASE_UNRESOLVED"
	CodeInAffectedRange       = "IN_AFFECTED_RANGE"
	CodeOutsideAffectedRanges = "OUTSIDE_AFFECTED_RANGES"
	CodeBranchNotCovered      = "BRANCH_NOT_COVERED"
	CodeConditionAbsent       = "CONDITION_ABSENT"
	CodeConditionUnknown      = "CONDITION_UNKNOWN"
	CodeConditionPresent      = "CONDITION_PRESENT"
	CodeNoConditionsNamed     = "NO_CONDITIONS_NAMED"
)

// Missing-evidence names. These identify which input fact was not established.
const (
	EvidenceVersion        = "version"
	EvidenceGlobalProtect  = "globalProtect"
	EvidenceAuthOverride   = "authOverride"
	EvidenceSharedOverride = "sharedOverrideCert"
)
