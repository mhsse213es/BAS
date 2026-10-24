// Package cvecatalog is a vendor-neutral, I/O-free catalog of known-CVE
// assessment entries. It resolves into internal/cveval's verdict contract
// (it imports cveval; cveval never imports it, matching internal/wafcatalog's
// one-way dependency on internal/wafval). It imports stdlib + cveval only --
// no HTTP client, no exploit framework, no network code of any kind. Real
// execution against a controlled lab is a separate, deferred package
// (internal/cvelab); this package only declares what a CVE is, what makes a
// target vulnerable or patched, and what evidence would prove either --
// never executes anything itself.
package cvecatalog

import "github.com/audspect/bas/internal/cveval"

// Severity is the catalog entry's declared risk level, independent of CVSS
// score math -- a coarse bucket for display and prioritization only.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// VersionRange is one affected span of a product's versions. Introduced
// empty means "unbounded below" (every version up to Fixed is affected);
// Fixed empty means "unbounded above" (no known fix exists in this range).
// Both empty is rejected at construction -- a range that affects nothing
// and excludes nothing is not a range.
type VersionRange struct {
	Introduced string
	Fixed      string
}

// AffectedProduct names the component a CVE affects and the version spans
// within it that are vulnerable.
type AffectedProduct struct {
	Name   string
	Ranges []VersionRange
}

// Reference is one external source for a CVE entry's claims.
type Reference struct {
	Source string
	URL    string
}

// ConfigFixture is one deterministic, offline-checkable signal: a
// configuration or version indicator Audspect can compare without
// executing anything, and the verdict it implies. Implies must be
// VerdictVulnerable or VerdictNotVulnerable -- never any other Verdict --
// enforced at construction.
type ConfigFixture struct {
	Description string
	Indicator   string
	Implies     cveval.Verdict
}

// CVEEntry is one versioned catalog entry: identity, affected scope, what
// execution this entry supports, and the two fixtures that let a caller
// classify an observed configuration without a live probe.
type CVEEntry struct {
	ID                string
	CWEIDs            []string
	Severity          Severity
	AffectedProduct   AffectedProduct
	Description       string
	Preconditions     string
	ExecutionProfile  cveval.ExecutionProfile
	References        []Reference
	LastVerified      string // RFC3339 date Audspect's own authors last checked this entry against its source references -- never a claim about when exploitability was last confirmed in the wild
	VulnerableFixture ConfigFixture
	PatchedFixture    ConfigFixture
	Provenance        string
}
