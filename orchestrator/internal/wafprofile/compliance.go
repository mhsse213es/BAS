// Package wafprofile is a bundling/reference layer covering waf.txt
// Phase 9's industry-and-regional-profiles item. It is deliberately NOT
// an evidence evaluator: it depends only on internal/wafcatalog, to
// confirm that a profile's referenced attack-vector IDs actually exist
// in the real catalog, and never on internal/wafval or any other
// WAF-phase package. Every compliance claim this package can express
// carries an explicit VerificationStatus and a mandatory Note: this
// package's seed data (catalog.go) never asserts a specific regulatory
// clause, circular number, or rule number as fact -- only a framework
// name, general scope, and an honest account of what was and wasn't
// confirmed against a primary source. See the design spec's §2 for why:
// real research run before writing this package found no primary-source
// citation for the specific regulatory details it looked for.
package wafprofile

import "fmt"

// VerificationStatus names whether a ComplianceReference's framework
// claim has been confirmed against the regulator's or standard body's
// own primary text, or only against secondary sources (vendor blogs,
// compliance-consultancy pages).
type VerificationStatus string

const (
	Verified   VerificationStatus = "verified"
	Unverified VerificationStatus = "unverified"
)

func validVerificationStatus(s VerificationStatus) bool {
	switch s {
	case Verified, Unverified:
		return true
	default:
		return false
	}
}

// ComplianceReference is one compliance/regulatory framework that makes
// a Profile's attack vectors relevant to the industry or region it
// describes. Note is mandatory regardless of VerificationStatus: it
// states what is, and is not, being asserted about the framework.
type ComplianceReference struct {
	Framework          string
	VerificationStatus VerificationStatus
	Note               string
	SourceURL          string
}

// NewComplianceReference validates at construction time, never at
// render time. SourceURL is optional -- not every framework reference
// has one canonical URL -- so an empty string is accepted.
func NewComplianceReference(framework string, status VerificationStatus, note string, sourceURL string) (ComplianceReference, error) {
	if framework == "" {
		return ComplianceReference{}, fmt.Errorf("framework must not be empty")
	}
	if !validVerificationStatus(status) {
		return ComplianceReference{}, fmt.Errorf("status %q is not one of the known VerificationStatus constants", status)
	}
	if note == "" {
		return ComplianceReference{}, fmt.Errorf("note must not be empty")
	}
	return ComplianceReference{Framework: framework, VerificationStatus: status, Note: note, SourceURL: sourceURL}, nil
}
