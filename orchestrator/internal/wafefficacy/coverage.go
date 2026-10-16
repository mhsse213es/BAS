package wafefficacy

import (
	"fmt"
	"strings"
)

// CoverageStatus is one domain's coverage state in a CoverageReport.
// "Covered" means at least one fixture-backed, proven scenario exists
// for the domain -- not that the domain's full breadth is built out.
type CoverageStatus string

const (
	CoverageCovered    CoverageStatus = "covered"
	CoverageExcluded   CoverageStatus = "excluded"
	CoverageNotCovered CoverageStatus = "not-covered"
)

func validCoverageStatus(s CoverageStatus) bool {
	switch s {
	case CoverageCovered, CoverageExcluded, CoverageNotCovered:
		return true
	default:
		return false
	}
}

// DomainCoverage is one domain's entry in a CoverageReport.
// ExclusionReason is required whenever Status is CoverageExcluded --
// enforced by NewCoverageReport, never left to convention.
type DomainCoverage struct {
	DomainID        string         `json:"domainId"`
	DomainName      string         `json:"domainName"`
	Status          CoverageStatus `json:"status"`
	ExclusionReason string         `json:"exclusionReason,omitempty"`
}

// CoverageReport is a validated set of DomainCoverage entries.
type CoverageReport struct {
	domains []DomainCoverage
}

// NewCoverageReport validates domains at construction time, never at
// render time: no DomainID may repeat, Status must be one of the 3
// known constants, and every CoverageExcluded domain must carry a
// non-empty ExclusionReason.
func NewCoverageReport(domains []DomainCoverage) (CoverageReport, error) {
	seen := make(map[string]bool, len(domains))
	for _, d := range domains {
		if seen[d.DomainID] {
			return CoverageReport{}, fmt.Errorf("duplicate domain ID %q", d.DomainID)
		}
		seen[d.DomainID] = true
		if !validCoverageStatus(d.Status) {
			return CoverageReport{}, fmt.Errorf("domain %q has unrecognized status %q", d.DomainID, d.Status)
		}
		if d.Status == CoverageExcluded && d.ExclusionReason == "" {
			return CoverageReport{}, fmt.Errorf("domain %q marked excluded with no documented reason", d.DomainID)
		}
	}
	return CoverageReport{domains: domains}, nil
}

func (r CoverageReport) Denominator() int { return len(r.domains) }

func (r CoverageReport) CoveredCount() int    { return r.countStatus(CoverageCovered) }
func (r CoverageReport) ExcludedCount() int   { return r.countStatus(CoverageExcluded) }
func (r CoverageReport) NotCoveredCount() int { return r.countStatus(CoverageNotCovered) }

func (r CoverageReport) countStatus(status CoverageStatus) int {
	n := 0
	for _, d := range r.domains {
		if d.Status == status {
			n++
		}
	}
	return n
}

// DomainsForDisplay returns every domain this report holds, in the
// order they were given to NewCoverageReport -- the only way a caller
// outside this package can read domain-level detail (DomainID,
// DomainName, Status, ExclusionReason) for rendering. It exists
// because CoverageReport's domains field is unexported by design, so
// a reporting layer cannot bypass NewCoverageReport's validation by
// constructing a CoverageReport directly.
func (r CoverageReport) DomainsForDisplay() []DomainCoverage {
	out := make([]DomainCoverage, len(r.domains))
	copy(out, r.domains)
	return out
}

// Exclusions renders every excluded domain's own documented reason.
func (r CoverageReport) Exclusions() []string {
	var out []string
	for _, d := range r.domains {
		if d.Status == CoverageExcluded {
			out = append(out, fmt.Sprintf("%s (%s): %s", d.DomainID, d.DomainName, d.ExclusionReason))
		}
	}
	return out
}

// noLiveExecutionDisclosure is a fixed, always-rendered caveat: every
// domain this report describes is evaluator-only, judged against
// caller-supplied (today, fixture) evidence -- there is no live
// HTTP-probing execution against a real target WAF yet. This is a
// report-level caveat, not a per-domain ExclusionReason: nothing here
// is excluded, but a reader must never mistake "covered" for "this
// runs against your live WAF today."
const noLiveExecutionDisclosure = "every domain is evaluator-only (fixture-backed evidence); no live HTTP-probing execution against a real target WAF exists yet"

// Summary renders the covered count, the denominator, every
// exclusion's reason (when any exist), and the fixed
// noLiveExecutionDisclosure -- which can never be omitted by a future
// edit, since it is interpolated directly into this function's return
// value rather than left in a doc comment.
func (r CoverageReport) Summary() string {
	if r.Denominator() == 0 {
		return "0/0 domains defined -- no coverage report can be computed; " + noLiveExecutionDisclosure
	}
	s := fmt.Sprintf("%d/%d domains covered", r.CoveredCount(), r.Denominator())
	if n := r.NotCoveredCount(); n > 0 {
		s += fmt.Sprintf("; %d not yet covered", n)
	}
	if excl := r.Exclusions(); len(excl) > 0 {
		s += fmt.Sprintf("; %d excluded: %s", len(excl), strings.Join(excl, "; "))
	}
	s += "; " + noLiveExecutionDisclosure
	return s
}
