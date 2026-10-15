package webgwefficacy

import (
	"fmt"
	"strings"
)

// CoverageStatus is one domain's coverage state in a CoverageReport.
// "Covered" means at least one fixture-backed, proven scenario exists
// for the domain -- not that the domain's full breadth is built out;
// webGW.txt's own 12-domain bullets each list many sub-capabilities,
// and most covered domains here have proven only one or a few of
// them so far.
type CoverageStatus string

const (
	CoverageCovered    CoverageStatus = "covered"
	CoverageExcluded   CoverageStatus = "excluded"
	CoverageNotCovered CoverageStatus = "not-covered"
)

// DomainCoverage is one domain's entry in a CoverageReport.
// ExclusionReason is required whenever Status is CoverageExcluded --
// enforced by NewCoverageReport, never left to convention.
type DomainCoverage struct {
	DomainID        string         `json:"domainId"`
	DomainName      string         `json:"domainName"`
	Status          CoverageStatus `json:"status"`
	ExclusionReason string         `json:"exclusionReason,omitempty"`
}

// CoverageReport is a validated set of DomainCoverage entries. Its
// only rendering surface is Summary -- there is no method that
// returns a bare percentage on its own, which is how "never an
// unqualified percentage" (webGW.txt's own quality-proof requirement)
// is enforced structurally rather than by convention.
type CoverageReport struct {
	domains []DomainCoverage
}

// NewCoverageReport validates domains at construction time, never at
// render time: no DomainID may repeat, and every CoverageExcluded
// domain must carry a non-empty ExclusionReason -- an exclusion
// without a documented reason is exactly the "silently dropped"
// failure mode this initiative exists to prevent.
func NewCoverageReport(domains []DomainCoverage) (CoverageReport, error) {
	seen := make(map[string]bool, len(domains))
	for _, d := range domains {
		if seen[d.DomainID] {
			return CoverageReport{}, fmt.Errorf("duplicate domain ID %q", d.DomainID)
		}
		seen[d.DomainID] = true
		if d.Status == CoverageExcluded && d.ExclusionReason == "" {
			return CoverageReport{}, fmt.Errorf("domain %q marked excluded with no documented reason", d.DomainID)
		}
	}
	return CoverageReport{domains: domains}, nil
}

// Denominator is the total number of domains considered, including
// CoverageNotCovered ones -- a domain that is merely incomplete is
// never quietly treated as if it didn't exist.
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

// Exclusions renders every excluded domain's own documented reason --
// a reader must never need to query a separate field to learn why a
// domain was excluded.
func (r CoverageReport) Exclusions() []string {
	var out []string
	for _, d := range r.domains {
		if d.Status == CoverageExcluded {
			out = append(out, fmt.Sprintf("%s (%s): %s", d.DomainID, d.DomainName, d.ExclusionReason))
		}
	}
	return out
}

// Summary renders the covered count, the denominator, and (when any
// exist) every exclusion's reason together in one string -- the only
// rendering surface this type has, so a percentage can never appear
// without its denominator and exclusions alongside it.
func (r CoverageReport) Summary() string {
	if r.Denominator() == 0 {
		return "0/0 domains defined -- no coverage report can be computed"
	}
	pct := float64(r.CoveredCount()) / float64(r.Denominator()) * 100
	s := fmt.Sprintf("%d/%d domains covered (%.0f%%)", r.CoveredCount(), r.Denominator(), pct)
	if n := r.NotCoveredCount(); n > 0 {
		s += fmt.Sprintf("; %d not yet covered", n)
	}
	if excl := r.Exclusions(); len(excl) > 0 {
		s += fmt.Sprintf("; %d excluded: %s", len(excl), strings.Join(excl, "; "))
	}
	return s
}

// AudspectWebGWCoverageReport returns Audspect's current,
// repository-verified WebGW coverage, mirroring this package's own
// architecture spec's §5 Coverage Matrix table exactly. Update this
// function at the end of every future phase that changes a domain's
// status -- a divergence between this function and §5's own table is
// a defect in whichever one is stale, never an acceptable permanent
// inconsistency.
func AudspectWebGWCoverageReport() (CoverageReport, error) {
	return NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "URL filtering/categorization/reputation", Status: CoverageCovered},
		{DomainID: "02", DomainName: "TLS inspection", Status: CoverageCovered},
		{DomainID: "03", DomainName: "DLP and web exfiltration", Status: CoverageCovered},
		{DomainID: "04", DomainName: "Malware/exploit delivery/file protection", Status: CoverageNotCovered},
		{DomainID: "05", DomainName: "Identity/auth/policy assignment", Status: CoverageCovered},
		{DomainID: "06", DomainName: "SaaS/shadow IT/CASB", Status: CoverageCovered},
		{DomainID: "07", DomainName: "DNS/covert channels/C2 (gateway-side policy)", Status: CoverageCovered},
		{DomainID: "08", DomainName: "Proxy bypass/egress control", Status: CoverageCovered},
		{DomainID: "09", DomainName: "Configuration drift/administration", Status: CoverageCovered},
		{DomainID: "10", DomainName: "Detection/telemetry/SIEM/response", Status: CoverageCovered},
		{DomainID: "11", DomainName: "Availability/resilience", Status: CoverageCovered},
		{DomainID: "12", DomainName: "Cross-control attack chains/industry-specific", Status: CoverageCovered},
	})
}
