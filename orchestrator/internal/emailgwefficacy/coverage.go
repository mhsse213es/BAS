package emailgwefficacy

import (
	"fmt"
	"strings"
)

// CoverageStatus is one taxonomy area's coverage state in a
// CoverageReport. "Covered" means at least one fixture-backed, proven
// scenario exists for the area -- not that the area's full breadth is
// built out; emailGW.txt's own taxonomy areas each name many
// sub-capabilities, and most covered areas here have proven only one
// or a few of them so far.
type CoverageStatus string

const (
	CoverageCovered    CoverageStatus = "covered"
	CoverageExcluded   CoverageStatus = "excluded"
	CoverageNotCovered CoverageStatus = "not-covered"
)

// AreaCoverage is one taxonomy area's entry in a CoverageReport.
// ExclusionReason is required whenever Status is CoverageExcluded --
// enforced by NewCoverageReport, never left to convention.
type AreaCoverage struct {
	AreaID          string         `json:"areaId"`
	AreaName        string         `json:"areaName"`
	Status          CoverageStatus `json:"status"`
	ExclusionReason string         `json:"exclusionReason,omitempty"`
}

// CoverageReport is a validated set of AreaCoverage entries. Its only
// rendering surface is Summary -- there is no method that returns a
// bare percentage on its own, which is how "never an unqualified
// percentage" (emailGW.txt's own quality-proof requirement) is
// enforced structurally rather than by convention.
type CoverageReport struct {
	areas []AreaCoverage
}

// NewCoverageReport validates areas at construction time, never at
// render time: no AreaID may repeat, and every CoverageExcluded area
// must carry a non-empty ExclusionReason -- an exclusion without a
// documented reason is exactly the "silently dropped" failure mode
// this initiative exists to prevent.
func NewCoverageReport(areas []AreaCoverage) (CoverageReport, error) {
	seen := make(map[string]bool, len(areas))
	for _, a := range areas {
		if seen[a.AreaID] {
			return CoverageReport{}, fmt.Errorf("duplicate area ID %q", a.AreaID)
		}
		seen[a.AreaID] = true
		switch a.Status {
		case CoverageCovered, CoverageExcluded, CoverageNotCovered:
		default:
			return CoverageReport{}, fmt.Errorf("area %q has unrecognized status %q", a.AreaID, a.Status)
		}
		if a.Status == CoverageExcluded && a.ExclusionReason == "" {
			return CoverageReport{}, fmt.Errorf("area %q marked excluded with no documented reason", a.AreaID)
		}
	}
	return CoverageReport{areas: areas}, nil
}

// Denominator is the total number of areas considered, including
// CoverageNotCovered ones -- an area that is merely incomplete is
// never quietly treated as if it didn't exist.
func (r CoverageReport) Denominator() int { return len(r.areas) }

func (r CoverageReport) CoveredCount() int    { return r.countStatus(CoverageCovered) }
func (r CoverageReport) ExcludedCount() int   { return r.countStatus(CoverageExcluded) }
func (r CoverageReport) NotCoveredCount() int { return r.countStatus(CoverageNotCovered) }

func (r CoverageReport) countStatus(status CoverageStatus) int {
	n := 0
	for _, a := range r.areas {
		if a.Status == status {
			n++
		}
	}
	return n
}

// Areas returns a copy of every area this report was built from --
// a copy, so a caller (e.g. an API handler rendering this report)
// can never mutate the report's own internal state by holding this
// slice.
func (r CoverageReport) Areas() []AreaCoverage {
	areas := make([]AreaCoverage, len(r.areas))
	copy(areas, r.areas)
	return areas
}

// Exclusions renders every excluded area's own documented reason -- a
// reader must never need to query a separate field to learn why an
// area was excluded.
func (r CoverageReport) Exclusions() []string {
	var out []string
	for _, a := range r.areas {
		if a.Status == CoverageExcluded {
			out = append(out, fmt.Sprintf("%s (%s): %s", a.AreaID, a.AreaName, a.ExclusionReason))
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
		return "0/0 areas defined -- no coverage report can be computed"
	}
	pct := float64(r.CoveredCount()) / float64(r.Denominator()) * 100
	s := fmt.Sprintf("%d/%d areas covered (%.0f%%)", r.CoveredCount(), r.Denominator(), pct)
	if n := r.NotCoveredCount(); n > 0 {
		s += fmt.Sprintf("; %d not yet covered", n)
	}
	if excl := r.Exclusions(); len(excl) > 0 {
		s += fmt.Sprintf("; %d excluded: %s", len(excl), strings.Join(excl, "; "))
	}
	return s
}

// AudspectEmailGWCoverageReport returns Audspect's current,
// repository-verified EmailGW coverage, mirroring this package's own
// architecture spec's §5 Coverage Matrix table exactly (areas A-G
// only -- vendors/industry-profiles/regulatory are tracked in that
// table directly, not as CoverageReport areas, since they aren't
// taxonomy areas with their own scenario pipeline). Update this
// function at the end of every future phase that changes an area's
// status -- a divergence between this function and §5's own table is
// a defect in whichever one is stale, never an acceptable permanent
// inconsistency.
func AudspectEmailGWCoverageReport() (CoverageReport, error) {
	return NewCoverageReport([]AreaCoverage{
		{AreaID: "A", AreaName: "Sender identity/spoofing/trust", Status: CoverageCovered},
		{AreaID: "B", AreaName: "Phishing/social engineering", Status: CoverageCovered},
		{AreaID: "C", AreaName: "Attachments/content inspection", Status: CoverageCovered},
		{AreaID: "D", AreaName: "URL/browser/post-delivery protection", Status: CoverageCovered},
		{AreaID: "E", AreaName: "Outbound security/DLP", Status: CoverageCovered},
		{AreaID: "F", AreaName: "Mailbox/identity/tenant security", Status: CoverageCovered},
		{
			AreaID:          "G",
			AreaName:        "Detection/IR/resilience",
			Status:          CoverageNotCovered,
			ExclusionReason: "",
		},
	})
}
