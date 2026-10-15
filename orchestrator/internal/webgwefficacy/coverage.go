package webgwefficacy

import (
	"fmt"
	"strings"
	"time"
)

// CoverageExclusion is one denominator item (a domain, a vendor, or
// any other thing this package reports coverage over) that is
// deliberately excluded from a coverage count, together with why --
// generalized beyond "domain" because this package's own real
// exclusion examples span both domains and vendors (e.g. Zscaler,
// Phase 4).
type CoverageExclusion struct {
	ItemID string `json:"itemId"`
	Reason string `json:"reason"`
}

// CoverageReport is a coverage count with an explicit denominator and
// explicit exclusions attached -- never a bare percentage, per the
// architecture spec's own quality-proof requirement ("no coverage
// percentage without a defined denominator and explicit exclusions").
// This package never maintains its own hardcoded copy of "all WebGW
// domains" -- that list lives in the architecture spec's own Coverage
// Matrix (§5); callers derive TotalItems/CoveredItems from it rather
// than this package duplicating and drifting from it.
type CoverageReport struct {
	TotalItems   int                 `json:"totalItems"`
	CoveredItems int                 `json:"coveredItems"`
	Exclusions   []CoverageExclusion `json:"exclusions"`
	GeneratedAt  time.Time           `json:"generatedAt"`
}

func NewCoverageReport(totalItems, coveredItems int, exclusions []CoverageExclusion, generatedAt time.Time) CoverageReport {
	return CoverageReport{
		TotalItems:   totalItems,
		CoveredItems: coveredItems,
		Exclusions:   exclusions,
		GeneratedAt:  generatedAt,
	}
}

// Summary renders this report as a single human-readable line that
// always states its denominator and exclusions explicitly, by
// construction -- there is no code path that emits a percentage
// without also stating the raw counts and the exclusions clause.
func (r CoverageReport) Summary() string {
	pct := 0.0
	if r.TotalItems > 0 {
		pct = float64(r.CoveredItems) / float64(r.TotalItems) * 100
	}

	exclusionText := "none"
	if len(r.Exclusions) > 0 {
		reasons := make([]string, len(r.Exclusions))
		for i, e := range r.Exclusions {
			reasons[i] = fmt.Sprintf("%s (%s)", e.ItemID, e.Reason)
		}
		exclusionText = strings.Join(reasons, "; ")
	}

	return fmt.Sprintf(
		"%d/%d covered (%.1f%% of %d total); exclusions: %s; generated %s",
		r.CoveredItems, r.TotalItems, pct, r.TotalItems, exclusionText, r.GeneratedAt.Format(time.RFC3339),
	)
}
