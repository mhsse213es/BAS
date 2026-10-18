package phishcatalog

import (
	"fmt"
	"strings"
)

// coverageRank orders CoverageState from weakest to strongest evidence
// -- the single source of truth RequireNoCoverageRegression compares
// against, so "regression" always means the same thing everywhere this
// package uses it.
var coverageRank = map[CoverageState]int{
	CoverageCatalogOnly:   0,
	CoverageFixtureTested: 1,
	CoverageAdapterTested: 2,
	CoverageLiveValidated: 3,
}

// ScenarioCoverage is one scenario's entry in a CoverageReport --
// mirrors internal/emailgwefficacy.AreaCoverage's own role, one level
// finer-grained: per scenario ID rather than per taxonomy area, since
// phishcatalog's maturity ladder (catalog-only/fixture-tested/adapter-
// tested/live-validated) is itself already a per-scenario property.
type ScenarioCoverage struct {
	ScenarioID string
	Name       string
	Area       Area
	Coverage   CoverageState
}

// CoverageReport is a validated snapshot of every scenario's
// ScenarioCoverage. Its only rendering surface is Summary -- there is
// no method returning a bare percentage on its own, the same
// structural discipline emailgwefficacy.CoverageReport enforces:
// "never an unqualified percentage."
type CoverageReport struct {
	entries []ScenarioCoverage
}

// NewCoverageReport validates entries at construction time: no
// ScenarioID may repeat, and every Coverage value must be one of the
// four recognized CoverageState constants.
func NewCoverageReport(entries []ScenarioCoverage) (CoverageReport, error) {
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if seen[e.ScenarioID] {
			return CoverageReport{}, fmt.Errorf("duplicate scenario ID %q", e.ScenarioID)
		}
		seen[e.ScenarioID] = true
		if _, ok := coverageRank[e.Coverage]; !ok {
			return CoverageReport{}, fmt.Errorf("scenario %q has unrecognized coverage %q", e.ScenarioID, e.Coverage)
		}
	}
	return CoverageReport{entries: entries}, nil
}

// AudspectPhishingCoverageReport builds a CoverageReport directly from
// AudspectPhishingCatalog's own live scenarios -- so this report can
// never drift from the catalog it describes the way a hand-maintained
// snapshot could.
func AudspectPhishingCoverageReport() (CoverageReport, error) {
	scenarios, err := AudspectPhishingCatalog()
	if err != nil {
		return CoverageReport{}, fmt.Errorf("loading scenario catalog: %w", err)
	}
	entries := make([]ScenarioCoverage, 0, len(scenarios))
	for _, s := range scenarios {
		entries = append(entries, ScenarioCoverage{ScenarioID: s.ID, Name: s.Name, Area: s.Area, Coverage: s.Coverage})
	}
	return NewCoverageReport(entries)
}

func (r CoverageReport) Denominator() int { return len(r.entries) }

func (r CoverageReport) CatalogOnlyCount() int   { return r.countStatus(CoverageCatalogOnly) }
func (r CoverageReport) FixtureTestedCount() int { return r.countStatus(CoverageFixtureTested) }
func (r CoverageReport) AdapterTestedCount() int { return r.countStatus(CoverageAdapterTested) }
func (r CoverageReport) LiveValidatedCount() int { return r.countStatus(CoverageLiveValidated) }

func (r CoverageReport) countStatus(status CoverageState) int {
	n := 0
	for _, e := range r.entries {
		if e.Coverage == status {
			n++
		}
	}
	return n
}

// Entries returns a copy of every scenario entry this report was built
// from, so a caller can never mutate the report's own internal state.
func (r CoverageReport) Entries() []ScenarioCoverage {
	entries := make([]ScenarioCoverage, len(r.entries))
	copy(entries, r.entries)
	return entries
}

// Summary renders every coverage tier's count against the
// denominator, plus the live-validated share as an explicitly-labeled
// percentage that always carries its own denominator alongside it --
// "no scenario marked complete on catalogue existence... alone" means
// this Summary can never collapse catalog-only entries into the same
// number as live-validated ones.
func (r CoverageReport) Summary() string {
	if r.Denominator() == 0 {
		return "0/0 scenarios defined -- no coverage report can be computed"
	}
	pct := float64(r.LiveValidatedCount()) / float64(r.Denominator()) * 100
	return fmt.Sprintf(
		"%d scenarios total: %d catalog-only, %d fixture-tested, %d adapter-tested, %d live-validated (%.0f%% of %d live-validated)",
		r.Denominator(), r.CatalogOnlyCount(), r.FixtureTestedCount(), r.AdapterTestedCount(), r.LiveValidatedCount(),
		pct, r.Denominator(),
	)
}

// RequireNoCoverageRegression compares a baseline CoverageReport
// (e.g. one captured at the last release) against current and returns
// an error naming every scenario whose Coverage dropped in rank
// (coverageRank) -- a release-qualification gate: silently shipping a
// scenario that regressed from adapter-tested back to catalog-only is
// exactly the "artificial completeness" drift the standing conditions
// exist to catch. A scenario present in current but absent from
// baseline (newly added) is never a regression; one present in
// baseline but absent from current is reported as a removal, since a
// scenario silently disappearing from the catalog is its own kind of
// undocumented regression.
func RequireNoCoverageRegression(baseline, current CoverageReport) error {
	baselineByID := make(map[string]ScenarioCoverage, len(baseline.entries))
	for _, e := range baseline.entries {
		baselineByID[e.ScenarioID] = e
	}
	currentByID := make(map[string]ScenarioCoverage, len(current.entries))
	for _, e := range current.entries {
		currentByID[e.ScenarioID] = e
	}

	var problems []string
	for id, before := range baselineByID {
		after, stillPresent := currentByID[id]
		if !stillPresent {
			problems = append(problems, fmt.Sprintf("%s: removed from the catalog (was %s)", id, before.Coverage))
			continue
		}
		if coverageRank[after.Coverage] < coverageRank[before.Coverage] {
			problems = append(problems, fmt.Sprintf("%s: regressed from %s to %s", id, before.Coverage, after.Coverage))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("coverage regression detected: %s", strings.Join(problems, "; "))
}
