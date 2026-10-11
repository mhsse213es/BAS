// Package rwscore is the ransomware-mastery scoring engine: it turns a
// run's rw_capability_results coverage counts (internal/db, sub-project
// #1) into a 5-dimension weighted score, a qualitative rating, and the
// risk-gate override the roadmap names by name. Pure computation -- no
// I/O, no DB import, so the whole engine is table-driven unit tests.
package rwscore

// Dimension names one of the five ransomware-mastery scoring dimensions --
// the same five rwevidence.Capability values, duplicated here (not
// imported) so rwscore stays input-agnostic, the same discipline
// rwevidence.StepInput uses to stay independent of scenario/models.
type Dimension string

const (
	DimensionPrevention     Dimension = "prevention"
	DimensionDetection      Dimension = "detection"
	DimensionContainment    Dimension = "containment"
	DimensionRecovery       Dimension = "recovery"
	DimensionDataProtection Dimension = "data_protection"
)

// CoverageRow mirrors db.RWCoverageRow's shape field-for-field -- rwscore
// never imports internal/db; the caller (internal/api) translates.
type CoverageRow struct {
	TechniqueID    string
	Capability     string
	Verdict        string
	SkipReason     string
	SpecificReason string
	Count          int
}

// DimensionScore is one dimension's independently-computed bucket counts
// and pass rate. Every count is carried, not just the ratio, so nothing a
// caller might want to surface is hidden behind a single opaque
// percentage.
type DimensionScore struct {
	Dimension     Dimension
	Pass          int
	Fail          int
	Error         int
	Unknown       int
	NotApplicable int
	NotTested     int
	PassRate      float64
}
