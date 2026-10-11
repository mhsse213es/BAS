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
	Dimension     Dimension `json:"dimension"`
	Pass          int       `json:"pass"`
	Fail          int       `json:"fail"`
	Error         int       `json:"error"`
	Unknown       int       `json:"unknown"`
	NotApplicable int       `json:"notApplicable"`
	NotTested     int       `json:"notTested"`
	PassRate      float64   `json:"passRate"`
}

// Rating is the overall qualitative rating a customer sees.
type Rating string

const (
	RatingProtected  Rating = "protected"
	RatingAtRisk     Rating = "at_risk"
	RatingVulnerable Rating = "vulnerable"
)

// RunScore is this sub-project's complete deliverable for one run. JSON
// tags are camelCase, matching every other API response struct in this
// codebase (e.g. VariantCoverageReport) -- found missing during final
// review.
type RunScore struct {
	Overall          float64          `json:"overall"`
	Rating           Rating           `json:"rating"`
	Dimensions       []DimensionScore `json:"dimensions"`
	CriticalFailures []string         `json:"criticalFailures"`
	GateTriggered    bool             `json:"gateTriggered"`
}
