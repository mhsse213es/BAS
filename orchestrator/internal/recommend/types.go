// Package recommend is the Phase 6 recommendation engine: it ranks
// ART-testable ATT&CK techniques by how much value testing them next would
// add, combining threat priority (internal/reporting's shipped scoring), how
// long since the fleet last tested them (scenario_runs), and how relevant
// they are to this specific environment (the SP3 attack-path graph + SP6
// asset criticality). Pure consumer — owns no DB tables.
package recommend

import "time"

// SuggestedScenario mirrors the shape /api/ti/suggest-pack already emits, so
// the existing scenario-creation flow consumes it unchanged.
type SuggestedScenario struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	ARTTechniques []string `json:"artTechniques"`
}

// RecommendedTechnique is one ranked technique plus the evidence behind its
// rank. Score is the composite; the three term fields are exposed so an
// operator can see WHY something ranked where it did.
type RecommendedTechnique struct {
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`

	Score int    `json:"score"` // 0-100 composite
	Tier  string `json:"tier"`  // Critical | High | Medium | Low

	CoverageState string     `json:"coverageState"` // never-tested | stale | recent
	LastTestedAt  *time.Time `json:"lastTestedAt,omitempty"`
	LastVerdict   string     `json:"lastVerdict,omitempty"`

	ActorPriority   int `json:"actorPriority"`
	ThreatPriority  int `json:"threatPriority"`
	CoverageGap     int `json:"coverageGap"`
	EnvironmentRisk int `json:"environmentRisk"`

	KEV            bool     `json:"kev"`
	EPSSPercentile float64  `json:"epssPercentile,omitempty"`
	ThreatActors   int      `json:"threatActors"`
	Reasons        []string `json:"reasons"`
}

// Recommendations is one Build() result. Techniques is always non-nil (an
// empty slice, not null) so the UI can iterate without a guard.
type Recommendations struct {
	Techniques        []RecommendedTechnique `json:"techniques"`
	SuggestedScenario SuggestedScenario      `json:"suggestedScenario"`
	HasData           bool                   `json:"hasData"`
}
