package endpointrisk

import "time"

// Finding is one evidence-backed issue shown on a category card.
// EstimatedTime/RequiresReboot/CanAudspectFix are deliberately absent --
// this sub-project ships no remediation-execution mechanism, so there is
// nothing honest to say about how a fix would be applied yet.
type Finding struct {
	Title            string `json:"title"`
	Severity         string `json:"severity"` // Critical | High | Medium | Low
	Risk             string `json:"risk"`
	AffectedStandard string `json:"affectedStandard,omitempty"`
	Remediation      string `json:"remediation"`
}

// CategoryScore is one category's contribution to the Health Score.
// Collected=false means no data source exists for this category yet
// (Security Configuration, Identity, Patch Management, Application Risk in
// V1) -- Score/Deficit/Findings are meaningless in that case and the
// frontend must render a "Not yet collected" placeholder instead of a 0.
type CategoryScore struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Collected bool      `json:"collected"`
	Score     int       `json:"score,omitempty"`   // 0-100, higher = safer
	Deficit   int       `json:"deficit,omitempty"` // 100 - Score
	Findings  []Finding `json:"findings,omitempty"`
}

// ActionItem is one row of the Recommended Action Plan: the worst finding
// in the category with the biggest deficit, not a fabricated per-finding
// risk-reduction percentage.
type ActionItem struct {
	CategoryID   string  `json:"categoryId"`
	CategoryName string  `json:"categoryName"`
	Deficit      int     `json:"deficit"`
	Finding      Finding `json:"finding"`
}

// AttackPathStep is one edge in the endpoint's attack-path chain narrative,
// rendered directly from exposure.Recommendations -- no new correlation
// logic.
type AttackPathStep struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// EndpointHealth is the full computed result for one agent.
type EndpointHealth struct {
	AgentID         string           `json:"agentId"`
	HealthScore     int              `json:"healthScore"`
	CriticalityRisk int              `json:"criticalityRisk"` // exposure.Scores.CriticalityRisk, sort/priority signal only -- never part of HealthScore
	Categories      []CategoryScore  `json:"categories"`
	ActionPlan      []ActionItem     `json:"actionPlan"`
	AttackPathChain []AttackPathStep `json:"attackPathChain"`
	Trend           string           `json:"trend"` // Improving | Stable | Declining | InsufficientData
}

// ComplianceInput is Task 2's compliance rollup output: one CompliancePercent
// per loaded framework, plus the real failed-control findings with their
// existing remediation text.
type ComplianceInput struct {
	PercentByFramework map[string]float64
	FailedFindings     []Finding
	Collected          bool
}

// BASReadinessInput is Task 2's BAS readiness aggregation output.
type BASReadinessInput struct {
	TechniquesTested int
	PassRate         float64 // 0-100
	LastExecutedAt   *time.Time
	Collected        bool
}
