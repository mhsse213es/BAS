package endpointrisk

import "time"

// Finding is one evidence-backed issue shown on a category card.
// EstimatedTime/RequiresReboot/CanAudspectFix are deliberately absent --
// this sub-project ships no remediation-execution mechanism, so there is
// nothing honest to say about how a fix would be applied yet.
// ID/Description/Reference/Expected/Observed/Passed/LastObserved/LastPassed
// are populated by posture-check findings (Security Configuration,
// Identity); every other finding builder (attack-path, detection,
// vulnerability, compliance, BAS-readiness) leaves them zero-valued --
// purely additive, no behavior change for those categories.
type Finding struct {
	ID               string     `json:"id,omitempty"` // check_id, for posture-check findings
	Title            string     `json:"title"`
	Description      string     `json:"description,omitempty"`
	Severity         string     `json:"severity"` // Critical | High | Medium | Low
	Risk             string     `json:"risk"`
	AffectedStandard string     `json:"affectedStandard,omitempty"`
	Remediation      string     `json:"remediation"`
	Reference        string     `json:"reference,omitempty"`
	Expected         string     `json:"expected,omitempty"`
	Observed         string     `json:"observed,omitempty"`
	Passed           bool       `json:"passed"`
	LastObserved     *time.Time `json:"lastObserved,omitempty"`
	LastPassed       *time.Time `json:"lastPassed,omitempty"`
}

// CategoryScore is one category's contribution to the Health Score.
// Collected=false means no data source exists for this category yet
// (Patch Management, Application Risk in V1) -- Score/Deficit/Findings are
// meaningless in that case and the frontend must render a "Not yet
// collected" placeholder instead of a 0.
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

// TrendDetail is now-vs-7-days-ago: a coarse band comparison (Direction,
// averaged across whichever of Compliance/BAS/SecurityConfig/Identity are
// Collected) plus a real new/resolved-findings diff computed only from
// Security Configuration + Identity, since those are the only categories
// with a stable per-finding ID (check_id) that survives across two points
// in time. Compliance/BAS-Readiness findings aren't stably keyed the same
// way, so they stay covered by Direction only.
type TrendDetail struct {
	Direction        string    `json:"direction"` // Improving | Stable | Declining | InsufficientData
	NewFindings      []Finding `json:"newFindings,omitempty"`
	ResolvedFindings []Finding `json:"resolvedFindings,omitempty"`
}

// EndpointHealth is the full computed result for one agent.
type EndpointHealth struct {
	AgentID         string           `json:"agentId"`
	HealthScore     int              `json:"healthScore"`
	CriticalityRisk int              `json:"criticalityRisk"` // exposure.Scores.CriticalityRisk, sort/priority signal only -- never part of HealthScore
	Categories      []CategoryScore  `json:"categories"`
	ActionPlan      []ActionItem     `json:"actionPlan"`
	AttackPathChain []AttackPathStep `json:"attackPathChain"`
	Trend           TrendDetail      `json:"trend"`
}

// ComplianceInput is the compliance rollup output: one CompliancePercent
// per loaded framework, plus the real failed-control findings with their
// existing remediation text.
type ComplianceInput struct {
	PercentByFramework map[string]float64
	FailedFindings     []Finding
	Collected          bool
}

// BASReadinessInput is the BAS readiness aggregation output.
type BASReadinessInput struct {
	TechniquesTested int
	PassRate         float64 // 0-100
	LastExecutedAt   *time.Time
	Collected        bool
}

// PostureCheckInput is the shared aggregation output for BOTH Security
// Configuration and Identity -- deliberately one generic type, not
// SecurityConfigInput/IdentityInput, since the two categories are
// structurally identical (a set of check_id-keyed pass/fail results).
type PostureCheckInput struct {
	Score     int       // 0-100, weighted pass rate (see aggregation)
	Passed    int       // unweighted count of currently-passing checks
	Failed    int       // unweighted count of currently-failing checks
	Total     int       // Passed + Failed
	Findings  []Finding // one per currently-failing check_id, ID = check_id
	Collected bool
}

// HealthInputs bundles the four evidence-row-backed category inputs so
// ComputeHealth takes two params (now, past) instead of eight positional
// ones -- every call site needed updating anyway to add SecurityConfig/
// Identity, so this is the natural point to fix the signature's ergonomics.
type HealthInputs struct {
	Compliance     ComplianceInput
	BAS            BASReadinessInput
	SecurityConfig PostureCheckInput
	Identity       PostureCheckInput
}
