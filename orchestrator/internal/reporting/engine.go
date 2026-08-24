// Package reporting builds full assessment reports and audit-pack ZIPs.
package reporting

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

// ScenarioResolver is the slice of the scenario engine the reporting layer needs
// to resolve a run's Detection Validation expectations. *scenario.Engine
// satisfies it. Kept as an interface so reporting stays testable without a real
// scenario engine, and nil-safe so a report renders fine when it is not wired.
type ScenarioResolver interface {
	Get(id string) (*scenario.Scenario, bool)
	ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef)
}

// VerificationResolver is the slice of the Verification Store the reporting
// layer READS to overlay analyst/API attestations on top of the automatic
// on-host verdicts. *verification.Store satisfies it. Kept as an interface so
// reporting stays testable and nil-safe: when nil, only automatic verification
// contributes (exactly the SP1 behaviour).
type VerificationResolver interface {
	CurrentForRun(ctx context.Context, runID string) (map[string]verification.Record, error)
	EvidenceCountsForRun(ctx context.Context, runID string) (map[string]int, error)
}

// RuleLibraryResolver is the slice of the SP2 Rule Library engine the
// reporting layer needs for the Attack Path Detection Coverage section.
// *rulelib.Engine satisfies it; nil-safe: WithRuleLibrary is optional and
// that section stays inactive while nil, same convention as
// ScenarioResolver/VerificationResolver above.
type RuleLibraryResolver interface {
	RulesByTechnique(techniqueID string) []rulelib.Rule
}

// Engine aggregates data from the DB into structured reports.
type Engine struct {
	db            *pgxpool.Pool
	scenarios     ScenarioResolver     // nil until WithScenarios is called; Detection Validation stays inactive while nil
	verifications VerificationResolver // nil until WithVerifications is called; only automatic verdicts contribute while nil
	rules         RuleLibraryResolver  // nil until WithRuleLibrary is called; Attack Path Detection Coverage stays inactive while nil
	// sectors/regions are the deployment's own configured values
	// (config.Config.ThreatIntelSectors/ThreatIntelRegions), set via
	// WithSectorRegion. Empty means priority scores never get the
	// sector/region bonus. See
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	sectors []string
	regions []string
	// threatIntelProvider is the configured ioc.Provider's name (e.g. "otx"),
	// set via WithThreatIntelProvider. Empty means the Threat Intelligence
	// section stays inactive -- matches the same "nil/empty means feature off"
	// convention as the fields above.
	threatIntelProvider string
}

func NewEngine(db *pgxpool.Pool) *Engine { return &Engine{db: db} }

// WithScenarios attaches the scenario resolver used to build the Detection
// Validation section. Returns the engine for chaining.
func (e *Engine) WithScenarios(r ScenarioResolver) *Engine {
	e.scenarios = r
	return e
}

// WithVerifications attaches the Verification Store so manual (SP2) and API
// (SP3) attestations overlay the automatic verdicts. Returns the engine for
// chaining.
func (e *Engine) WithVerifications(r VerificationResolver) *Engine {
	e.verifications = r
	return e
}

// WithRuleLibrary attaches the Rule Library resolver used by the Attack Path
// Detection Coverage section. Returns the engine for chaining.
func (e *Engine) WithRuleLibrary(r RuleLibraryResolver) *Engine {
	e.rules = r
	return e
}

// WithSectorRegion attaches the deployment's own sector/region, used to
// weight technique priority scores toward actors that target them. Returns
// the engine for chaining.
func (e *Engine) WithSectorRegion(sectors, regions []string) *Engine {
	e.sectors = sectors
	e.regions = regions
	return e
}

// WithThreatIntelProvider attaches the name of the configured ioc.Provider
// (e.g. "otx") so populateThreatIntel knows which provider's ioc_enrichment
// rows to read -- the cache is provider-keyed, so an unfiltered join would be
// ambiguous if a provider is ever switched and old rows linger. Returns the
// engine for chaining.
func (e *Engine) WithThreatIntelProvider(name string) *Engine {
	e.threatIntelProvider = name
	return e
}

// Sectors returns the configured deployment sectors, for callers (like
// internal/api's recommend handler) that hold an *Engine and need the same
// values without duplicating storage.
func (e *Engine) Sectors() []string { return e.sectors }

// Regions returns the configured deployment regions, mirroring Sectors.
func (e *Engine) Regions() []string { return e.regions }

// ── Report types ──────────────────────────────────────────────────────────────

// FullReport is the complete assessment output for one agent.
type FullReport struct {
	GeneratedAt         time.Time        `json:"generatedAt"`
	Agent               models.Agent     `json:"agent"`
	Summary             ExecutiveSummary `json:"summary"`
	TacticHeatmap       []TacticEntry    `json:"tacticHeatmap"`
	TopFindings         []Finding        `json:"topFindings"`
	Runs                []RunSummary     `json:"runs"`
	SecurityTools       []string         `json:"securityTools"`
	DetectionCategories []Category       `json:"detectionCategories"`
	ObjectiveRisks      []ObjectiveRisk  `json:"objectiveRisks"`
	Reverted            []string         `json:"reverted"` // endpoint changes rolled back post-run (cleanup evidence)
	Detection           DetectionSummary `json:"detection"`
	// DetectionValidation is the expected-vs-actual gap analysis (Detection
	// Validation Pack). HasData is false — and the section renders as before —
	// for any run whose scenario declares no expected_detection.
	DetectionValidation DetectionValidationSection `json:"detectionValidation"`
	TrendAnalysis       TrendSummary               `json:"trendAnalysis"`
	AttackPath          AttackPath                 `json:"attackPath"`
	AttackFlow          []AttackFlowNode           `json:"attackFlow,omitempty"`
	AttackFlowSummary   AttackFlowSummary          `json:"attackFlowSummary"`
	// VariantCoverage holds multi-variant evasion analysis for the HTML/PDF report.
	// Populated from scenario_variant_technique_summary; nil for runs with no variant depth.
	VariantCoverage *VariantCoverageSection `json:"variantCoverage,omitempty"`
	// CampaignVariantCoverage holds trend-focused multi-variant analysis for campaign reports.
	// Populated from campaign_variant_summary; nil for non-campaign reports.
	CampaignVariantCoverage *CampaignVariantSection `json:"campaignVariantCoverage,omitempty"`
	// EnvRestoration summarises cleanup success for this run/campaign:
	// what was touched, what was reverted, and what (if anything) was left behind.
	EnvRestoration *EnvRestoration `json:"envRestoration,omitempty"`
	// ReadinessScores is the per-threat-actor readiness analysis: for each ATT&CK
	// group whose techniques overlap with this run, how well were they prevented
	// and detected? Nil when <3 techniques overlap with any group.
	ReadinessScores []ReadinessScore `json:"readinessScores,omitempty"`
	// KEVExposure summarises which tested techniques have active CISA KEV CVEs and
	// how the controls performed against them. Nil when the cves table is empty.
	KEVExposure *KEVExposure `json:"kevExposure,omitempty"`
	// RansomwareReadiness is a subset of ReadinessScores filtered to known ransomware
	// threat actors, sorted worst prevention readiness first.
	RansomwareReadiness []ReadinessScore `json:"ransomwareReadiness,omitempty"`
	// PriorityScores ranks each tested technique by combined KEV+EPSS+threat-actor
	// signal into an actionable tier. Techniques with no signal and verdict!=fail
	// are excluded. Nil when nothing is testable.
	PriorityScores []TechniquePriority `json:"priorityScores,omitempty"`
	// DetectionTechniques is the per-technique purple-team verdict from the agent's
	// post-run alert sweep (prevented|detected|undetected + confidence). Empty until
	// the agent submits detections for the run. Sourced from scenario_runs.detection_summary.
	DetectionTechniques []DetectionTechnique `json:"detectionTechniques,omitempty"`
	// KillChain is the run's adversary actions paired with the defensive outcome,
	// ordered by ATT&CK kill-chain phase — the dual-rail purple-team timeline.
	KillChain []KillChainStep `json:"killChain,omitempty"`
	// TechniqueMatrix is the per-step detection validation table: execution result
	// combined with post-run EDR alert correlation for every technique in the run.
	TechniqueMatrix []TechniqueRow `json:"techniqueMatrix,omitempty"`
	// Executive-grade derivations (Cymulate-style report).
	ExecutiveConclusion string          `json:"executiveConclusion"`
	TopRiskDrivers      []RiskDriver    `json:"topRiskDrivers"`
	Insights            Insights        `json:"insights"`
	ActionPlan          []ActionItem    `json:"actionPlan"`
	Reliability         Reliability     `json:"reliability"`
	Glossary            []GlossaryEntry `json:"glossary"`
	// Scope is set for fleet-wide (campaign) reports; nil for single-agent/run
	// reports. When present the cover and Asset Context render the campaign scope
	// and the per-agent breakdown instead of single-agent metadata.
	Scope          *ReportScope       `json:"scope,omitempty"`
	CampaignAgents []CampaignAgentRow `json:"campaignAgents,omitempty"`
	// AttackPathValidation is the native attack-path engine's lateral-movement /
	// blast-radius / crown-jewel analysis for the subject. nil until the
	// attackpath.collect task has produced edges and the graph has been analyzed
	// (Phase 1 collection). When present the report renders the Attack Path
	// Validation section; otherwise that section shows a "not yet collected" state.
	AttackPathValidation *attackpath.Summary `json:"attackPathValidation,omitempty"`
	// PathCorrelation is the SP3 Attack Path <-> Detection Correlation
	// annotation of AttackPathValidation's dangerous paths and choke points.
	// nil under the exact same conditions as AttackPathValidation (no
	// collection yet), or when WithRuleLibrary was never called.
	PathCorrelation        *pathcorrelation.AttackPathCorrelation `json:"pathCorrelation,omitempty"`
	AttackSurfaceAge       int                                    `json:"attackSurfaceAge"`
	OldestFindingName      string                                 `json:"oldestFindingName"`
	OldestFindingID        string                                 `json:"oldestFindingID"`
	OldestFindingSeverity  string                                 `json:"oldestFindingSeverity"`
	AttackSurfaceSLAStatus string                                 `json:"attackSurfaceSLAStatus"`
	DetectionSources       []DetectionSource                      `json:"detectionSources,omitempty"`
	PerfCPUBefore          float64                                `json:"perfCpuBefore"`
	PerfCPUAfter           float64                                `json:"perfCpuAfter"`
	PerfRAMBefore          float64                                `json:"perfRamBefore"`
	PerfRAMAfter           float64                                `json:"perfRamAfter"`
	PerfDiskBefore         float64                                `json:"perfDiskBefore"`
	PerfDiskAfter          float64                                `json:"perfDiskAfter"`
	CleanupFailed          bool                                   `json:"cleanupFailed"`
	CleanupFailedCount     int                                    `json:"cleanupFailedCount"`
	// CoverageBreakdown is the 3-bucket prevention/detection breakdown derived from
	// TechniqueMatrix (DetectionVerdict field). It powers the Coverage Analytics
	// page and is used in the executive summary score cards.
	CoverageBreakdown CoverageBreakdown `json:"coverageBreakdown"`
	// Alert fatigue metrics — populated from scenario_runs.alerts_total/alerts_high_fidelity/noise_score.
	AlertsTotal        int     `json:"alertsTotal"`
	AlertsHighFidelity int     `json:"alertsHighFidelity"`
	NoiseScore         float64 `json:"noiseScore"`
	// ScenarioName is the name of the scenario used to build this report.
	// Populated by Build (latest run's name), BuildFromRun, and BuildFromCampaign.
	// Used by handlers to construct descriptive download filenames.
	ScenarioName string `json:"scenarioName,omitempty"`
	// ActiveFilter is set when the report was generated with a result filter
	// (prevented/not_prevented/detected/not_detected). The score always reflects
	// the full unfiltered run; only the kill chain and technique matrix are subsetted.
	ActiveFilter     string `json:"activeFilter,omitempty"`
	FilterTotalCount int    `json:"filterTotalCount,omitempty"` // total techniques before filter
	FilterMatchCount int    `json:"filterMatchCount,omitempty"` // techniques matching the filter
	// PrivilegeSummary counts steps by execution context across the TechniqueMatrix.
	// Populated alongside TechniqueMatrix so the summary page can show privilege coverage.
	PrivilegeSummary PrivilegeSummary `json:"privilegeSummary"`
	// SkipBreakdown counts Result=Skipped entries by SkipReason. Populated by
	// deriveExecutive so a policy-constrained run reads as "compliant," not
	// "incomplete."
	SkipBreakdown SkipBreakdown `json:"skipBreakdown"`
	// StepsTotalBase/StepsEligibleBase are read directly from
	// scenario_runs.steps_total_base/steps_eligible_base (captured once at
	// dispatch time) — the raw inputs to Coverage, computed by deriveExecutive.
	StepsTotalBase    int `json:"stepsTotalBase"`
	StepsEligibleBase int `json:"stepsEligibleBase"`
	// Coverage reports Scenario Coverage (executed/total) and Eligible Coverage
	// (executed/eligible) so a policy-constrained run reads as complete against
	// what it could run, not incomplete against everything the scenario defines.
	Coverage CoverageSummary `json:"coverage"`
	// ThreatIntel is the configured provider's enrichment of this run's
	// extracted IOCs (run_iocs). Nil when no provider is configured or the run
	// has no IOCs. Populated by BuildFromRun only (single-run reports).
	ThreatIntel *ThreatIntelSection `json:"threatIntel,omitempty"`
}

// ThreatIntelSection is the report's "did this execution produce artifacts
// known to threat intelligence" answer -- summary-first, then per-indicator
// detail. No field here is called "confidence": tiers are derived from raw
// pulse counts under honest, non-authoritative names.
type ThreatIntelSection struct {
	Provider   string                 `json:"provider"` // "otx"
	Summary    ThreatIntelSummary     `json:"summary"`
	Indicators []ThreatIntelIndicator `json:"indicators"` // sorted worst-tier-first
}

type ThreatIntelSummary struct {
	ExtractedCount           int `json:"extractedCount"`
	PendingCount             int `json:"pendingCount"`
	UnknownCount             int `json:"unknownCount"`
	SuspiciousCount          int `json:"suspiciousCount"`
	MaliciousAssociatedCount int `json:"maliciousAssociatedCount"`
}

type ThreatIntelIndicator struct {
	Type            string   `json:"type"` // ip | domain | url | hash | cve
	Value           string   `json:"value"`
	TechniqueIDs    []string `json:"techniqueIds"`
	SimulationIDs   []string `json:"simulationIds"`
	Tier            string   `json:"tier"` // pending | unknown | suspicious | malicious-associated
	PulseCount      int      `json:"pulseCount"`
	PulseNames      []string `json:"pulseNames,omitempty"`
	MalwareFamilies []string `json:"malwareFamilies,omitempty"`
	AdversaryNames  []string `json:"adversaryNames,omitempty"`
	Industries      []string `json:"industries,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}

// PrivilegeSummary is the per-tier step count and prevention breakdown for the privilege table.
type PrivilegeSummary struct {
	User      int `json:"user"`
	Admin     int `json:"admin"`
	System    int `json:"system"`
	Legacy    int `json:"legacy"`    // unannotated steps (requires_priv not set)
	Fallbacks int `json:"fallbacks"` // steps that requested "user" but fell back to admin (executedAs contains "→")
	// Per-tier prevention counts (steps where exec was blocked/passed).
	UserPrevented   int `json:"userPrevented"`
	AdminPrevented  int `json:"adminPrevented"`
	SystemPrevented int `json:"systemPrevented"`
	LegacyPrevented int `json:"legacyPrevented"`
	// Per-tier prevention rates (0-100).
	UserRate   int `json:"userRate"`
	AdminRate  int `json:"adminRate"`
	SystemRate int `json:"systemRate"`
	LegacyRate int `json:"legacyRate"`
}

// VariantCoverageSection is the report section for multi-variant evasion results.
// Sourced from scenario_variant_technique_summary; populated only for runs with
// variant depth. All fields carry json tags (garble safety — see GenerateHTML).
type VariantCoverageSection struct {
	HasData              bool                 `json:"hasData"`
	TechniquesTotal      int                  `json:"techniquesTotal"`
	VariantsExecuted     int                  `json:"variantsExecuted"`
	Blocked              int                  `json:"blocked"`
	Detected             int                  `json:"detected"`
	Bypassed             int                  `json:"bypassed"`
	BypassRate           float64              `json:"bypassRate"`
	PreventionScore      float64              `json:"preventionScore"`
	DetectionScore       float64              `json:"detectionScore"`
	TechniquesWithBypass int                  `json:"techniquesWithBypass"`
	FirstBypassElapsed   string               `json:"firstBypassElapsed,omitempty"`
	TrendNote            string               `json:"trendNote,omitempty"`
	Maturity             VariantMaturityScore `json:"maturity"`
	Techniques           []VariantTechRow     `json:"techniques"`
}

// VariantMaturityScore flags which test dimensions were exercised in the run.
type VariantMaturityScore struct {
	ExecutionTested bool `json:"executionTested"`
	EncodingTested  bool `json:"encodingTested"`
	PrivilegeTested bool `json:"privilegeTested"`
	ProxyTested     bool `json:"proxyTested"`
	EvasionTested   bool `json:"evasionTested"` // always false (Advanced Evasion Pack not yet implemented)
}

// VariantTechRow is one technique entry in the variant coverage table.
type VariantTechRow struct {
	TechniqueID       string   `json:"techniqueId"`
	TechniqueName     string   `json:"techniqueName"`
	Tactic            string   `json:"tactic"`
	VariantsExecuted  int      `json:"variantsExecuted"`
	Blocked           int      `json:"blocked"`
	Detected          int      `json:"detected"`
	Bypassed          int      `json:"bypassed"`
	BypassRate        float64  `json:"bypassRate"`
	HasBypass         bool     `json:"hasBypass"`
	Severity          string   `json:"severity,omitempty"` // Critical|High|Medium|Low
	BestBypassLabel   string   `json:"bestBypassLabel,omitempty"`
	Headline          string   `json:"headline,omitempty"`
	RemediationPoints []string `json:"remediationPoints,omitempty"`
}

// CampaignVariantSection holds trend-focused variant analysis for campaign HTML/PDF
// reports. Sourced from campaign_variant_summary (pre-computed per campaign).
type CampaignVariantSection struct {
	HasData          bool            `json:"hasData"`
	TechniquesTested int             `json:"techniquesTested"`
	VariantsExecuted int             `json:"variantsExecuted"`
	Blocked          int             `json:"blocked"`
	Detected         int             `json:"detected"`
	Bypassed         int             `json:"bypassed"`
	RunCount         int             `json:"runCount"`
	PreventionScore  float64         `json:"preventionScore"`
	DetectionScore   float64         `json:"detectionScore"`
	TopBypasses      []CampTopBypass `json:"topBypasses"`
	TacticBreakdown  []CampTacticRow `json:"tacticBreakdown"`
	HasTrend         bool            `json:"hasTrend"`
	TrendImproved    bool            `json:"trendImproved"`
	PrevBypassed     int             `json:"prevBypassed"`
	ImprovementPct   float64         `json:"improvementPct"`
	TrendDelta       int             `json:"trendDelta"` // positive = regression, negative = improvement
	TrendNote        string          `json:"trendNote"`
}

// CampTopBypass is a technique that bypassed controls in multiple campaign runs.
type CampTopBypass struct {
	TechniqueID      string `json:"techniqueId"`
	TechniqueName    string `json:"techniqueName"`
	Tactic           string `json:"tactic"`
	TimesObserved    int    `json:"timesObserved"`
	MostCommonBypass string `json:"mostCommonBypass"`
}

// CampTacticRow is one ATT&CK tactic in the campaign tactic risk heatmap.
type CampTacticRow struct {
	Tactic         string  `json:"tactic"`
	Tested         int     `json:"tested"`
	Bypassed       int     `json:"bypassed"`
	PreventionRate float64 `json:"preventionRate"`
	RiskLevel      string  `json:"riskLevel"` // High|Medium|Low
}

// ReportScope describes a fleet-wide (campaign) report's subject.
type ReportScope struct {
	Kind       string `json:"kind"`     // "campaign"
	Title      string `json:"title"`    // campaign name
	Subtitle   string `json:"subtitle"` // "Campaign Assessment — <scenario>"
	Scenario   string `json:"scenario"`
	AgentCount int    `json:"agentCount"`
	RunCount   int    `json:"runCount"`
}

// CampaignAgentRow is one endpoint's result inside a campaign's per-agent breakdown.
type CampaignAgentRow struct {
	Hostname        string  `json:"hostname"`
	Status          string  `json:"status"`
	PreventionScore float64 `json:"preventionScore"`
	Tested          int     `json:"tested"`
	Failed          int     `json:"failed"`
}

// DetectionSource represents a security product's performance summary.
type DetectionSource struct {
	Product    string `json:"product"`
	Detections int    `json:"detections"`
	MinMTTDMs  int64  `json:"minMttdMs"` // quickest detection time in ms
	AvgMTTDMs  int64  `json:"avgMttdMs"` // average detection time in ms
}

// DetectionTechnique is one per-technique detection verdict surfaced to the UI.
type DetectionTechnique struct {
	TechniqueID    string `json:"techniqueId"`
	Verdict        string `json:"verdict"`              // prevented|detected|undetected
	Confidence     string `json:"confidence,omitempty"` // high|low when detected
	TimeToDetectMs int64  `json:"timeToDetectMs,omitempty"`
}

// RemediationPlan is structured remediation guidance for a failing technique.
// Priority / Owner / Effort map to the four fields on the report finding card.
type RemediationPlan struct {
	Priority     string `json:"priority"`     // Critical | High | Medium | Low
	Owner        string `json:"owner"`        // team responsible for the fix
	Effort       string `json:"effort"`       // Hours | Days | Weeks
	Verification string `json:"verification"` // how to confirm the fix worked
}

// TechniqueRow is one row in the Detection Validation table — execution verdict
// combined with post-run EDR/alert correlation for the same technique.
type TechniqueRow struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	// StepName is the specific dispatched atomic's own name (e.g. "T1003 -
	// Test 3: LSASS dump via comsvcs.dll MiniDump"), distinguishing rows
	// that share the same TechniqueID/TechniqueName -- routine in a Full
	// Sweep, where one technique commonly has several atomics. Empty for
	// local_check-sourced results, where TechniqueName is already the
	// specific check name (see models.SimulationResult.StepName).
	StepName         string `json:"stepName,omitempty"`
	Tactic           string `json:"tactic"`
	Severity         string `json:"severity"`
	ExecVerdict      string `json:"execVerdict"`                // pass|fail|blocked|error|skipped
	DetectionVerdict string `json:"detectionVerdict,omitempty"` // prevented|detected|undetected
	AlertChannel     string `json:"alertChannel,omitempty"`
	AlertProvider    string `json:"alertProvider,omitempty"`
	AlertEventID     int    `json:"alertEventId,omitempty"`
	AlertThreatName  string `json:"alertThreatName,omitempty"`
	AlertCommandLine string `json:"alertCommandLine,omitempty"`
	Confidence       string `json:"confidence,omitempty"` // high|low
	MTTDMs           int64  `json:"mttdMs,omitempty"`
	DurationMs       int64  `json:"durationMs"`
	CleanupVerdict   string `json:"cleanupVerdict,omitempty"` // reverted|partial|leaked|rescued ("rescued" is set only by buildEnvRestoration, at report-build time — never the raw agent verdict)
	// CleanupResidual mirrors models.SimulationResult.CleanupResidual — see
	// buildEnvRestoration for how it's cross-referenced against reverted[] to
	// produce the "rescued" verdict.
	CleanupResidual []string `json:"cleanupResidual,omitempty"`
	ControlName     string   `json:"controlName,omitempty"`   // specific control that blocked (Defender ASR, AppLocker, WDAC)
	ControlRuleID   string   `json:"controlRuleId,omitempty"` // ASR GUID or AppLocker policy name
	// RequestedPriv is the effective tier sent to the agent (PrivSpec.Effective()).
	// "Legacy" when the step was unannotated.
	RequestedPriv string `json:"requestedPriv"`
	// RequestedPrivMin / RequestedPrivPref carry the full PrivSpec when the step
	// used the richer YAML form {minimum: user, preferred: admin}. Both empty
	// means either a plain scalar annotation or a legacy unannotated step.
	RequestedPrivMin  string `json:"requestedPrivMin,omitempty"`
	RequestedPrivPref string `json:"requestedPrivPref,omitempty"`
	// ExecutedAs is the actual privilege tier used at runtime.
	// "Legacy" when the step was unannotated. "User→Admin" flags a WTS fallback.
	ExecutedAs     string          `json:"executedAs"`
	Details        string          `json:"details,omitempty"`
	Remediation    string          `json:"remediation,omitempty"`
	BusinessImpact string          `json:"businessImpact,omitempty"`
	Command        string          `json:"command,omitempty"`   // human-readable step command from scenario YAML
	Framework      string          `json:"framework,omitempty"` // art | caldera | sigma | custom
	RemPlan        RemediationPlan `json:"remPlan,omitempty"`
}

// CoverageBreakdown is the 3-bucket summary of all technique-level verdicts
// within a report. Every technique that was executed (not errored/skipped) lands
// in exactly one bucket:
//
//	Prevented     — execution was blocked (pass/blocked verdict)
//	DetectedOnly  — execution succeeded but an EDR/SIEM alert fired (fail+detected)
//	Missed        — execution succeeded with no detection (fail+undetected / no telemetry)
//
// Rates are integers 0-100. HasData is false when TechniqueMatrix is empty.
type CoverageBreakdown struct {
	HasData           bool              `json:"hasData"`
	Attempted         int               `json:"attempted"`
	Prevented         int               `json:"prevented"`
	DetectedOnly      int               `json:"detectedOnly"`
	Missed            int               `json:"missed"`
	PreventionRate    int               `json:"preventionRate"`    // prevented/attempted*100
	DetectionCoverage int               `json:"detectionCoverage"` // (prevented+detectedOnly)/attempted*100
	ByTactic          []TacticBreakdown `json:"byTactic"`
	MissedTechniques  []TechniqueRow    `json:"missedTechniques"` // top-20 missed+detectedOnly rows, action items
}

// TacticBreakdown is the per-tactic 3-bucket row for the Coverage Analytics page.
type TacticBreakdown struct {
	Tactic       string `json:"tactic"`
	Attempted    int    `json:"attempted"`
	Prevented    int    `json:"prevented"`
	DetectedOnly int    `json:"detectedOnly"`
	Missed       int    `json:"missed"`
}

// buildCoverageBreakdown derives the 3-bucket coverage summary from TechniqueMatrix.
func buildCoverageBreakdown(matrix []TechniqueRow) CoverageBreakdown {
	if len(matrix) == 0 {
		return CoverageBreakdown{}
	}
	cb := CoverageBreakdown{HasData: true}
	tacMap := map[string]*TacticBreakdown{}
	var gapped []TechniqueRow
	for _, row := range matrix {
		switch row.DetectionVerdict {
		case "prevented", "detected", "undetected":
		default:
			continue // error/skipped — excluded
		}
		cb.Attempted++
		tac := row.Tactic
		if tac == "" {
			tac = "unknown"
		}
		if tacMap[tac] == nil {
			tacMap[tac] = &TacticBreakdown{Tactic: tac}
		}
		t := tacMap[tac]
		t.Attempted++
		switch row.DetectionVerdict {
		case "prevented":
			cb.Prevented++
			t.Prevented++
		case "detected":
			cb.DetectedOnly++
			t.DetectedOnly++
			gapped = append(gapped, row)
		default: // "undetected"
			cb.Missed++
			t.Missed++
			gapped = append(gapped, row)
		}
	}
	if cb.Attempted > 0 {
		cb.PreventionRate = cb.Prevented * 100 / cb.Attempted
		cb.DetectionCoverage = (cb.Prevented + cb.DetectedOnly) * 100 / cb.Attempted
	}
	// sort tactics: most missed first, then alpha.
	for _, t := range tacMap {
		cb.ByTactic = append(cb.ByTactic, *t)
	}
	sort.Slice(cb.ByTactic, func(i, j int) bool {
		if cb.ByTactic[i].Missed != cb.ByTactic[j].Missed {
			return cb.ByTactic[i].Missed > cb.ByTactic[j].Missed
		}
		return cb.ByTactic[i].Tactic < cb.ByTactic[j].Tactic
	})
	// top-20 gapped techniques — missed first, then detectedOnly.
	sort.SliceStable(gapped, func(i, j int) bool {
		// missed > detectedOnly
		mi := gapped[i].DetectionVerdict == "undetected"
		mj := gapped[j].DetectionVerdict == "undetected"
		if mi != mj {
			return mi // missed first
		}
		return gapped[i].TechniqueID < gapped[j].TechniqueID
	})
	if len(gapped) > 20 {
		gapped = gapped[:20]
	}
	cb.MissedTechniques = gapped
	return cb
}

// KillChainStep is one step of the purple-team kill chain: an adversary action
// paired with the defensive outcome. Ordered by ATT&CK kill-chain phase. PASS/
// BLOCKED render as Prevented; FAIL as Detected (an alert fired) or Missed (none).
// ERROR/SKIPPED are excluded — they are not security outcomes.
type KillChainStep struct {
	Phase       string `json:"phase"` // tactic slug (frontend humanizes)
	TechniqueID string `json:"techniqueId"`
	Technique   string `json:"technique"`            // technique name
	Action      string `json:"action"`               // adversary action / intent
	Outcome     string `json:"outcome"`              // prevented | detected | missed
	Detail      string `json:"detail"`               // defensive response text
	Confidence  string `json:"confidence,omitempty"` // high|low for detected
	LatencyMs   int64  `json:"latencyMs,omitempty"`  // time-to-detect for detected
}

// AttackPathStep is one kill-chain phase the endpoint did not prevent, with the
// unprevented technique(s) in that phase.
type AttackPathStep struct {
	Tactic     string   `json:"tactic"`
	Techniques []string `json:"techniques"` // "T1059.001 — PowerShell"
}

// AttackPath is the chain of consecutive kill-chain phases this run's unprevented
// techniques actually form — the executive's-eye view the ART review asked for
// (attackers chain steps; they do not operate one ATT&CK ID at a time). It is
// grounded strictly in observed FAILs ordered by kill-chain phase: the path the
// endpoint's gaps permit, not a hypothetical or inferred causal chain.
type AttackPath struct {
	Steps []AttackPathStep `json:"steps"`
}

// buildAttackPath orders the run's unprevented techniques (FAIL) by kill-chain
// phase into a single realized path. Techniques are de-duplicated per phase;
// PASS/ERROR/SKIPPED never appear (they are not part of an attacker's successful
// chain). Honest by design — no technique→technique causal inference, only the
// observed traversal across phases.
func buildAttackPath(results []models.SimulationResult) AttackPath {
	type acc struct {
		techs []string
		seen  map[string]bool
	}
	m := make(map[string]*acc)
	for _, r := range results {
		if r.Result != models.ResultFail {
			continue
		}
		t := r.Technique.Tactic
		if t == "" {
			continue
		}
		a := m[t]
		if a == nil {
			a = &acc{seen: make(map[string]bool)}
			m[t] = a
		}
		key := r.Technique.ID
		if key == "" {
			key = r.Technique.Name
		}
		if key == "" || a.seen[key] {
			continue
		}
		a.seen[key] = true
		label := strings.TrimSpace(r.Technique.Name)
		switch {
		case r.Technique.ID != "" && label != "":
			label = r.Technique.ID + " — " + label
		case r.Technique.ID != "":
			label = r.Technique.ID
		}
		a.techs = append(a.techs, label)
	}
	var ap AttackPath
	for _, tactic := range tacticOrder {
		a := m[tactic]
		if a == nil || len(a.techs) == 0 {
			continue
		}
		ap.Steps = append(ap.Steps, AttackPathStep{Tactic: tactic, Techniques: a.techs})
	}
	return ap
}

// ── Attack Flow ──────────────────────────────────────────────────────────────

// AttackFlowNode is one technique in the per-run attack flow visualization.
// Ordered by kill-chain tactic phase; control attribution and detection verdict
// are derived from the same evidence pipeline used by the kill-chain builder.
type AttackFlowNode struct {
	Step          int    `json:"step"`
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	// StepName is the specific dispatched atomic's own name -- see
	// TechniqueRow.StepName for why this is separate from TechniqueName.
	StepName    string `json:"stepName,omitempty"`
	Tactic      string `json:"tactic"`
	TacticLabel string `json:"tacticLabel"`
	Severity    string `json:"severity"`
	DurationMs  int64  `json:"durationMs"`

	// Verdict: "blocked" | "detected" | "logged" | "bypassed" | "error" | "skipped"
	Verdict      string `json:"verdict"`
	VerdictLabel string `json:"verdictLabel"`

	// ControlName names the security control responsible for this verdict.
	// Blocked steps: the blocking product/rule. Detected steps: the alerting
	// EDR/AV. Bypassed steps: empty (no control stopped or observed it).
	ControlName     string `json:"controlName"`
	DetectionSource string `json:"detectionSource,omitempty"`
	AlertName       string `json:"alertName,omitempty"`

	IsStopPoint bool `json:"isStopPoint"` // true when the attack was halted here
}

// BuildAttackFlow returns an ordered attack flow for a run's results, one node
// per technique sorted by kill-chain tactic phase then original step order.
// This is the data source for the dashboard drawer "Attack Flow" tab and the
// HTML/PDF report attack flow section.
func BuildAttackFlow(results []models.SimulationResult) []AttackFlowNode {
	tacticIdx := make(map[string]int, len(tacticOrder))
	for i, t := range tacticOrder {
		tacticIdx[t] = i
	}

	nodes := make([]AttackFlowNode, 0, len(results))
	for i, r := range results {
		node := AttackFlowNode{
			Step:          i + 1,
			TechniqueID:   r.Technique.ID,
			TechniqueName: r.Technique.Name,
			StepName:      r.StepName,
			Tactic:        r.Technique.Tactic,
			TacticLabel:   humanizeTactic(r.Technique.Tactic),
			Severity:      r.Severity,
			DurationMs:    r.DurationMs,
		}

		switch r.Result {
		case models.ResultPass:
			node.Verdict = "blocked"
			node.VerdictLabel = "Blocked"
			node.IsStopPoint = true
			if r.BlockingControl != nil && r.BlockingControl.Name != "" {
				node.ControlName = r.BlockingControl.Name
			} else if ctrl := attributeControl(r); ctrl != "" {
				node.ControlName = ctrl
			} else {
				node.ControlName = "Security Control"
			}

		case models.ResultBlocked:
			node.Verdict = "blocked"
			node.VerdictLabel = "Blocked (AV Quarantine)"
			node.IsStopPoint = true
			node.ControlName = "Antivirus / EDR"

		case models.ResultFail:
			det := classifyDetection(r.Events)
			if r.DetectionVerdict == "detected" || r.DetectionAlert != nil {
				node.Verdict = "detected"
				node.VerdictLabel = "Detected — Not Stopped"
				if r.DetectionAlert != nil {
					node.ControlName = r.DetectionAlert.Provider
					node.AlertName = r.DetectionAlert.ThreatName
				} else if det.Detected {
					node.ControlName = det.Source
				}
				node.DetectionSource = det.Source
			} else if det.Status == "Detected" {
				node.Verdict = "detected"
				node.VerdictLabel = "Detected — Not Stopped"
				node.ControlName = det.Source
				node.DetectionSource = det.Source
			} else if det.Status == "Logged" {
				node.Verdict = "logged"
				node.VerdictLabel = "Logged — No Alert Raised"
				node.ControlName = det.Source
				node.DetectionSource = det.Source
			} else {
				node.Verdict = "bypassed"
				node.VerdictLabel = "Bypassed — Undetected"
			}

		case models.ResultError:
			node.Verdict = "error"
			node.VerdictLabel = "Error"
			node.ControlName = "—"

		case models.ResultSkipped:
			node.Verdict = "skipped"
			node.VerdictLabel = "Skipped"
			node.ControlName = "—"

		default:
			node.Verdict = "unknown"
			node.VerdictLabel = string(r.Result)
			node.ControlName = "—"
		}

		nodes = append(nodes, node)
	}

	sort.SliceStable(nodes, func(i, j int) bool {
		ti, iOk := tacticIdx[nodes[i].Tactic]
		tj, jOk := tacticIdx[nodes[j].Tactic]
		if !iOk {
			ti = 999
		}
		if !jOk {
			tj = 999
		}
		if ti != tj {
			return ti < tj
		}
		return nodes[i].Step < nodes[j].Step
	})

	return nodes
}

// AttackFlowSummary holds pre-computed verdict counts for the attack flow.
// Stored alongside AttackFlow in ReportData so templates can avoid counting.
type AttackFlowSummary struct {
	Total    int `json:"total"`
	Blocked  int `json:"blocked"`
	Detected int `json:"detected"`
	Logged   int `json:"logged"`
	Bypassed int `json:"bypassed"`
	Errors   int `json:"errors"`
	Skipped  int `json:"skipped"`
}

func summariseAttackFlow(nodes []AttackFlowNode) AttackFlowSummary {
	s := AttackFlowSummary{Total: len(nodes)}
	for _, n := range nodes {
		switch n.Verdict {
		case "blocked":
			s.Blocked++
		case "detected":
			s.Detected++
		case "logged":
			s.Logged++
		case "bypassed":
			s.Bypassed++
		case "error":
			s.Errors++
		case "skipped":
			s.Skipped++
		}
	}
	return s
}

// buildKillChain fuses the run's per-step verdicts with the detection verdicts
// into the dual-rail timeline (adversary action ↔ defensive outcome), ordered by
// kill-chain phase and, within a phase, by execution time. PASS/BLOCKED →
// "prevented"; FAIL → "detected" when an alert fired (the agent's detection sweep
// first, falling back to the coarse per-step events), else "missed". ERROR/SKIPPED
// and tactic-less steps are excluded. Honest: no detected verdict without evidence.
// detTechIndex builds a TechniqueID -> DetectionTechnique lookup, built once
// and shared across every result classification in a report (avoids
// rebuilding this map per-result).
func detTechIndex(dets []DetectionTechnique) map[string]DetectionTechnique {
	idx := make(map[string]DetectionTechnique, len(dets))
	for _, d := range dets {
		if d.TechniqueID != "" {
			idx[d.TechniqueID] = d
		}
	}
	return idx
}

// classifyOutcome classifies one result's security outcome: "blocked" (a
// control prevented it), "detected" (ran, but an alert fired), "missed"
// (ran, no detection — the blind spot), or "excluded" (ERROR/SKIPPED — an
// execution problem, not a security outcome). Shared by buildKillChain and
// the sweep technique/encoding rollups (buildSweepTechniqueBreakdown,
// buildSweepEncodingBreakdown) so there is one source of truth for this
// classification instead of copies that can drift apart.
func classifyOutcome(r models.SimulationResult, detByTech map[string]DetectionTechnique) string {
	if r.Result == models.ResultError || r.Result == models.ResultSkipped {
		return "excluded"
	}
	if r.Result == models.ResultPass || r.Result == models.ResultBlocked {
		return "blocked"
	}
	if d, ok := detByTech[r.Technique.ID]; ok && d.Verdict == "detected" {
		return "detected"
	}
	if cd := classifyDetection(r.Events); cd.Status == "Detected" {
		return "detected"
	}
	return "missed"
}

func buildKillChain(results []models.SimulationResult, dets []DetectionTechnique) []KillChainStep {
	detByTech := detTechIndex(dets)
	byTactic := make(map[string][]models.SimulationResult)
	for _, r := range results {
		if classifyOutcome(r, detByTech) == "excluded" {
			continue
		}
		if r.Technique.Tactic == "" {
			continue
		}
		byTactic[r.Technique.Tactic] = append(byTactic[r.Technique.Tactic], r)
	}
	var out []KillChainStep
	for _, tactic := range tacticOrder {
		rs := byTactic[tactic]
		if len(rs) == 0 {
			continue
		}
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].ExecutedAt.Before(rs[j].ExecutedAt) })
		for _, r := range rs {
			step := KillChainStep{
				Phase: tactic, TechniqueID: r.Technique.ID,
				Technique: r.Technique.Name, Action: killChainAction(r),
			}
			switch classifyOutcome(r, detByTech) {
			case "blocked":
				step.Outcome = "prevented"
				if ctrl := attributeControl(r); ctrl != "" {
					step.Detail = "Blocked by " + ctrl
				} else {
					step.Detail = "Prevented by a control"
				}
			case "detected":
				step.Outcome = "detected"
				if d, ok := detByTech[r.Technique.ID]; ok && d.Verdict == "detected" {
					step.Confidence = d.Confidence
					step.LatencyMs = d.TimeToDetectMs
					step.Detail = "Detection alert raised"
				} else {
					step.Detail = classifyDetection(r.Events).Detail
				}
			default: // "missed"
				step.Outcome = "missed"
				step.Detail = "No detection — executed unseen"
			}
			out = append(out, step)
		}
	}
	return out
}

// privLabel normalises a raw ExecutedAs/RequestedPriv value to a report-friendly
// label. Empty (unannotated legacy step) becomes "Legacy"; the value is otherwise
// title-cased so "user→admin" stays readable and "admin" becomes "Admin".
func privLabel(raw string) string {
	if raw == "" {
		return "Legacy"
	}
	// Title-case the first word; preserve the "→" fallback arrow as-is.
	if len(raw) == 0 {
		return raw
	}
	return strings.ToUpper(raw[:1]) + raw[1:]
}

// buildTechniqueMatrix combines each step's execution verdict with its post-run
// EDR/alert detection verdict into a single flat row for the Detection Validation
// table. DetectionVerdict in results (written by SubmitRunDetections) is preferred;
// the DetectionTechnique slice (from detection_summary) is the fallback.
func buildTechniqueMatrix(results []models.SimulationResult, dets []DetectionTechnique) []TechniqueRow {
	detIdx := make(map[string]DetectionTechnique, len(dets))
	for _, d := range dets {
		detIdx[d.TechniqueID] = d
	}
	rows := make([]TechniqueRow, 0, len(results))
	for _, r := range results {
		row := TechniqueRow{
			TechniqueID:       r.Technique.ID,
			TechniqueName:     r.Technique.Name,
			StepName:          r.StepName,
			Tactic:            r.Technique.Tactic,
			Severity:          r.Severity,
			ExecVerdict:       string(r.Result),
			DurationMs:        r.DurationMs,
			CleanupVerdict:    r.CleanupVerdict,
			CleanupResidual:   r.CleanupResidual,
			RequestedPriv:     privLabel(r.RequestedPriv),
			RequestedPrivMin:  privLabel(r.RequestedPrivMin),
			RequestedPrivPref: privLabel(r.RequestedPrivPref),
			ExecutedAs:        privLabel(r.ExecutedAs),
			Details:           r.Details,
			Remediation:       r.Remediation,
			BusinessImpact:    tacticBusinessImpact(r.Technique.Tactic, r.Technique.ID),
			Command:           r.Command,
			Framework:         r.Framework,
			RemPlan:           remediationPlan(r.Technique.Tactic, r.Technique.ID, r.Severity),
		}
		if r.BlockingControl != nil {
			row.ControlName = r.BlockingControl.Name
			row.ControlRuleID = r.BlockingControl.RuleID
		}
		if row.ControlName == "" && (r.Result == models.ResultPass || r.Result == models.ResultBlocked) {
			row.ControlName = attributeControl(r)
		}
		if r.DetectionVerdict != "" {
			row.DetectionVerdict = r.DetectionVerdict
			if r.DetectionAlert != nil {
				row.AlertChannel = r.DetectionAlert.Channel
				row.AlertProvider = r.DetectionAlert.Provider
				row.AlertEventID = r.DetectionAlert.EventID
				row.AlertThreatName = r.DetectionAlert.ThreatName
				row.AlertCommandLine = truncateStr(r.DetectionAlert.CommandLine, 80)
				row.Confidence = r.DetectionAlert.Confidence
				row.MTTDMs = r.DetectionAlert.MTTDMs
			}
		} else if d, ok := detIdx[r.Technique.ID]; ok {
			row.DetectionVerdict = d.Verdict
			row.Confidence = d.Confidence
			row.MTTDMs = d.TimeToDetectMs
		}
		rows = append(rows, row)
	}
	return rows
}

// buildPrivilegeSummary counts steps by execution context from a TechniqueMatrix
// and computes per-tier prevention counts and rates.
func buildPrivilegeSummary(matrix []TechniqueRow) PrivilegeSummary {
	var ps PrivilegeSummary
	prevented := func(execVerdict string) bool {
		return execVerdict == "pass" || execVerdict == "blocked"
	}
	for _, r := range matrix {
		p := prevented(r.ExecVerdict)
		switch r.ExecutedAs {
		case "Legacy":
			ps.Legacy++
			if p {
				ps.LegacyPrevented++
			}
		case "System":
			ps.System++
			if p {
				ps.SystemPrevented++
			}
		case "Admin":
			ps.Admin++
			if p {
				ps.AdminPrevented++
			}
		default:
			if strings.Contains(r.ExecutedAs, "→") {
				ps.Fallbacks++
				ps.Admin++ // fell back to admin
				if p {
					ps.AdminPrevented++
				}
			} else {
				ps.User++
				if p {
					ps.UserPrevented++
				}
			}
		}
	}
	if ps.User > 0 {
		ps.UserRate = ps.UserPrevented * 100 / ps.User
	}
	if ps.Admin > 0 {
		ps.AdminRate = ps.AdminPrevented * 100 / ps.Admin
	}
	if ps.System > 0 {
		ps.SystemRate = ps.SystemPrevented * 100 / ps.System
	}
	if ps.Legacy > 0 {
		ps.LegacyRate = ps.LegacyPrevented * 100 / ps.Legacy
	}
	return ps
}

// SkipBreakdown counts Result=Skipped entries by SkipReason.
type SkipBreakdown struct {
	Policy   int `json:"policy"`
	Content  int `json:"content"`
	Platform int `json:"platform"`
}

// buildSkipBreakdown counts skipped results by SkipReason. An empty or
// unrecognized reason falls into Platform — an unclassified skip is still an
// environment gap, not a policy decision.
func buildSkipBreakdown(results []models.SimulationResult) SkipBreakdown {
	var sb SkipBreakdown
	for _, r := range results {
		if r.Result != models.ResultSkipped {
			continue
		}
		switch r.SkipReason {
		case models.SkipReasonPolicyPrivilege:
			sb.Policy++
		case models.SkipReasonMissingContent:
			sb.Content++
		default:
			sb.Platform++
		}
	}
	return sb
}

// CoverageSummary reports how much of a scenario's base-technique steps were
// attemptable (Eligible) and defined (ScenarioTotal), against how many
// actually executed. Separate from SkipBreakdown's "why" and separate from
// PASS/FAIL scoring — this is a completeness metric, not a security score.
type CoverageSummary struct {
	ScenarioTotal int `json:"scenarioTotal"`
	Eligible      int `json:"eligible"`
	Executed      int `json:"executed"`
	// ScenarioCoveragePct = Executed/ScenarioTotal*100 (0 when ScenarioTotal==0).
	ScenarioCoveragePct int `json:"scenarioCoveragePct"`
	// EligibleCoveragePct = Executed/Eligible*100 (0 when Eligible==0).
	EligibleCoveragePct int `json:"eligibleCoveragePct"`
}

// buildCoverageSummary derives Executed from results — distinct base
// techniques (by Technique.ID, the same key groupResultsByTechnique uses)
// with at least one non-policy-skip result — and combines it with the
// dispatch-time-captured totalBase/eligibleBase counts into both coverage
// ratios. A policy-skipped technique was never dispatched to the agent at
// all, so it must not count as executed. A zero denominator means coverage
// data isn't available for this run (e.g. it predates this feature) — 0%,
// not an error.
func buildCoverageSummary(results []models.SimulationResult, totalBase, eligibleBase int) CoverageSummary {
	executable := make([]models.SimulationResult, 0, len(results))
	for _, r := range results {
		if r.SkipReason == models.SkipReasonPolicyPrivilege {
			continue
		}
		executable = append(executable, r)
	}
	executed := len(groupResultsByTechnique(executable))
	cs := CoverageSummary{ScenarioTotal: totalBase, Eligible: eligibleBase, Executed: executed}
	if totalBase > 0 {
		cs.ScenarioCoveragePct = executed * 100 / totalBase
	}
	if eligibleBase > 0 {
		cs.EligibleCoveragePct = executed * 100 / eligibleBase
	}
	return cs
}

// killChainAction renders a concise adversary-action label for a kill-chain node.
func killChainAction(r models.SimulationResult) string {
	for _, s := range []string{r.ThreatImpact, r.Details} {
		if s = strings.TrimSpace(s); s != "" {
			return truncateStr(s, 110)
		}
	}
	if r.Technique.Name != "" {
		return "Executed " + r.Technique.Name
	}
	return "Technique executed"
}

func truncateStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// TrendPoint is one scored assessment in the endpoint's history, for the trend
// sparkline (oldest → newest).
type TrendPoint struct {
	RunID           string    `json:"runId"`
	Date            time.Time `json:"date"`
	PreventionScore float64   `json:"preventionScore"`
	RiskScore       int       `json:"riskScore"`
}

// TrendSummary answers "are we improving?" — the question a BAS is bought to
// answer. It compares the current run's prevention effectiveness to the previous
// scored assessment for the same endpoint and carries a short history for a
// sparkline. A snapshot becomes a programme metric.
type TrendSummary struct {
	HasPrevious        bool         `json:"hasPrevious"`
	CurrentPrevention  float64      `json:"currentPrevention"`
	PreviousPrevention float64      `json:"previousPrevention"`
	DeltaPrevention    float64      `json:"deltaPrevention"` // current − previous (pts)
	CurrentRisk        int          `json:"currentRisk"`
	PreviousRisk       int          `json:"previousRisk"`
	History            []TrendPoint `json:"history"` // oldest → newest, ≤6 points
}

// buildTrendSummary derives the prevention trend from the endpoint's run history.
// Only scored runs (completed/partial) count; the newest is "current", the next
// is "previous". History is capped to the most recent few, oldest-first for
// display. With fewer than two scored runs the trend is simply marked absent —
// we never invent a baseline.
func buildTrendSummary(runs []RunSummary) TrendSummary {
	var scored []RunSummary
	for _, r := range runs {
		if r.Status == "completed" || r.Status == "partial" {
			scored = append(scored, r)
		}
	}
	var t TrendSummary
	if len(scored) == 0 {
		return t
	}
	cur := scored[0]
	t.CurrentPrevention = cur.PreventionScore
	t.CurrentRisk = cur.RiskScore

	const maxPts = 6
	pts := scored
	if len(pts) > maxPts {
		pts = pts[:maxPts]
	}
	for i := len(pts) - 1; i >= 0; i-- {
		t.History = append(t.History, TrendPoint{
			RunID: pts[i].ID, Date: pts[i].StartedAt,
			PreventionScore: pts[i].PreventionScore, RiskScore: pts[i].RiskScore,
		})
	}
	if len(scored) >= 2 {
		prev := scored[1]
		t.HasPrevious = true
		t.PreviousPrevention = prev.PreventionScore
		t.DeltaPrevention = cur.PreventionScore - prev.PreventionScore
		t.PreviousRisk = prev.RiskScore
	}
	return t
}

// ObjectiveRisk expresses the run's outcome in business terms an executive cares
// about ("Can credentials be stolen?") rather than raw percentages. Derived from
// the per-tactic pass/fail of the run; ERROR/SKIPPED are excluded.
type ObjectiveRisk struct {
	Objective string `json:"objective"`
	Tactic    string `json:"tactic"`
	Risk      string `json:"risk"` // High | Medium | Low
	Tested    int    `json:"tested"`
	Failed    int    `json:"failed"`
}

// objectiveByTactic maps an ATT&CK tactic to the business objective an attacker
// achieves with it, in the order executives read risk.
var objectiveByTactic = []struct{ tactic, objective string }{
	{"credential-access", "Credential Theft"},
	{"privilege-escalation", "Privilege Escalation"},
	{"persistence", "Persistence"},
	{"lateral-movement", "Lateral Movement"},
	{"command-and-control", "Command & Control"},
	{"exfiltration", "Data Exfiltration"},
	{"impact", "Ransomware / Impact"},
	{"defense-evasion", "Defense Evasion"},
	{"execution", "Code Execution"},
	{"discovery", "Discovery"},
}

// buildObjectiveRisks rolls per-tactic results up to a business-objective risk
// band: High when most tested techniques in the objective went unprevented,
// Medium when some did, Low when all were blocked. Objectives with no executed
// techniques are omitted (we do not assert risk for untested objectives).
func buildObjectiveRisks(results []models.SimulationResult) []ObjectiveRisk {
	type agg struct{ tested, failed int }
	m := make(map[string]*agg)
	for _, r := range results {
		if r.Result == models.ResultError || r.Result == models.ResultSkipped {
			continue
		}
		a := m[r.Technique.Tactic]
		if a == nil {
			a = &agg{}
			m[r.Technique.Tactic] = a
		}
		a.tested++
		if r.Result == models.ResultFail {
			a.failed++
		}
	}
	var out []ObjectiveRisk
	for _, o := range objectiveByTactic {
		a := m[o.tactic]
		if a == nil || a.tested == 0 {
			continue
		}
		risk := "Low"
		switch {
		case a.failed == 0:
			risk = "Low"
		case a.failed*100/a.tested >= 50:
			risk = "High"
		default:
			risk = "Medium"
		}
		out = append(out, ObjectiveRisk{
			Objective: o.objective, Tactic: o.tactic, Risk: risk,
			Tested: a.tested, Failed: a.failed,
		})
	}
	return out
}

// ExecutiveSummary is the top-level risk picture derived from the latest run.
type ExecutiveSummary struct {
	RiskScore          int                      `json:"riskScore"`
	Classification     string                   `json:"classification"`
	PreventionScore    float64                  `json:"preventionScore"`
	ExposureScore      float64                  `json:"exposureScore"`
	CoverageScore      float64                  `json:"coverageScore"`     // defense rate — tactics fully blocked
	KillChainCoverage  float64                  `json:"killChainCoverage"` // breadth — % of 14 ATT&CK tactics exercised
	KillChainAmplifier float64                  `json:"killChainAmplifier"`
	Trend              string                   `json:"trend"`
	TotalRuns          int                      `json:"totalRuns"`
	TotalTechniques    int                      `json:"totalTechniques"`
	PassedTechniques   int                      `json:"passedTechniques"`
	FailedTechniques   int                      `json:"failedTechniques"`
	ErroredTechniques  int                      `json:"erroredTechniques"` // BAS could not execute — excluded from scoring
	SkippedTechniques  int                      `json:"skippedTechniques"` // intentionally not run — excluded from scoring
	LastRunAt          time.Time                `json:"lastRunAt"`
	LastScenarioName   string                   `json:"lastScenarioName"`
	CriticalFailures   []models.CriticalFailure `json:"criticalFailures"`
	Recommendations    []string                 `json:"recommendations"`
	DetectionRate      int                      `json:"detectionRate"`  // detected ÷ executed-not-prevented
	UndetectedRate     int                      `json:"undetectedRate"` // blind spots — succeeded with no alert
	MTTDMs             int64                    `json:"mttdMs"`         // mean time-to-detect across detected techniques
	// Executive framing (Cymulate-style).
	ExposureLevel     string  `json:"exposureLevel"`     // Low | Medium | High | Critical (from prevention)
	DetectionScore    float64 `json:"detectionScore"`    // detected ÷ executed-unprevented, %
	DetectionMeasured bool    `json:"detectionMeasured"` // false ⇒ no telemetry ⇒ render N/A
	PenetrationTested int     `json:"penetrationTested"` // executed (PASS+FAIL)
	PenetrationFailed int     `json:"penetrationFailed"` // penetrated (FAIL)
	PenetrationPct    int     `json:"penetrationPct"`    // failed ÷ tested
	// Attack path (4th score pillar — nil when no collection has run).
	AttackPathScore *int   `json:"attackPathScore,omitempty"`
	AttackPathBand  string `json:"attackPathBand,omitempty"` // Critical | High | Medium | Low
}

// TacticEntry is one row of the ATT&CK tactic heatmap.
type TacticEntry struct {
	Tactic      string `json:"tactic"`
	Passed      int    `json:"passed"`
	Failed      int    `json:"failed"`
	Total       int    `json:"total"` // Coverage — techniques tested in this tactic
	PassPct     int    `json:"passPct"`
	Detected    int    `json:"detected"`    // of the FAILs, how many raised a detection alert
	DetectedPct int    `json:"detectedPct"` // detected ÷ failed
	MTTDMs      int64  `json:"mttdMs"`      // mean time-to-detect (per-run only; 0 when unavailable)
	Weight      string `json:"weight"`      // Critical | High | Medium | Low
}

// Finding is a single Critical or High severity failure surfaced in the report.
type Finding struct {
	TechniqueID      string          `json:"techniqueId"`
	TechniqueName    string          `json:"techniqueName"`
	Tactic           string          `json:"tactic"`
	Severity         string          `json:"severity"`
	Details          string          `json:"details"`
	Remediation      string          `json:"remediation"`
	ScenarioName     string          `json:"scenarioName"`
	BusinessImpact   string          `json:"businessImpact,omitempty"`
	ExecVerdict      string          `json:"execVerdict,omitempty"`
	ExecutedAs       string          `json:"executedAs,omitempty"`
	RequestedPriv    string          `json:"requestedPriv,omitempty"`
	DetectionVerdict string          `json:"detectionVerdict,omitempty"`
	CleanupVerdict   string          `json:"cleanupVerdict,omitempty"`
	DurationMs       int64           `json:"durationMs,omitempty"`
	Command          string          `json:"command,omitempty"`
	Framework        string          `json:"framework,omitempty"`
	RemPlan          RemediationPlan `json:"remPlan,omitempty"`
	KEV              bool            `json:"kev"`      // technique has ≥1 active CISA KEV CVE
	KEVCount         int             `json:"kevCount"` // number of KEV CVEs linked
}

// RunSummary is one row in the Scenario Run History table.
type RunSummary struct {
	ID               string     `json:"id"`
	ScenarioName     string     `json:"scenarioName"`
	Status           string     `json:"status"`
	StartedAt        time.Time  `json:"startedAt"`
	CompletedAt      *time.Time `json:"completedAt,omitempty"`
	RiskScore        int        `json:"riskScore"`
	Classification   string     `json:"classification"`
	PreventionScore  float64    `json:"preventionScore"`
	ExposureScore    float64    `json:"exposureScore"`
	TotalTechniques  int        `json:"totalTechniques"`
	FailedTechniques int        `json:"failedTechniques"`
}

// Category is one detection category from the agent's posture report.
type Category struct {
	Name   string `json:"name"`
	Result string `json:"result"` // pass | fail | unknown
}

// ── Builder ───────────────────────────────────────────────────────────────────

// Build constructs a FullReport for the given agent from current DB state.
func (e *Engine) Build(ctx context.Context, agentID string, filter string) (*FullReport, error) {
	report := &FullReport{GeneratedAt: time.Now().UTC()}

	// ── 1. Agent metadata ─────────────────────────────────────────────────
	row := e.db.QueryRow(ctx,
		`SELECT agent_id, hostname, ip_address, os_version, username,
		        status, env_label, has_report, binary_hash, binary_trusted, last_update,
		        security_products
		 FROM agents WHERE agent_id = $1`, agentID)
	var agentSecProducts []byte
	if err := row.Scan(
		&report.Agent.AgentID, &report.Agent.Hostname, &report.Agent.IPAddress,
		&report.Agent.OSVersion, &report.Agent.Username, &report.Agent.Status,
		&report.Agent.EnvLabel, &report.Agent.HasReport,
		&report.Agent.BinaryHash, &report.Agent.BinaryTrusted, &report.Agent.LastUpdate,
		&agentSecProducts,
	); err != nil {
		report.Agent.AgentID = agentID
	}
	json.Unmarshal(agentSecProducts, &report.SecurityTools)

	// ── 2. Scenario run history (last 20) ─────────────────────────────────
	rows, err := e.db.Query(ctx,
		`SELECT id, name, status, score, started_at, completed_at
		 FROM scenario_runs
		 WHERE agent_id = $1
		 ORDER BY started_at DESC
		 LIMIT 20`, agentID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var rs RunSummary
			var scoreRaw []byte
			rows.Scan(&rs.ID, &rs.ScenarioName, &rs.Status, &scoreRaw, &rs.StartedAt, &rs.CompletedAt)
			if len(scoreRaw) > 0 {
				var sc models.Score
				if json.Unmarshal(scoreRaw, &sc) == nil {
					rs.RiskScore = sc.RiskScore
					rs.Classification = sc.Classification
					rs.PreventionScore = sc.PreventionScore
					rs.ExposureScore = sc.ExposureScore
					rs.TotalTechniques = sc.TotalTechniques
					rs.FailedTechniques = sc.FailedTechniques
				}
			}
			report.Runs = append(report.Runs, rs)
		}
	}

	// ── 3. Latest completed run — for detailed analysis ────────────────────
	var latestResults []models.SimulationResult
	var latestScenarioName string
	var latestRunAt time.Time
	var latestScore models.Score

	latestRow := e.db.QueryRow(ctx,
		`SELECT name, results, score, started_at, reverted, steps_total_base, steps_eligible_base
		 FROM scenario_runs
		 WHERE agent_id = $1 AND status IN ('completed','partial')
		 ORDER BY started_at DESC LIMIT 1`, agentID)
	var resultsRaw, scoreRaw2, revertedRaw []byte
	if err := latestRow.Scan(&latestScenarioName, &resultsRaw, &scoreRaw2, &latestRunAt, &revertedRaw,
		&report.StepsTotalBase, &report.StepsEligibleBase); err == nil {
		json.Unmarshal(resultsRaw, &latestResults)
		json.Unmarshal(scoreRaw2, &latestScore)
		json.Unmarshal(revertedRaw, &report.Reverted)
		if filter != "" && filter != "all" {
			report.ActiveFilter = filter
			report.FilterTotalCount = len(latestResults)
		}
		latestResults = FilterResults(latestResults, filter)
		if filter != "" && filter != "all" {
			report.FilterMatchCount = len(latestResults)
		}
	}

	// ── 4. Tactic heatmap from latest run ────────────────────────────────
	report.ScenarioName = latestScenarioName
	report.TacticHeatmap = buildTacticHeatmap(latestResults)

	// ── 5. Top findings (Critical + High failures) from latest run ────────
	report.TopFindings = buildTopFindings(latestResults, latestScenarioName)
	report.ObjectiveRisks = buildObjectiveRisks(latestResults)
	report.Detection = buildDetectionSummary(latestResults)
	report.TrendAnalysis = buildTrendSummary(report.Runs)
	report.AttackPath = buildAttackPath(latestResults)
	report.AttackFlow = BuildAttackFlow(latestResults)
	report.AttackFlowSummary = summariseAttackFlow(report.AttackFlow)
	// Coverage breakdown: derive from results directly (no detection telemetry in Build()
	// because the latest-run query omits detection_summary; we use exec verdict only).
	report.TechniqueMatrix = buildTechniqueMatrix(latestResults, nil)
	report.CoverageBreakdown = buildCoverageBreakdown(report.TechniqueMatrix)
	report.PrivilegeSummary = buildPrivilegeSummary(report.TechniqueMatrix)
	for _, r := range report.TechniqueMatrix {
		if r.CleanupVerdict == "partial" || r.CleanupVerdict == "leaked" {
			report.CleanupFailed = true
			report.CleanupFailedCount++
		}
	}

	// ── 6. Executive summary ─────────────────────────────────────────────
	report.Summary = ExecutiveSummary{
		RiskScore:          latestScore.RiskScore,
		Classification:     latestScore.Classification,
		PreventionScore:    latestScore.PreventionScore,
		ExposureScore:      latestScore.ExposureScore,
		CoverageScore:      latestScore.CoverageScore,
		KillChainCoverage:  latestScore.KillChainCoverage,
		KillChainAmplifier: latestScore.KillChainAmplifier,
		Trend:              latestScore.Trend,
		TotalRuns:          len(report.Runs),
		TotalTechniques:    latestScore.TotalTechniques,
		PassedTechniques:   latestScore.PassedTechniques,
		FailedTechniques:   latestScore.FailedTechniques,
		ErroredTechniques:  latestScore.ErroredTechniques,
		SkippedTechniques:  latestScore.SkippedTechniques,
		LastRunAt:          latestRunAt,
		LastScenarioName:   latestScenarioName,
		CriticalFailures:   latestScore.CriticalFailures,
		Recommendations:    buildRecommendations(latestScore, report.TacticHeatmap),
	}
	if report.Summary.Classification == "" {
		report.Summary.Classification = "No Data"
	}

	// ── 7. Detection coverage by tactic (re-derived from live run results) ─
	// The legacy agent-submitted posture report (/api/report → reports table)
	// is no longer fed by the agent — it posts only to /api/scenarios/result.
	// Derive per-tactic verdicts from the latest run instead. SecurityTools has
	// no live source, so it is intentionally left empty.
	report.DetectionCategories = buildDetectionCategories(latestResults)

	// ── 8. Executive-grade derivations (exposure, insights, action plan, …) ─
	deriveExecutive(report, latestResults, nil)

	if g, s := e.loadAttackPathGraph(ctx); g != nil {
		report.AttackPathValidation = &s
		report.PathCorrelation = e.loadPathCorrelation(ctx, g, s)
	}
	applyAttackPathToSummary(&report.Summary, report.AttackPathValidation)

	e.populateAttackSurfaceAge(ctx, report, agentID)

	var cpuBefore, cpuAfter, ramBefore, ramAfter, diskBefore, diskAfter float64
	e.db.QueryRow(ctx,
		`SELECT perf_cpu_before, perf_cpu_after, perf_ram_before, perf_ram_after, perf_disk_before, perf_disk_after
		 FROM scenario_runs WHERE agent_id = $1 AND status IN ('completed','partial') AND completed_at IS NOT NULL
		 ORDER BY completed_at DESC LIMIT 1`, agentID,
	).Scan(&cpuBefore, &cpuAfter, &ramBefore, &ramAfter, &diskBefore, &diskAfter)

	report.PerfCPUBefore = cpuBefore
	report.PerfCPUAfter = cpuAfter
	report.PerfRAMBefore = ramBefore
	report.PerfRAMAfter = ramAfter
	report.PerfDiskBefore = diskBefore
	report.PerfDiskAfter = diskAfter

	var latestDetSum []byte
	e.db.QueryRow(ctx,
		`SELECT detection_summary FROM scenario_runs
		 WHERE agent_id = $1 AND status IN ('completed','partial') AND completed_at IS NOT NULL
		 ORDER BY completed_at DESC LIMIT 1`, agentID,
	).Scan(&latestDetSum)
	report.DetectionSources = buildDetectionSourcesFromSummary(latestDetSum)

	er := buildEnvRestoration(report.TechniqueMatrix, report.Reverted)
	if er.HasData {
		er.RunCount = 1
		if er.StepsLeaked == 0 {
			er.RunsClean = 1
		} else {
			er.RunsWithIssues = 1
		}
		report.EnvRestoration = &er
	}
	report.ReadinessScores = buildReadinessScores(report.TechniqueMatrix)
	report.RansomwareReadiness = buildRansomwareReadiness(report.TechniqueMatrix)
	e.enrichReadinessTrends(ctx, report.Agent.AgentID, report.ReadinessScores, "")
	e.enrichReadinessTrends(ctx, report.Agent.AgentID, report.RansomwareReadiness, "")
	e.populateKEVExposure(ctx, report)
	e.populatePriorityScores(ctx, report)

	return report, nil
}

// loadAttackPathGraph builds the fleet attack-path graph from every agent's
// stored collection and analyzes it, returning both the graph and its
// Summary. Returns (nil, zero Summary) when no collection exists yet (the
// report then renders the "not yet collected" state) and never fails a
// report on a DB error. Attack paths are inherently fleet-wide — lateral
// movement spans hosts — so the same graph attaches to per-agent, per-run,
// and campaign reports alike. The graph (not just the Summary) is exposed
// because loadPathCorrelation (SP3) needs to run further graph queries
// beyond what Summary already computed.
func (e *Engine) loadAttackPathGraph(ctx context.Context) (*attackpath.Graph, attackpath.Summary) {
	rows, err := e.db.Query(ctx, `SELECT payload FROM attackpath_collections`)
	if err != nil {
		return nil, attackpath.Summary{}
	}
	defer rows.Close()
	var cols []attackpath.Collection
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		var c attackpath.Collection
		if json.Unmarshal(raw, &c) == nil {
			cols = append(cols, c)
		}
	}
	if len(cols) == 0 {
		return nil, attackpath.Summary{}
	}
	return attackpath.BuildGraphAndAnalyze(cols, e.loadAssetTags(ctx))
}

// loadPathCorrelation runs the SP3 correlation engine against an
// already-built graph/summary. Returns nil when g is nil (nothing collected)
// or when the Rule Library resolver was never wired — same nil-safe
// convention as every other optional report section. Errors are logged, not
// propagated: a correlation failure must never fail the whole report.
func (e *Engine) loadPathCorrelation(ctx context.Context, g *attackpath.Graph, s attackpath.Summary) *pathcorrelation.AttackPathCorrelation {
	if g == nil || e.rules == nil {
		return nil
	}
	// e.rules is a RuleLibraryResolver interface value already — passing it
	// straight into pathcorrelation.Correlate's RuleLibrary parameter is
	// safe here (no typed-nil risk, unlike the *rulelib.Engine call site in
	// the API handler) because e.rules is only ever set via WithRuleLibrary
	// with a genuinely non-nil argument, and the g==nil / e.rules==nil check
	// above already guards the nil case explicitly.
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(
		ctx, g, s, paths,
		pathcorrelation.DefaultEdgeTechniqueMapper{},
		pathcorrelation.NewSQLRunLookup(e.db),
		e.rules,
	)
	if err != nil {
		log.Printf("warn: pathcorrelation.Correlate: %v", err)
		return nil
	}
	return &corr
}

// loadAssetTags reads operator-supplied host tags (crown jewel / segment /
// tier-0) so the report's attack-path section reflects them. Best-effort.
func (e *Engine) loadAssetTags(ctx context.Context) []attackpath.AssetTag {
	rows, err := e.db.Query(ctx,
		`SELECT host_key, label, crown_jewel, segment, high_value FROM attackpath_asset_tags`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var tags []attackpath.AssetTag
	for rows.Next() {
		var t attackpath.AssetTag
		if rows.Scan(&t.HostKey, &t.Label, &t.CrownJewel, &t.Segment, &t.HighValue) == nil {
			tags = append(tags, t)
		}
	}
	return tags
}

// BuildFromRun constructs a FullReport scoped to a single scenario run.
// Useful for per-run export and HTML report without needing the full agent history.
func (e *Engine) BuildFromRun(ctx context.Context, runID string, filter string) (*FullReport, error) {
	report := &FullReport{GeneratedAt: time.Now().UTC()}

	var agentID, scenarioID, scenarioName, status string
	var resultsRaw, scoreRaw []byte
	var startedAt time.Time
	var completedAt *time.Time

	var revertedRaw, detSummaryRaw []byte
	var detRate, undetRate *int
	var mttd *int64
	var cpuBefore, cpuAfter, ramBefore, ramAfter, diskBefore, diskAfter float64
	err := e.db.QueryRow(ctx,
		`SELECT agent_id, scenario_id, name, status, results, score, started_at, completed_at, reverted,
		        detection_rate, undetected_rate, mttd_ms, detection_summary,
		        perf_cpu_before, perf_cpu_after, perf_ram_before, perf_ram_after, perf_disk_before, perf_disk_after,
		        alerts_total, alerts_high_fidelity, noise_score, steps_total_base, steps_eligible_base
		 FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&agentID, &scenarioID, &scenarioName, &status, &resultsRaw, &scoreRaw, &startedAt, &completedAt, &revertedRaw,
		&detRate, &undetRate, &mttd, &detSummaryRaw,
		&cpuBefore, &cpuAfter, &ramBefore, &ramAfter, &diskBefore, &diskAfter,
		&report.AlertsTotal, &report.AlertsHighFidelity, &report.NoiseScore,
		&report.StepsTotalBase, &report.StepsEligibleBase)
	if err != nil {
		return nil, fmt.Errorf("run %s not found: %w", runID, err)
	}
	report.PerfCPUBefore = cpuBefore
	report.PerfCPUAfter = cpuAfter
	report.PerfRAMBefore = ramBefore
	report.PerfRAMAfter = ramAfter
	report.PerfDiskBefore = diskBefore
	report.PerfDiskAfter = diskAfter
	if len(detSummaryRaw) > 0 {
		var ds struct {
			Techniques []DetectionTechnique `json:"techniques"`
		}
		if json.Unmarshal(detSummaryRaw, &ds) == nil {
			report.DetectionTechniques = ds.Techniques
		}
	}
	report.DetectionSources = buildDetectionSourcesFromSummary(detSummaryRaw)

	var results []models.SimulationResult
	var score models.Score
	json.Unmarshal(resultsRaw, &results)
	json.Unmarshal(scoreRaw, &score)
	json.Unmarshal(revertedRaw, &report.Reverted)
	if filter != "" && filter != "all" {
		report.ActiveFilter = filter
		report.FilterTotalCount = len(results)
	}
	results = FilterResults(results, filter)
	if filter != "" && filter != "all" {
		report.FilterMatchCount = len(results)
		var filteredDet []DetectionTechnique
		for _, dt := range report.DetectionTechniques {
			found := false
			for _, r := range results {
				if r.Technique.ID == dt.TechniqueID {
					found = true
					break
				}
			}
			if found {
				filteredDet = append(filteredDet, dt)
			}
		}
		report.DetectionTechniques = filteredDet
	}

	// Agent metadata
	row := e.db.QueryRow(ctx,
		`SELECT agent_id, hostname, ip_address, os_version, username,
		        status, env_label, has_report, binary_hash, binary_trusted, last_update,
		        security_products
		 FROM agents WHERE agent_id = $1`, agentID)
	var agentSecProducts []byte
	row.Scan(
		&report.Agent.AgentID, &report.Agent.Hostname, &report.Agent.IPAddress,
		&report.Agent.OSVersion, &report.Agent.Username, &report.Agent.Status,
		&report.Agent.EnvLabel, &report.Agent.HasReport,
		&report.Agent.BinaryHash, &report.Agent.BinaryTrusted, &report.Agent.LastUpdate,
		&agentSecProducts,
	)
	json.Unmarshal(agentSecProducts, &report.SecurityTools)
	if report.Agent.AgentID == "" {
		report.Agent.AgentID = agentID
	}

	report.TacticHeatmap = buildTacticHeatmap(results)
	report.DetectionCategories = buildDetectionCategories(results)
	report.TopFindings = buildTopFindings(results, scenarioName)
	report.ObjectiveRisks = buildObjectiveRisks(results)
	report.Detection = buildDetectionSummary(results)
	report.DetectionValidation = e.buildDetectionValidation(ctx, runID, scenarioID, results)
	report.AttackPath = buildAttackPath(results)
	report.AttackFlow = BuildAttackFlow(results)
	report.AttackFlowSummary = summariseAttackFlow(report.AttackFlow)
	report.KillChain = buildKillChain(results, report.DetectionTechniques)
	report.TechniqueMatrix = buildTechniqueMatrix(results, report.DetectionTechniques)
	report.CoverageBreakdown = buildCoverageBreakdown(report.TechniqueMatrix)
	report.PrivilegeSummary = buildPrivilegeSummary(report.TechniqueMatrix)
	for _, r := range report.TechniqueMatrix {
		if r.CleanupVerdict == "partial" || r.CleanupVerdict == "leaked" {
			report.CleanupFailed = true
			report.CleanupFailedCount++
		}
	}

	report.Summary = ExecutiveSummary{
		RiskScore:          score.RiskScore,
		Classification:     score.Classification,
		PreventionScore:    score.PreventionScore,
		ExposureScore:      score.ExposureScore,
		CoverageScore:      score.CoverageScore,
		KillChainCoverage:  score.KillChainCoverage,
		KillChainAmplifier: score.KillChainAmplifier,
		Trend:              score.Trend,
		TotalRuns:          1,
		TotalTechniques:    score.TotalTechniques,
		PassedTechniques:   score.PassedTechniques,
		FailedTechniques:   score.FailedTechniques,
		ErroredTechniques:  score.ErroredTechniques,
		SkippedTechniques:  score.SkippedTechniques,
		LastRunAt:          startedAt,
		LastScenarioName:   scenarioName,
		CriticalFailures:   score.CriticalFailures,
		Recommendations:    buildRecommendations(score, report.TacticHeatmap),
	}
	if report.Summary.Classification == "" {
		report.Summary.Classification = "No Data"
	}
	if detRate != nil {
		report.Summary.DetectionRate = *detRate
	}
	if undetRate != nil {
		report.Summary.UndetectedRate = *undetRate
	}
	if mttd != nil {
		report.Summary.MTTDMs = *mttd
	}

	report.Runs = []RunSummary{{
		ID: runID, ScenarioName: scenarioName, Status: status,
		StartedAt: startedAt, CompletedAt: completedAt,
		RiskScore: score.RiskScore, Classification: score.Classification,
		PreventionScore: score.PreventionScore, ExposureScore: score.ExposureScore,
		TotalTechniques: score.TotalTechniques, FailedTechniques: score.FailedTechniques,
	}}

	// Trend: a per-run report still shows the endpoint's programme trend, not just
	// this run in isolation. Pull the agent's scored run history for the comparison.
	var trendRuns []RunSummary
	if trows, terr := e.db.Query(ctx,
		`SELECT id, status, score, started_at
		   FROM scenario_runs
		  WHERE agent_id = $1 AND status IN ('completed','partial')
		  ORDER BY started_at DESC LIMIT 20`, agentID); terr == nil {
		defer trows.Close()
		for trows.Next() {
			var rs RunSummary
			var scoreRaw []byte
			trows.Scan(&rs.ID, &rs.Status, &scoreRaw, &rs.StartedAt)
			if len(scoreRaw) > 0 {
				var sc models.Score
				if json.Unmarshal(scoreRaw, &sc) == nil {
					rs.PreventionScore = sc.PreventionScore
					rs.RiskScore = sc.RiskScore
				}
			}
			trendRuns = append(trendRuns, rs)
		}
	}
	report.TrendAnalysis = buildTrendSummary(trendRuns)

	// Executive-grade derivations — per-run detection verdicts carry latency, so
	// MTTD-per-tactic is available here (unlike the agent posture Build).
	deriveExecutive(report, results, report.DetectionTechniques)

	if g, s := e.loadAttackPathGraph(ctx); g != nil {
		report.AttackPathValidation = &s
		report.PathCorrelation = e.loadPathCorrelation(ctx, g, s)
	}
	applyAttackPathToSummary(&report.Summary, report.AttackPathValidation)

	e.populateAttackSurfaceAge(ctx, report, agentID)
	e.populateVariantCoverage(ctx, report, runID)

	er := buildEnvRestoration(report.TechniqueMatrix, report.Reverted)
	if er.HasData {
		er.RunCount = 1
		if er.StepsLeaked == 0 {
			er.RunsClean = 1
		} else {
			er.RunsWithIssues = 1
		}
		report.EnvRestoration = &er
	}
	report.ReadinessScores = buildReadinessScores(report.TechniqueMatrix)
	report.RansomwareReadiness = buildRansomwareReadiness(report.TechniqueMatrix)
	// Enrich with trends first (compares to previous runs), then persist this run.
	e.enrichReadinessTrends(ctx, agentID, report.ReadinessScores, runID)
	e.enrichReadinessTrends(ctx, agentID, report.RansomwareReadiness, runID)
	e.persistReadinessHistory(ctx, runID, agentID, report.ReadinessScores)
	e.populateKEVExposure(ctx, report)
	e.populateThreatIntel(ctx, report, runID)
	e.populatePriorityScores(ctx, report)

	return report, nil
}

// BuildFromCampaign constructs a fleet-wide FullReport for a campaign by
// aggregating every child run's results into one assessment, then reusing the
// same derivations and renderers as the single-agent report. The Scope +
// per-agent breakdown carry the campaign framing; scores are computed over the
// union of all child-run results so the headline reflects the whole fleet.
func (e *Engine) BuildFromCampaign(ctx context.Context, campaignID string, filter string) (*FullReport, error) {
	report := &FullReport{GeneratedAt: time.Now().UTC()}

	var campName, scenarioID, scenarioName string
	var startedAt time.Time
	if err := e.db.QueryRow(ctx,
		`SELECT name, scenario_id, scenario_name, started_at FROM campaigns WHERE id = $1`, campaignID,
	).Scan(&campName, &scenarioID, &scenarioName, &startedAt); err != nil {
		return nil, fmt.Errorf("campaign %s not found: %w", campaignID, err)
	}

	rows, err := e.db.Query(ctx,
		`SELECT sr.id, sr.agent_id, COALESCE(a.hostname,''), sr.status, sr.results, sr.score,
		        sr.started_at, sr.completed_at, sr.steps_total_base, sr.steps_eligible_base
		   FROM scenario_runs sr LEFT JOIN agents a ON a.agent_id = sr.agent_id
		  WHERE sr.campaign_id = $1 ORDER BY sr.started_at`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var allResults []models.SimulationResult
	agentSet := map[string]bool{}
	var runCount int
	for rows.Next() {
		var rid, agentID, hostname, status string
		var resultsRaw, scoreRaw []byte
		var sAt time.Time
		var cAt *time.Time
		var stepsTotalBase, stepsEligibleBase int
		if rows.Scan(&rid, &agentID, &hostname, &status, &resultsRaw, &scoreRaw, &sAt, &cAt,
			&stepsTotalBase, &stepsEligibleBase) != nil {
			continue
		}
		report.StepsTotalBase += stepsTotalBase
		report.StepsEligibleBase += stepsEligibleBase
		runCount++
		agentSet[agentID] = true
		var results []models.SimulationResult
		if len(resultsRaw) > 0 {
			if json.Unmarshal(resultsRaw, &results) == nil {
				results = FilterResults(results, filter)
				allResults = append(allResults, results...)
			}
		}
		var sc models.Score
		if len(scoreRaw) > 0 {
			_ = json.Unmarshal(scoreRaw, &sc)
		}
		host := hostname
		if host == "" {
			host = agentID
		}
		report.CampaignAgents = append(report.CampaignAgents, CampaignAgentRow{
			Hostname: host, Status: status, PreventionScore: sc.PreventionScore,
			Tested: sc.PassedTechniques + sc.FailedTechniques, Failed: sc.FailedTechniques,
		})
		report.Runs = append(report.Runs, RunSummary{
			ID: rid, ScenarioName: scenarioName, Status: status, StartedAt: sAt, CompletedAt: cAt,
			RiskScore: sc.RiskScore, Classification: sc.Classification,
			PreventionScore: sc.PreventionScore, ExposureScore: sc.ExposureScore,
			TotalTechniques: sc.TotalTechniques, FailedTechniques: sc.FailedTechniques,
		})
	}

	// Fleet score = ComputeScore over the union of all child-run results.
	score := models.ComputeScore(allResults, nil)
	report.TacticHeatmap = buildTacticHeatmap(allResults)
	report.TopFindings = buildTopFindings(allResults, scenarioName)
	report.ObjectiveRisks = buildObjectiveRisks(allResults)
	report.Detection = buildDetectionSummary(allResults)
	// Campaign aggregates many runs; per-run manual attestations are overlaid on
	// the per-run report, not the campaign roll-up. Pass runID="" → automatic only.
	report.DetectionValidation = e.buildDetectionValidation(ctx, "", scenarioID, allResults)
	report.AttackPath = buildAttackPath(allResults)
	report.TechniqueMatrix = buildTechniqueMatrix(allResults, nil)
	report.CoverageBreakdown = buildCoverageBreakdown(report.TechniqueMatrix)
	report.PrivilegeSummary = buildPrivilegeSummary(report.TechniqueMatrix)
	for _, r := range report.TechniqueMatrix {
		if r.CleanupVerdict == "partial" || r.CleanupVerdict == "leaked" {
			report.CleanupFailed = true
			report.CleanupFailedCount++
		}
	}

	report.Summary = ExecutiveSummary{
		RiskScore: score.RiskScore, Classification: score.Classification,
		PreventionScore: score.PreventionScore, ExposureScore: score.ExposureScore,
		CoverageScore: score.CoverageScore, KillChainCoverage: score.KillChainCoverage,
		KillChainAmplifier: score.KillChainAmplifier, Trend: score.Trend,
		TotalRuns: runCount, TotalTechniques: score.TotalTechniques,
		PassedTechniques: score.PassedTechniques, FailedTechniques: score.FailedTechniques,
		ErroredTechniques: score.ErroredTechniques, SkippedTechniques: score.SkippedTechniques,
		LastRunAt: startedAt, LastScenarioName: scenarioName,
		CriticalFailures: score.CriticalFailures,
		Recommendations:  buildRecommendations(score, report.TacticHeatmap),
	}
	if report.Summary.Classification == "" {
		report.Summary.Classification = "No Data"
	}
	// Agent.Hostname backs the page footers and fallbacks; set it to the campaign.
	report.Agent.Hostname = campName
	report.ScenarioName = scenarioName
	report.Scope = &ReportScope{
		Kind: "campaign", Title: campName,
		Subtitle: "Campaign Assessment — " + scenarioName,
		Scenario: scenarioName, AgentCount: len(agentSet), RunCount: runCount,
	}

	// Campaign aggregates multiple runs, so per-tactic detection latency (MTTD)
	// is not meaningful here — pass nil dets (MTTD renders "—").
	deriveExecutive(report, allResults, nil)

	if g, s := e.loadAttackPathGraph(ctx); g != nil {
		report.AttackPathValidation = &s
		report.PathCorrelation = e.loadPathCorrelation(ctx, g, s)
	}
	applyAttackPathToSummary(&report.Summary, report.AttackPathValidation)

	e.populateCampaignAttackSurfaceAge(ctx, report, campaignID)
	e.populateCampaignVariantCoverage(ctx, report, campaignID)

	// Aggregate detection sources across all campaign runs.
	dRows, _ := e.db.Query(ctx,
		`SELECT detection_summary FROM scenario_runs
		 WHERE campaign_id = $1 AND detection_summary IS NOT NULL`, campaignID)
	if dRows != nil {
		defer dRows.Close()
		type pacc struct {
			count int
			minMs int64
			sumMs int64
		}
		prodMap := map[string]*pacc{}
		for dRows.Next() {
			var raw []byte
			if dRows.Scan(&raw) != nil {
				continue
			}
			for _, src := range buildDetectionSourcesFromSummary(raw) {
				pa, ok := prodMap[src.Product]
				if !ok {
					pa = &pacc{}
					prodMap[src.Product] = pa
				}
				pa.count += src.Detections
				pa.sumMs += src.AvgMTTDMs * int64(src.Detections)
				if src.MinMTTDMs > 0 && (pa.minMs == 0 || src.MinMTTDMs < pa.minMs) {
					pa.minMs = src.MinMTTDMs
				}
			}
		}
		if len(prodMap) > 0 {
			dsList := make([]DetectionSource, 0, len(prodMap))
			for prod, pa := range prodMap {
				var avg int64
				if pa.count > 0 {
					avg = pa.sumMs / int64(pa.count)
				}
				dsList = append(dsList, DetectionSource{
					Product:    prod,
					Detections: pa.count,
					MinMTTDMs:  pa.minMs,
					AvgMTTDMs:  avg,
				})
			}
			sort.Slice(dsList, func(i, j int) bool {
				return dsList[i].Detections > dsList[j].Detections
			})
			report.DetectionSources = dsList
		}
	}

	// Environment Restoration — aggregate per-run breakdown from scenario_runs.
	er := buildEnvRestoration(report.TechniqueMatrix, report.Reverted)
	if er.HasData {
		var runsTotal, runsClean int
		e.db.QueryRow(ctx,
			`SELECT COUNT(*),
			        COALESCE(SUM(CASE WHEN leaked_steps = 0 THEN 1 ELSE 0 END), 0)
			 FROM scenario_runs
			 WHERE campaign_id = $1 AND status IN ('completed','partial')`, campaignID,
		).Scan(&runsTotal, &runsClean)
		er.RunCount = runsTotal
		er.RunsClean = runsClean
		er.RunsWithIssues = runsTotal - runsClean
		report.EnvRestoration = &er
	}
	report.ReadinessScores = buildReadinessScores(report.TechniqueMatrix)
	report.RansomwareReadiness = buildRansomwareReadiness(report.TechniqueMatrix)
	// For campaigns, use the first agent's history for trend context (best-effort).
	for aid := range agentSet {
		e.enrichReadinessTrends(ctx, aid, report.ReadinessScores, "")
		e.enrichReadinessTrends(ctx, aid, report.RansomwareReadiness, "")
		break
	}
	e.populateKEVExposure(ctx, report)
	e.populatePriorityScores(ctx, report)

	return report, nil
}

// TechniqueGroup aggregates every result for one ATT&CK technique so the report
// shows a single rolled-up entry with counts, instead of repeating the same
// technique (and its identical threat/remediation) dozens of times — the
// "report fatigue" the ART selective review flagged.
type TechniqueGroup struct {
	TechniqueID string
	Name        string
	Tactic      string
	Severity    string
	Executed    int // FAIL — ran without being blocked
	Blocked     int // PASS / BLOCKED — a control stopped it
	Errored     int // ERROR — BAS could not execute (excluded from scoring)
	Skipped     int // SKIPPED — intentionally not run
	Total       int
	Results     []models.SimulationResult
}

// groupResultsByTechnique rolls results up by technique ID (falling back to name
// for non-ATT&CK checks), preserving first-seen order. Counts are tallied per the
// 4-verdict taxonomy so the report can summarise ERROR/SKIPPED noise rather than
// rendering a block for each one.
func groupResultsByTechnique(results []models.SimulationResult) []TechniqueGroup {
	idx := make(map[string]int)
	var groups []TechniqueGroup
	for _, r := range results {
		key := r.Technique.ID
		if key == "" {
			key = r.Technique.Name
		}
		i, ok := idx[key]
		if !ok {
			i = len(groups)
			idx[key] = i
			groups = append(groups, TechniqueGroup{
				TechniqueID: r.Technique.ID,
				Name:        r.Technique.Name,
				Tactic:      r.Technique.Tactic,
				Severity:    r.Severity,
			})
		}
		g := &groups[i]
		g.Total++
		g.Results = append(g.Results, r)
		switch r.Result {
		case models.ResultFail:
			g.Executed++
		case models.ResultPass, models.ResultBlocked:
			g.Blocked++
		case models.ResultError:
			g.Errored++
		case models.ResultSkipped:
			g.Skipped++
		}
	}
	return groups
}

// Detection is the per-technique detection verdict derived from the event-log
// telemetry the agent collected during the step. It answers the ART review's
// "was the attack detected, and by what" — honestly limited to what is locally
// observable (Microsoft Defender + Sysmon/Security); third-party EDR alerts are
// never asserted because they are not locally queryable.
type Detection struct {
	Detected bool   // a real detection alert fired (Defender)
	Status   string // "Detected" | "Logged" | "None"
	Source   string // "Microsoft Defender" | "Sysmon" | "Windows Security" | ""
	Detail   string // human phrase for the report
}

// defenderDetectIDs are Microsoft Defender Operational event IDs that mean a
// threat was detected / acted on (not benign update/scan noise).
var defenderDetectIDs = map[string]bool{
	"1006": true, "1007": true, "1008": true, "1009": true, "1010": true,
	"1011": true, "1012": true, "1015": true, "1116": true, "1117": true,
	"1118": true, "1119": true,
}

// classifyDetection maps the agent's raw "id:log" event tokens to a detection
// verdict. A Defender detection event = Detected; any other telemetry (Sysmon,
// Security, benign Defender events) = Logged (visibility, no alert); nothing =
// None. Interpretation lives here on the server, not on the agent.
// ClassifyDetectionStatus returns the coarse detection status ("Detected" |
// "Logged" | "None") for a step's events. Exported so the campaign rollup can
// reuse the same event-token heuristic the kill-chain uses, without duplicating
// it.
func ClassifyDetectionStatus(events []string) string { return classifyDetection(events).Status }

func classifyDetection(events []string) Detection {
	loggedSource := ""
	for _, ev := range events {
		id, logName, ok := splitEventToken(ev)
		if !ok {
			continue
		}
		llog := strings.ToLower(logName)
		switch {
		case strings.Contains(llog, "defender"):
			if defenderDetectIDs[id] {
				return Detection{
					Detected: true, Status: "Detected", Source: "Microsoft Defender",
					Detail: "Microsoft Defender raised a detection (event " + id + ")",
				}
			}
			if loggedSource == "" {
				loggedSource = "Microsoft Defender"
			}
		case strings.Contains(llog, "sysmon"):
			if loggedSource == "" {
				loggedSource = "Sysmon"
			}
		case detect.IsEDRProvider(logName):
			return Detection{
				Detected: true, Status: "Detected", Source: logName,
				Detail: "Third-party EDR raised a detection (" + logName + " event " + id + ")",
			}
		default:
			if loggedSource == "" {
				loggedSource = "Windows Security"
			}
		}
	}
	if loggedSource != "" {
		return Detection{
			Status: "Logged", Source: loggedSource,
			Detail: "Activity logged by " + loggedSource + " — no detection alert raised",
		}
	}
	return Detection{Status: "None", Detail: "No detection telemetry observed"}
}

// asrBlockIDs are Microsoft Defender Operational event IDs that mean an Attack
// Surface Reduction (or related Defender exploit-guard) rule BLOCKED an action —
// not merely audited it. Used to attribute a PASS to Defender ASR specifically.
var asrBlockIDs = map[string]bool{
	"1121": true, // ASR rule blocked
	"1123": true, // Controlled folder access blocked
	"1125": true, // Network protection blocked
}

// attributeControl names the security control that blocked a technique, when the
// evidence honestly supports a specific attribution — addressing the ART review's
// "PASS, but which control?". Order of confidence: Defender Operational events
// (ASR rule action / threat action), then recognisable block signatures in the
// captured output. Returns "" when no control can be evidenced; the caller then
// states a control blocked it WITHOUT guessing a product. We never assert a
// control we cannot evidence. Framework-agnostic — keys off events and output.
func attributeControl(r models.SimulationResult) string {
	for _, ev := range r.Events {
		id, logName, ok := splitEventToken(ev)
		if !ok {
			continue
		}
		if strings.Contains(strings.ToLower(logName), "defender") {
			if asrBlockIDs[id] {
				return "Microsoft Defender (ASR rule)"
			}
			if defenderDetectIDs[id] {
				return "Microsoft Defender"
			}
		}
	}
	low := strings.ToLower(r.RawOutput)
	switch {
	case strings.Contains(low, "defender"),
		strings.Contains(low, "antivirus"),
		strings.Contains(low, "threat detected"),
		strings.Contains(low, "quarantined"),
		strings.Contains(low, "operation did not complete successfully"):
		return "Microsoft Defender (from output)"
	case strings.Contains(low, "blocked by group policy"),
		strings.Contains(low, "blocked by your administrator"),
		strings.Contains(low, "this program is blocked"),
		strings.Contains(low, "this app has been blocked"):
		return "Application Control / Group Policy"
	case strings.Contains(low, "constrained language"):
		return "PowerShell Constrained Language Mode"
	case strings.Contains(low, "amsi"):
		return "Antimalware Scan Interface (AMSI)"
	}
	return ""
}

// DetectionSummary is the defence-in-depth rollup of executed (FAIL) techniques:
// a FAIL means prevention did not stop the technique, but the SOC outcome differs
// sharply depending on whether it was also detected. This reframes a raw FAIL
// count into the actionable "prevented? detected?" matrix a BAS buyer expects.
type DetectionSummary struct {
	ExecutedUnprevented int  // FAIL count — prevention controls did not stop execution
	Detected            int  // …of which a detection alert fired (Microsoft Defender)
	LoggedOnly          int  // …of which telemetry exists but no alert was raised
	Undetected          int  // …of which no telemetry was observed (executed unseen)
	TelemetryObserved   bool // any host telemetry was collected this run at all
}

// buildDetectionSummary tallies the prevention/detection matrix and records
// whether ANY host telemetry was collected during the run. The distinction is
// critical and honest: when no events were collected for the entire run (an old
// agent build, the agent offline, or Defender disabled), "Undetected" does NOT
// mean the techniques evaded detection — it means detection could not be measured
// at all. The report must say so rather than implying every technique slipped past
// the SOC. When telemetry exists, an undetected FAIL is a genuine visibility gap.
func buildDetectionSummary(results []models.SimulationResult) DetectionSummary {
	var s DetectionSummary
	for _, r := range results {
		if len(r.Events) > 0 {
			s.TelemetryObserved = true
		}
		if r.Result != models.ResultFail {
			continue
		}
		s.ExecutedUnprevented++
		switch classifyDetection(r.Events).Status {
		case "Detected":
			s.Detected++
		case "Logged":
			s.LoggedOnly++
		default:
			s.Undetected++
		}
	}
	return s
}

// splitEventToken parses a "id:logName" telemetry token. Log names contain no
// colon, so a split on the first colon is unambiguous.
func splitEventToken(tok string) (id, logName string, ok bool) {
	i := strings.IndexByte(tok, ':')
	if i <= 0 || i >= len(tok)-1 {
		return "", "", false
	}
	return strings.TrimSpace(tok[:i]), strings.TrimSpace(tok[i+1:]), true
}

// ── helpers ───────────────────────────────────────────────────────────────────

var tacticOrder = []string{
	"initial-access", "execution", "persistence", "privilege-escalation",
	"defense-evasion", "credential-access", "discovery",
	"lateral-movement", "collection", "exfiltration", "command-and-control", "impact",
}

var tacticWeight = map[string]string{
	"credential-access": "Critical", "lateral-movement": "Critical", "privilege-escalation": "Critical",
	"persistence": "High", "defense-evasion": "High", "execution": "High",
	"command-and-control": "High", "impact": "High", "exfiltration": "High", "collection": "High",
	"initial-access": "Medium", "discovery": "Low", "reconnaissance": "Low",
}

func buildTacticHeatmap(results []models.SimulationResult) []TacticEntry {
	passed := make(map[string]int)
	failed := make(map[string]int)
	for _, r := range results {
		// ERROR (BAS could not execute) and SKIPPED (not run) are not security
		// outcomes — they must not taint a tactic as failed.
		if r.Result == models.ResultSkipped || r.Result == models.ResultError {
			continue
		}
		t := r.Technique.Tactic
		if t == "" {
			continue
		}
		if r.Result == models.ResultPass || r.Result == models.ResultBlocked {
			passed[t]++
		} else {
			failed[t]++
		}
	}
	var out []TacticEntry
	for _, tactic := range tacticOrder {
		p, f := passed[tactic], failed[tactic]
		total := p + f
		if total == 0 {
			continue
		}
		pct := 0
		if total > 0 {
			pct = p * 100 / total
		}
		out = append(out, TacticEntry{
			Tactic: tactic, Passed: p, Failed: f, Total: total, PassPct: pct,
			Weight: tacticWeight[tactic],
		})
	}
	return out
}

// buildDetectionCategories rolls the run's checks up to a per-tactic verdict for
// the report's "Detection Coverage" section: a tactic is "pass" when all its
// executed checks passed, "fail" when any failed, "unknown" when it was only
// skipped. Re-derived from live results (each check carries its ATT&CK tactic),
// replacing the legacy agent-submitted posture report. Ordered by kill-chain
// phase and consistent with the tactic heatmap (a single failure taints the
// tactic — same rule as CoverageScore).
func buildDetectionCategories(results []models.SimulationResult) []Category {
	type agg struct{ exec, fail int }
	m := make(map[string]*agg)
	for _, r := range results {
		t := r.Technique.Tactic
		if t == "" {
			continue
		}
		a := m[t]
		if a == nil {
			a = &agg{}
			m[t] = a
		}
		if r.Result == models.ResultSkipped || r.Result == models.ResultError {
			continue
		}
		a.exec++
		if r.Result != models.ResultPass && r.Result != models.ResultBlocked {
			a.fail++
		}
	}
	var out []Category
	for _, tactic := range tacticOrder {
		a := m[tactic]
		if a == nil {
			continue
		}
		result := "unknown" // tested but only skipped
		if a.exec > 0 {
			if a.fail == 0 {
				result = "pass"
			} else {
				result = "fail"
			}
		}
		out = append(out, Category{Name: tactic, Result: result})
	}
	return out
}

// tacticBusinessImpact returns an executive-grade business impact sentence for a
// failing technique. Technique-level overrides give precise context for the most
// impactful ATT&CK techniques; the tactic-level fallback ensures every finding has
// coverage across all 14 ATT&CK Enterprise tactics.
func tacticBusinessImpact(tactic, techniqueID string) string {
	switch strings.ToUpper(strings.TrimSpace(techniqueID)) {
	case "T1003", "T1003.001":
		return "LSASS credentials enable Pass-the-Hash or Pass-the-Ticket attacks against every Windows endpoint in the domain. An attacker can silently reach domain controllers without triggering additional authentication prompts."
	case "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008":
		return "Harvested credentials grant silent access to other systems in the domain. Lateral movement can begin within minutes of a successful dump."
	case "T1486":
		return "Ransomware reached the encryption stage. A real attack would render files unrecoverable without tested backups, potentially halting operations for days and triggering RBI/SEBI incident notification obligations."
	case "T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.012":
		return "Code injected into a trusted process can evade application whitelisting and most EDR behavioral detection, operating with the full privileges of the host process."
	case "T1078", "T1078.001", "T1078.002", "T1078.003", "T1078.004":
		return "Compromised valid credentials produce activity indistinguishable from a legitimate user. Detection may require weeks of forensic analysis to identify the full breach timeline."
	case "T1059", "T1059.001", "T1059.003":
		return "Script execution gives an attacker arbitrary command execution under the endpoint's user or system context — the baseline capability for ransomware deployment, data exfiltration, and persistence."
	case "T1053", "T1053.002", "T1053.003", "T1053.005":
		return "Scheduled task persistence survives reboots, password resets, and many partial remediation attempts. An attacker automatically re-establishes access even after initial cleanup efforts."
	case "T1547", "T1547.001":
		return "Registry run-key persistence ensures the attacker's payload executes on every user logon, enabling long-dwell-time campaigns that remain undetected for extended periods."
	case "T1562", "T1562.001":
		return "With security tooling disabled, all subsequent attacker activity is invisible to the SOC. This is the standard precursor to ransomware deployment and large-scale data exfiltration."
	case "T1190":
		return "Exploiting a public-facing application gives an attacker an unauthenticated foothold inside the network perimeter, bypassing all VPN and identity controls."
	}
	switch strings.ToLower(strings.TrimSpace(tactic)) {
	case "initial-access":
		return "An attacker could establish an initial foothold inside the corporate network, bypassing perimeter controls and enabling all subsequent campaign stages."
	case "execution":
		return "Malicious code ran on this endpoint. From here, an attacker can deploy ransomware, establish persistence, or use the endpoint as a launchpad for attacks on adjacent systems."
	case "persistence":
		return "An attacker can survive system reboots and credential rotations, maintaining durable long-term access without re-exploitation — increasing dwell time and the window for data theft."
	case "privilege-escalation":
		return "Admin or SYSTEM-level access was achieved. An attacker can now disable security tools, access protected data stores, and move laterally across the domain without restriction."
	case "defense-evasion":
		return "Security controls were bypassed on this endpoint. An attacker operating in this state can conduct further activity with a greatly reduced chance of detection or incident response."
	case "credential-access":
		return "Credentials harvested here can authenticate as legitimate users across Active Directory, enabling silent lateral movement and potentially domain-wide access within minutes."
	case "discovery":
		return "Internal network structure and high-value targets have been identified. An attacker can now plan targeted lateral movement and data theft with precision and minimal noise."
	case "lateral-movement":
		return "An attacker can pivot from this endpoint to other systems on the network, expanding the breach blast radius. In BFSI environments this can reach core banking systems and payment infrastructure."
	case "collection":
		return "Sensitive data — documents, credentials, and financial records — can be gathered and staged for exfiltration. Attackers typically spend weeks in this phase before data leaves the network."
	case "command-and-control":
		return "Remote control of this endpoint is established over a covert channel. An attacker can issue commands, exfiltrate data, and re-deploy payloads even after partial remediation."
	case "exfiltration":
		return "Data is being transferred outside organizational control. In a real incident this represents breach completion, triggering regulatory notification obligations under DPDPA, RBI, and SEBI CSCRF frameworks."
	case "impact":
		return "Business operations are at risk of disruption. Ransomware, service outages, or data destruction are realistic outcomes at this kill-chain stage, with recovery typically taking days to weeks."
	case "resource-development":
		return "Organizational resources can be weaponized as attacker infrastructure, enabling further campaigns and potentially implicating the organization in attacks against third parties."
	case "reconnaissance":
		return "Targeted intelligence gathered about users, systems, and vulnerabilities enables attackers to craft more effective attacks with higher success rates and lower detection probability."
	}
	return ""
}

// remediationPlan returns structured remediation guidance (Priority / Owner /
// Effort / Verification) for a failing technique. Technique-level overrides
// provide specific actionable steps; severity and tactic-level fallbacks ensure
// every finding has coverage.
func remediationPlan(tactic, techniqueID, severity string) RemediationPlan {
	tid := strings.ToUpper(strings.TrimSpace(techniqueID))
	tac := strings.ToLower(strings.TrimSpace(tactic))

	switch tid {
	case "T1003", "T1003.001":
		return RemediationPlan{
			Priority:     "Critical",
			Owner:        "Active Directory / Identity Team",
			Effort:       "Days",
			Verification: "Re-run LSASS dump test — result must change to BLOCKED. Enable Credential Guard via Group Policy (Device Guard) and confirm with Get-WinEvent -FilterHashtable @{LogName='System'; Id=12}. Verify Event ID 4656 fires in Windows Security log on any LSASS handle attempt.",
		}
	case "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006", "T1003.007", "T1003.008":
		return RemediationPlan{
			Priority:     "Critical",
			Owner:        "Active Directory / Identity Team",
			Effort:       "Days",
			Verification: "Re-run the credential dump sub-technique — result must change to BLOCKED. Audit SAM/NTDS/LSA secret access via Windows Security Event 4663. Restrict access to credential stores using SACL auditing and Protected Users group.",
		}
	case "T1486":
		return RemediationPlan{
			Priority:     "Critical",
			Owner:        "Endpoint Security / Backup Team",
			Effort:       "Weeks",
			Verification: "Re-run ransomware simulation — file encryption must be BLOCKED by Controlled Folder Access or EDR policy. Verify an immutable offline backup exists with a last-restore-date under 24 hours. Execute a test restore on a non-production asset and document RTO.",
		}
	case "T1055", "T1055.001", "T1055.002", "T1055.003", "T1055.004", "T1055.012":
		return RemediationPlan{
			Priority:     "Critical",
			Owner:        "Endpoint Security Team",
			Effort:       "Days",
			Verification: "Re-run process injection test — must produce BLOCKED verdict. Enable Windows Defender Exploit Protection memory protections (Enable-ExploitProtection) or equivalent EDR injection-prevention policy. Confirm injection events log to SIEM.",
		}
	case "T1078", "T1078.001", "T1078.002", "T1078.003", "T1078.004":
		return RemediationPlan{
			Priority:     "Critical",
			Owner:        "Active Directory / IAM Team",
			Effort:       "Days",
			Verification: "Enroll all privileged accounts in MFA. Deploy LAPS for local admin accounts. Audit logon events (Event 4624/4625) for anomalous access. Re-test with a controlled credential spray — all attempts must be detected or blocked.",
		}
	case "T1059", "T1059.001", "T1059.003":
		return RemediationPlan{
			Priority:     "High",
			Owner:        "Endpoint Security Team",
			Effort:       "Days",
			Verification: "Enable PowerShell Constrained Language Mode and Script Block Logging. Re-run scripting execution test — EDR must alert or block. Confirm AMSI events appear in Windows Defender event log (Event ID 1116 / 1117).",
		}
	case "T1053", "T1053.002", "T1053.003", "T1053.005":
		return RemediationPlan{
			Priority:     "High",
			Owner:        "IT / SysAdmin Team",
			Effort:       "Days",
			Verification: `Re-run scheduled task persistence test — Sysmon Event ID 1 (process create: schtasks.exe) must be captured and alerted. Audit existing tasks: Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\Microsoft*'}. Remove or document any unlisted tasks.`,
		}
	case "T1547", "T1547.001":
		return RemediationPlan{
			Priority:     "High",
			Owner:        "IT / SysAdmin Team",
			Effort:       "Days",
			Verification: "Re-run registry run-key persistence test — Sysmon Event ID 13 (registry value set) must be captured and alerted on HKCU/HKLM Run keys. Deploy AppLocker or WDAC rules to block execution from user-writable locations.",
		}
	case "T1562", "T1562.001":
		return RemediationPlan{
			Priority:     "Critical",
			Owner:        "SOC / Endpoint Security Team",
			Effort:       "Hours",
			Verification: "Enable Tamper Protection on all endpoints via Microsoft Intune or Defender policy. Re-run defense evasion test — tamper attempt must be BLOCKED. Confirm Get-MpComputerStatus shows IsTamperProtected: True on all endpoints.",
		}
	case "T1190":
		return RemediationPlan{
			Priority:     "Critical",
			Owner:        "SOC / Perimeter Security Team",
			Effort:       "Days",
			Verification: "Apply vendor patch or WAF rule for the exploited vulnerability. Re-run exploit test against the patched asset — result must change to BLOCKED. Confirm WAF logs show the attempt and that the vulnerability scanner no longer reports the CVE.",
		}
	}

	p := RemediationPlan{}
	switch severity {
	case "Critical":
		p.Priority = "Critical"
		p.Effort = "Days"
	case "High":
		p.Priority = "High"
		p.Effort = "Days"
	case "Medium":
		p.Priority = "Medium"
		p.Effort = "Weeks"
	default:
		p.Priority = "Low"
		p.Effort = "Weeks"
	}
	switch tac {
	case "initial-access":
		p.Owner = "SOC / Perimeter Security Team"
		p.Verification = "Re-test initial access vector after control change. Confirm network perimeter and email gateway logs block and alert on the attempt."
	case "execution":
		p.Owner = "Endpoint Security Team"
		p.Verification = "Re-run execution technique after applying EDR behavioral rule. AMSI or EDR event must fire. Verify process creation events are captured in SIEM."
	case "persistence":
		p.Owner = "IT / SysAdmin Team"
		p.Verification = "Re-run persistence technique after deploying detection rule. Verify Sysmon or Windows Event capture the action. Audit startup locations for unauthorised entries."
	case "privilege-escalation":
		p.Owner = "Active Directory / Endpoint Team"
		p.Verification = "Apply least-privilege policy and re-run escalation test. Verify admin tokens are not accessible to standard users. Confirm LAPS is active on target."
	case "defense-evasion":
		p.Owner = "Endpoint Security Team"
		p.Verification = "Enable additional EDR behavioral rules and Tamper Protection. Re-run evasion test — EDR must detect or block. Verify Tamper Protection is active on all endpoints."
	case "credential-access":
		p.Owner = "Active Directory / Identity Team"
		p.Verification = "Enable Credential Guard and audit credential access events (Event IDs 4648, 4776, 4768). Re-run credential access technique — result must change to BLOCKED."
	case "discovery":
		p.Owner = "Endpoint Security Team"
		p.Verification = "Deploy UEBA or behavioral rule for reconnaissance activity. Re-run discovery technique — SIEM must generate an alert on the enumeration behaviour."
	case "lateral-movement":
		p.Owner = "Network Security Team"
		p.Verification = "Restrict SMB/WinRM/RDP between non-admin workstations via firewall policy. Re-run lateral movement technique — connection must be blocked or alerted."
	case "collection":
		p.Owner = "SOC / DLP Team"
		p.Verification = "Deploy DLP policy for sensitive file access patterns. Re-run collection technique — DLP rule must alert. Verify SIEM captures file read events on sensitive paths."
	case "command-and-control":
		p.Owner = "Network Security Team"
		p.Verification = "Block identified C2 channels via proxy/firewall. Deploy DNS filtering for known-bad domains. Re-run C2 technique — outbound connection must be blocked."
	case "exfiltration":
		p.Owner = "SOC / DLP Team"
		p.Verification = "Enable DLP outbound data transfer rules. Re-run exfiltration technique — data transfer must be blocked or alerted. Verify alert fires in SIEM within 5 minutes."
	case "impact":
		p.Owner = "Endpoint Security / Backup Team"
		p.Verification = "Enable Controlled Folder Access and validate immutable backup exists. Re-run impact technique — file modification must be BLOCKED. Confirm backup restore is tested and RTO documented."
	default:
		p.Owner = "Security Team"
		p.Verification = "Re-run this technique after applying the recommended control. The verdict must change from FAIL to BLOCKED or DETECTED. Confirm the detection event appears in SIEM."
	}
	return p
}

func buildTopFindings(results []models.SimulationResult, scenarioName string) []Finding {
	var findings []Finding
	// Deduplicate by technique: the same technique failing across several atomic
	// tests is ONE finding, not the "Critical, Critical, Critical…" repetition the
	// ART review flagged. Keep the first occurrence (first-seen order).
	seen := make(map[string]bool)
	for _, r := range results {
		if r.Result != models.ResultFail {
			continue
		}
		if r.Severity != "Critical" && r.Severity != "High" {
			continue
		}
		key := r.Technique.ID
		if key == "" {
			key = r.Technique.Name
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		findings = append(findings, Finding{
			TechniqueID:      r.Technique.ID,
			TechniqueName:    r.Technique.Name,
			Tactic:           r.Technique.Tactic,
			Severity:         r.Severity,
			Details:          r.Details,
			Remediation:      r.Remediation,
			BusinessImpact:   tacticBusinessImpact(r.Technique.Tactic, r.Technique.ID),
			ScenarioName:     scenarioName,
			ExecVerdict:      string(r.Result),
			ExecutedAs:       privLabel(r.ExecutedAs),
			RequestedPriv:    privLabel(r.RequestedPriv),
			DetectionVerdict: r.DetectionVerdict,
			CleanupVerdict:   r.CleanupVerdict,
			DurationMs:       r.DurationMs,
			Command:          r.Command,
			Framework:        r.Framework,
			RemPlan:          remediationPlan(r.Technique.Tactic, r.Technique.ID, r.Severity),
		})
	}
	return findings
}

func buildRecommendations(score models.Score, heatmap []TacticEntry) []string {
	var recs []string
	if score.PreventionScore < 50 {
		recs = append(recs, "Overall prevention score is critically low. Prioritise endpoint hardening and EDR deployment across all assets.")
	} else if score.PreventionScore < 70 {
		recs = append(recs, "Prevention score indicates significant control gaps. Review failed techniques and apply vendor hardening guides.")
	}
	for _, t := range heatmap {
		if t.Failed > 0 && t.Weight == "Critical" {
			recs = append(recs, "Critical tactic '"+t.Tactic+"' has "+formatInt(t.Failed)+" failing technique(s). Address immediately — this tactic has the highest attacker value in BFSI environments.")
		}
	}
	if score.KillChainAmplifier >= 1.8 {
		recs = append(recs, "Kill-chain amplifier is "+formatFloat(score.KillChainAmplifier)+"× — an attacker can traverse multiple consecutive kill-chain phases unimpeded. Implement network segmentation and lateral movement controls.")
	}
	if score.ExposureScore > 60 {
		recs = append(recs, "Exposure score exceeds 60. Deploy a 24×7 SOC with SIEM correlation rules aligned to detected failure patterns.")
	}
	if score.KillChainCoverage < 50 {
		recs = append(recs, "Tactic coverage is below 50%. Run additional scenarios (ART full sweep, Caldera lateral movement) to exercise more of the ATT&CK kill chain before next audit.")
	}
	if len(recs) == 0 {
		recs = append(recs, "Maintain current security posture. Schedule next BAS assessment within 30 days to verify continued effectiveness.")
	}
	return recs
}

// applyAttackPathToSummary copies the attack-path score into the executive
// summary and appends lateral-movement recommendations when the graph shows
// domain compromise, reachable crown jewels, or segmentation violations.
// Called after loadAttackPathGraph so the summary fields stay consistent.
func applyAttackPathToSummary(s *ExecutiveSummary, ap *attackpath.Summary) {
	if ap == nil {
		return
	}
	score := ap.AttackPathScore
	s.AttackPathScore = &score
	s.AttackPathBand = ap.Band
	s.Recommendations = append(s.Recommendations, attackPathRecs(ap)...)
}

// attackPathRecs returns executive-grade recommendations derived from the
// attack-path graph analysis. Returns nil when the graph is clean.
func attackPathRecs(ap *attackpath.Summary) []string {
	if ap == nil {
		return nil
	}
	var recs []string
	if ap.DomainCompromise {
		diff := string(ap.ShortestDADifficulty)
		recs = append(recs, "Domain compromise path exists (difficulty: "+diff+"). An attacker who gains a foothold on any host can reach Domain Admin / Tier-0 in "+formatInt(len(ap.ShortestDAPath))+" hop(s). Segment the network, enforce tiered administration (PAW/LAPS), and restrict lateral-movement protocols (SMB/WinRM/RDP) to authorised management hosts only.")
	}
	reachableCJs := 0
	for _, cj := range ap.CrownJewels {
		if cj.Reachable {
			reachableCJs++
		}
	}
	if reachableCJs > 0 {
		recs = append(recs, formatInt(reachableCJs)+" of "+formatInt(len(ap.CrownJewels))+" tagged crown-jewel asset(s) are reachable from at least one endpoint. Place crown jewels in a dedicated, firewall-enforced segment with no direct lateral-movement paths from user VLANs.")
	}
	if n := len(ap.SegmentationViols); n > 0 {
		recs = append(recs, formatInt(n)+" lateral-movement edge(s) cross a network-segment boundary — flat network exposure. Apply micro-segmentation or firewall rules to block SMB (445), WinRM (5985/5986), and RDP (3389) between VLANs that have no operational need to communicate.")
	}
	if len(ap.ChokePoints) > 0 && ap.ChokePoints[0].Coverage > 0.5 {
		cp := ap.ChokePoints[0]
		recs = append(recs, "Choke point '"+cp.Label+"' lies on "+fmt.Sprintf("%.0f%%", cp.Coverage*100)+" of attacker paths to high-value targets. Hardening or removing this single host would eliminate the majority of reachable attack paths — prioritise it for patching, SMB/WinRM lockdown, and local-admin removal.")
	}
	return recs
}

func formatInt(n int) string {
	return fmt.Sprintf("%d", n)
}

// buildDetectionSourcesFromSummary parses a scenario_runs.detection_summary JSON blob
// and returns security products ranked by detection count (descending), with min and
// average time-to-detect per product. Only "detected" verdicts with a named provider
// contribute; prevented/undetected techniques are excluded.
func buildDetectionSourcesFromSummary(raw []byte) []DetectionSource {
	if len(raw) == 0 {
		return nil
	}
	var ds struct {
		Techniques []struct {
			Verdict        string `json:"verdict"`
			TimeToDetectMs int64  `json:"timeToDetectMs"`
			Alert          *struct {
				Provider string `json:"provider"`
			} `json:"alert"`
		} `json:"techniques"`
	}
	if json.Unmarshal(raw, &ds) != nil {
		return nil
	}
	type acc struct {
		count int
		minMs int64
		sumMs int64
	}
	m := map[string]*acc{}
	for _, t := range ds.Techniques {
		if t.Verdict != "detected" || t.Alert == nil || t.Alert.Provider == "" {
			continue
		}
		a, ok := m[t.Alert.Provider]
		if !ok {
			a = &acc{}
			m[t.Alert.Provider] = a
		}
		a.count++
		a.sumMs += t.TimeToDetectMs
		if t.TimeToDetectMs > 0 && (a.minMs == 0 || t.TimeToDetectMs < a.minMs) {
			a.minMs = t.TimeToDetectMs
		}
	}
	if len(m) == 0 {
		return nil
	}
	out := make([]DetectionSource, 0, len(m))
	for product, a := range m {
		var avg int64
		if a.count > 0 {
			avg = a.sumMs / int64(a.count)
		}
		out = append(out, DetectionSource{
			Product:    product,
			Detections: a.count,
			MinMTTDMs:  a.minMs,
			AvgMTTDMs:  avg,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Detections > out[j].Detections
	})
	return out
}

func (e *Engine) populateAttackSurfaceAge(ctx context.Context, report *FullReport, agentID string) {
	var oldestFirstSeen *time.Time
	var oldestTechID, oldestTechName, oldestSeverity string
	err := e.db.QueryRow(ctx,
		`SELECT first_seen, technique_id, technique_name, severity 
		 FROM findings 
		 WHERE agent_id = $1 AND status = 'open' 
		 ORDER BY first_seen ASC LIMIT 1`, agentID,
	).Scan(&oldestFirstSeen, &oldestTechID, &oldestTechName, &oldestSeverity)
	if err != nil {
		report.AttackSurfaceAge = 0
		report.OldestFindingName = ""
		report.OldestFindingID = ""
		report.OldestFindingSeverity = ""
		report.AttackSurfaceSLAStatus = "within-sla"
		return
	}
	if oldestFirstSeen != nil {
		report.AttackSurfaceAge = int(time.Since(*oldestFirstSeen).Hours() / 24)
		report.OldestFindingName = oldestTechName
		report.OldestFindingID = oldestTechID
		report.OldestFindingSeverity = oldestSeverity
		if report.AttackSurfaceAge < 30 {
			report.AttackSurfaceSLAStatus = "within-sla"
		} else if report.AttackSurfaceAge < 90 {
			report.AttackSurfaceSLAStatus = "over-sla"
		} else {
			report.AttackSurfaceSLAStatus = "critical-sla"
		}
	} else {
		report.AttackSurfaceAge = 0
		report.OldestFindingName = ""
		report.OldestFindingID = ""
		report.OldestFindingSeverity = ""
		report.AttackSurfaceSLAStatus = "within-sla"
	}
}

func (e *Engine) populateCampaignAttackSurfaceAge(ctx context.Context, report *FullReport, campaignID string) {
	var oldestFirstSeen *time.Time
	var oldestTechID, oldestTechName, oldestSeverity string
	err := e.db.QueryRow(ctx,
		`SELECT f.first_seen, f.technique_id, f.technique_name, f.severity 
		 FROM findings f
		 JOIN scenario_runs sr ON sr.agent_id = f.agent_id
		 WHERE sr.campaign_id = $1 AND f.status = 'open' 
		 ORDER BY f.first_seen ASC LIMIT 1`, campaignID,
	).Scan(&oldestFirstSeen, &oldestTechID, &oldestTechName, &oldestSeverity)
	if err != nil {
		report.AttackSurfaceAge = 0
		report.OldestFindingName = ""
		report.OldestFindingID = ""
		report.OldestFindingSeverity = ""
		report.AttackSurfaceSLAStatus = "within-sla"
		return
	}
	if oldestFirstSeen != nil {
		report.AttackSurfaceAge = int(time.Since(*oldestFirstSeen).Hours() / 24)
		report.OldestFindingName = oldestTechName
		report.OldestFindingID = oldestTechID
		report.OldestFindingSeverity = oldestSeverity
		if report.AttackSurfaceAge < 30 {
			report.AttackSurfaceSLAStatus = "within-sla"
		} else if report.AttackSurfaceAge < 90 {
			report.AttackSurfaceSLAStatus = "over-sla"
		} else {
			report.AttackSurfaceSLAStatus = "critical-sla"
		}
	} else {
		report.AttackSurfaceAge = 0
		report.OldestFindingName = ""
		report.OldestFindingID = ""
		report.OldestFindingSeverity = ""
		report.AttackSurfaceSLAStatus = "within-sla"
	}
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%.1f", f)
}

func FilterResults(results []models.SimulationResult, filter string) []models.SimulationResult {
	if filter == "" || filter == "all" {
		return results
	}
	var filtered []models.SimulationResult
	for _, r := range results {
		isPrevented := r.Result == models.ResultPass || r.Result == models.ResultBlocked
		isDetected := r.DetectionVerdict == "detected"
		switch filter {
		case "prevented":
			if isPrevented {
				filtered = append(filtered, r)
			}
		case "not_prevented":
			if !isPrevented {
				filtered = append(filtered, r)
			}
		case "detected":
			if isDetected {
				filtered = append(filtered, r)
			}
		case "not_detected":
			if !isDetected {
				filtered = append(filtered, r)
			}
		}
	}
	return filtered
}

// ── Variant Coverage ──────────────────────────────────────────────────────────

// populateVariantCoverage queries scenario_variant_technique_summary for the run
// and populates report.VariantCoverage. No-op when no variant rows exist.
func (e *Engine) populateVariantCoverage(ctx context.Context, report *FullReport, runID string) {
	rows, err := e.db.Query(ctx, `
		SELECT technique_id, COALESCE(technique_name,''), COALESCE(tactic,''),
		       variants_executed, blocked, detected, logged, bypassed, errors,
		       best_bypass_variant_id,
		       COALESCE(encodings_tested,'{}'), COALESCE(contexts_tested,'{}'), COALESCE(privileges_tested,'{}')
		  FROM scenario_variant_technique_summary
		 WHERE run_id = $1
		 ORDER BY bypassed DESC, detected DESC, variants_executed DESC`, runID)
	if err != nil {
		return
	}
	defer rows.Close()

	type summRow struct {
		techID, techName, tactic                         string
		total, blocked, detected, logged, bypassed, errs int
		bestBypassID                                     *string
		encodings, contexts, privileges                  []string
	}

	var summaries []summRow
	var bestIDs []string

	for rows.Next() {
		var s summRow
		if err := rows.Scan(
			&s.techID, &s.techName, &s.tactic,
			&s.total, &s.blocked, &s.detected, &s.logged, &s.bypassed, &s.errs,
			&s.bestBypassID,
			&s.encodings, &s.contexts, &s.privileges,
		); err != nil {
			continue
		}
		summaries = append(summaries, s)
		if s.bestBypassID != nil {
			bestIDs = append(bestIDs, *s.bestBypassID)
		}
	}
	rows.Close()

	if len(summaries) == 0 {
		return
	}

	// Bulk-fetch best bypass variant details (encoding / context / privilege).
	type bypassDetail struct{ enc, execCtx, priv string }
	bestBypassDetails := map[string]bypassDetail{}
	if len(bestIDs) > 0 {
		phs := make([]string, len(bestIDs))
		args := make([]any, len(bestIDs))
		for i, id := range bestIDs {
			phs[i] = fmt.Sprintf("$%d", i+1)
			args[i] = id
		}
		brows, berr := e.db.Query(ctx,
			`SELECT id, encoding, execution_context, privilege
			   FROM scenario_variant_results
			  WHERE id IN (`+strings.Join(phs, ",")+`)`,
			args...,
		)
		if berr == nil {
			defer brows.Close()
			for brows.Next() {
				var id, enc, execCtxCol, priv string
				if brows.Scan(&id, &enc, &execCtxCol, &priv) == nil {
					bestBypassDetails[id] = bypassDetail{enc, execCtxCol, priv}
				}
			}
		}
	}

	sec := &VariantCoverageSection{}
	maturity := VariantMaturityScore{ExecutionTested: true}

	for _, s := range summaries {
		t := VariantTechRow{
			TechniqueID:      s.techID,
			TechniqueName:    s.techName,
			Tactic:           s.tactic,
			VariantsExecuted: s.total,
			Blocked:          s.blocked,
			Detected:         s.detected + s.logged, // merge logged → detected for display
			Bypassed:         s.bypassed,
			HasBypass:        s.bypassed > 0,
		}
		counted := t.Blocked + t.Detected + t.Bypassed
		if counted > 0 {
			t.BypassRate = float64(t.Bypassed) / float64(counted) * 100
		}

		if s.bestBypassID != nil {
			if d, ok := bestBypassDetails[*s.bestBypassID]; ok {
				t.BestBypassLabel = variantBypassLabel(d.enc, d.execCtx, d.priv)
				t.Headline, t.RemediationPoints = variantCoverageRecommendation(s.techID, d.enc, d.execCtx, d.priv)
				t.Severity = variantBypassSeverity(d.priv, d.execCtx)
			}
		}

		// Maturity: track which dimensions were exercised.
		for _, enc := range s.encodings {
			if enc != "plain" {
				maturity.EncodingTested = true
			}
		}
		if len(s.privileges) > 1 || (len(s.privileges) == 1 && s.privileges[0] != "user") {
			maturity.PrivilegeTested = true
		}
		for _, c := range s.contexts {
			if c != "direct" {
				maturity.ProxyTested = true
			}
		}

		sec.TechniquesTotal++
		sec.VariantsExecuted += s.total
		sec.Blocked += t.Blocked
		sec.Detected += t.Detected
		sec.Bypassed += t.Bypassed
		if t.HasBypass {
			sec.TechniquesWithBypass++
		}
		sec.Techniques = append(sec.Techniques, t)
	}

	// Global rates.
	counted := sec.Blocked + sec.Detected + sec.Bypassed
	if counted > 0 {
		sec.BypassRate = float64(sec.Bypassed) / float64(counted) * 100
		sec.PreventionScore = float64(sec.Blocked) / float64(counted) * 100
		nonBlocked := sec.Detected + sec.Bypassed
		if nonBlocked > 0 {
			sec.DetectionScore = float64(sec.Detected) / float64(nonBlocked) * 100
		}
	}

	// First successful bypass timing (relative to run start).
	if len(report.Runs) > 0 {
		var firstBypassAt *time.Time
		if scanErr := e.db.QueryRow(ctx,
			`SELECT MIN(executed_at) FROM scenario_variant_results
			  WHERE run_id = $1 AND verdict = 'bypassed'`, runID,
		).Scan(&firstBypassAt); scanErr == nil && firstBypassAt != nil {
			if elapsed := firstBypassAt.Sub(report.Runs[0].StartedAt); elapsed > 0 {
				mins := int(elapsed.Minutes())
				secs := int(elapsed.Seconds()) % 60
				sec.FirstBypassElapsed = fmt.Sprintf("%dm %ds", mins, secs)
			}
		}
	}

	// Sort: bypass techniques first by severity DESC, then non-bypass by bypassed count.
	sort.Slice(sec.Techniques, func(i, j int) bool {
		ti, tj := sec.Techniques[i], sec.Techniques[j]
		if ti.HasBypass != tj.HasBypass {
			return ti.HasBypass
		}
		if ti.HasBypass {
			return variantSeverityScore(ti.Severity) > variantSeverityScore(tj.Severity)
		}
		return ti.Bypassed > tj.Bypassed
	})

	sec.TrendNote = "No prior variant run on record — trend comparison will be available after the next run."
	sec.Maturity = maturity
	sec.HasData = true
	report.VariantCoverage = sec
}

// variantBypassLabel formats a best-bypass combination as "Charcode + WMI + Admin".
func variantBypassLabel(enc, execCtx, priv string) string {
	var parts []string
	switch enc {
	case "base64":
		parts = append(parts, "Base64")
	case "charcode":
		parts = append(parts, "Charcode")
	}
	switch execCtx {
	case "wmi":
		parts = append(parts, "WMI")
	case "scheduled-task":
		parts = append(parts, "Schtasks")
	case "com":
		parts = append(parts, "COM")
	}
	switch priv {
	case "admin":
		parts = append(parts, "Admin")
	case "system":
		parts = append(parts, "System")
	}
	if len(parts) == 0 {
		return "Plain / Direct"
	}
	return strings.Join(parts, " + ")
}

// variantBypassSeverity derives finding severity from privilege tier and execution context.
// SYSTEM bypass = Critical; Admin = High; User = Medium. WMI/schtasks proxy elevates by one.
func variantBypassSeverity(priv, execCtx string) string {
	score := 1 // default Medium
	switch priv {
	case "system":
		score = 3
	case "admin":
		score = 2
	}
	switch execCtx {
	case "wmi", "scheduled-task":
		if score < 3 {
			score++
		}
	}
	switch score {
	case 3:
		return "Critical"
	case 2:
		return "High"
	case 1:
		return "Medium"
	default:
		return "Low"
	}
}

func variantSeverityScore(s string) int {
	switch s {
	case "Critical":
		return 3
	case "High":
		return 2
	case "Medium":
		return 1
	default:
		return 0
	}
}

// variantCoverageRecommendation returns a headline + remediation bullets for the
// best bypass combination. Mirrors api.coverageRecommendation for the reporting package.
func variantCoverageRecommendation(techID, enc, execCtx, priv string) (headline string, points []string) {
	noun := variantTechExecLang(techID)

	switch execCtx {
	case "wmi":
		headline = fmt.Sprintf("%s via WMI (T1047) was not prevented", noun)
		points = []string{
			"Enable WMI activity auditing (Events 5857–5861, Microsoft-Windows-WMI-Activity/Operational)",
			"Block wmic.exe via AppLocker or WDAC if Win32_Process.Create is not operationally required",
			"Add EDR alert: PowerShell spawning child processes through WMI instead of CreateProcess",
			"Review EDR WMI execution detection rules and verify they are in Block mode (not Audit)",
		}
	case "scheduled-task":
		headline = fmt.Sprintf("%s via Scheduled Task (T1053.005) was not prevented", noun)
		points = []string{
			"Enable Task Scheduler audit logging (Events 4698, 4699, 4702 — Security log)",
			"Alert on schtasks.exe creating tasks with /sc once — strong BAS and malware indicator",
			"Consider AppLocker rules restricting schtasks.exe execution in non-administrative contexts",
			"Review EDR scheduled task detection rules — verify Block mode is active",
		}
	case "com":
		headline = fmt.Sprintf("%s via COM WScript.Shell (T1559.001) was not prevented", noun)
		points = []string{
			"Add EDR rule: alert when WScript.Shell.Run spawns child processes (powershell.exe, cmd.exe)",
			"Enable Script Auditing (Event 4104) to capture WScript-invoked payload content",
			"Review COM object instantiation policy — restrict New-Object -COM WScript.Shell in Constrained Language Mode",
		}
	default:
		switch enc {
		case "base64":
			headline = fmt.Sprintf("%s with Base64 encoding (-EncodedCommand) was not detected", noun)
			points = []string{
				"Enable PowerShell ScriptBlock logging (Event 4104) — decodes base64 transparently",
				"Enable ASR rule: Block execution of potentially obfuscated scripts (GUID 5BEB7EFE)",
				"Ensure AMSI is functioning and not bypassed — base64 payloads are decoded before AMSI inspection",
			}
		case "charcode":
			headline = fmt.Sprintf("%s with charcode obfuscation (IEX([char]N+...)) was not detected", noun)
			points = []string{
				"Enable PowerShell ScriptBlock logging (Event 4104) — charcode is decoded before logging",
				"Deploy PowerShell Constrained Language Mode to restrict arbitrary IEX invocations",
				"Enable ASR rule: Block execution of potentially obfuscated scripts (GUID 5BEB7EFE)",
			}
		default:
			headline = fmt.Sprintf("%s executed without triggering a prevention or detection control", noun)
			points = []string{
				fmt.Sprintf("Review EDR prevention policy coverage for %s", techID),
				"Enable PowerShell Module logging (Event 4103) and ScriptBlock logging (Event 4104)",
				"Verify ASR rules are in Block mode — Audit mode does not prevent execution",
			}
		}
	}

	switch priv {
	case "admin":
		points = append(points,
			"Execution succeeded at local administrator privilege — review privileged access controls and local admin restrictions (LAPS / PAW model)")
	case "system":
		points = append(points,
			"Execution succeeded at SYSTEM privilege — verify privilege escalation path controls and SYSTEM-level execution restrictions")
	}

	return headline, points
}

func variantTechExecLang(techID string) string {
	prefixes := []struct{ prefix, label string }{
		{"T1059.001", "PowerShell execution"},
		{"T1059.003", "Windows Command Shell execution"},
		{"T1059.005", "Visual Basic execution"},
		{"T1059", "Script/command execution"},
		{"T1047", "WMI execution"},
		{"T1053", "Scheduled task execution"},
		{"T1218", "System binary proxy execution"},
		{"T1055", "Process injection"},
	}
	for _, p := range prefixes {
		if strings.HasPrefix(techID, p.prefix) {
			return p.label
		}
	}
	return techID + " execution"
}

// ── Environment Restoration ───────────────────────────────────────────────────

// EnvRestoration summarises how well the simulation cleaned up after itself.
// CleanupRate uses only cleanup-capable steps so a run with few cleanable steps
// cannot inflate the score with "no cleanup needed" steps.
type EnvRestoration struct {
	HasData          bool    `json:"hasData"`
	StepsTotal       int     `json:"stepsTotal"`
	StepsWithCleanup int     `json:"stepsWithCleanup"`
	StepsCleaned     int     `json:"stepsCleaned"`
	StepsLeaked      int     `json:"stepsLeaked"`
	StepsRescued     int     `json:"stepsRescued,omitempty"` // subset of StepsCleaned that a step's own script failed to clean, later confirmed removed by the whole-run safety net
	StepsNoCleanup   int     `json:"stepsNoCleanup"`
	RevertedCount    int     `json:"revertedCount"`
	CleanupRate      float64 `json:"cleanupRate"`  // stepsCleaned/(cleaned+leaked)*100
	CoverageRate     float64 `json:"coverageRate"` // stepsWithCleanup/stepsTotal*100
	ImpactLevel      string  `json:"impactLevel"`  // "clean"|"minor"|"persistent"
	ImpactLabel      string  `json:"impactLabel"`
	StatusLabel      string  `json:"statusLabel"` // "Successful"|"Attention Required"|"Failed"
	ExecSummary      string  `json:"execSummary"`
	// Campaign-level breakdown (zero for run reports)
	RunCount       int `json:"runCount,omitempty"`
	RunsClean      int `json:"runsClean,omitempty"`
	RunsWithIssues int `json:"runsWithIssues,omitempty"`
}

// revertedKeyPrefixes maps each human-readable prefix revertFromSnapshot
// writes into a run's reverted[] log (agent/snapshot_windows.go,
// agent/snapshot_posix.go) back to the normalized key format diffSnapshots
// uses for CleanupResidual, so a step's residual keys can be cross-referenced
// against what the whole-run safety net actually confirmed removing.
var revertedKeyPrefixes = []struct{ from, to string }{
	{"tmp removed: ", "tmp:"},
	{"registry removed: ", "registry:"},
	{"schtask deleted: ", "schtask:"},
	{"service stopped: ", "service:"},
	{"startup removed: ", "startup:"},
	{"cron removed: ", "cron:"},
	{"file restored: ", ""},
}

// normalizeReverted maps one reverted[] log entry to its normalized
// CleanupResidual-format key. ok is false for an entry with no known mapping
// ("crontab: user crontab restored", "iptables: rules restored" — fixed
// literal log lines handled as exact-match special cases below, and anything
// else unrecognized) — those never match a residual key, so the step they
// might relate to is conservatively left at its raw verdict rather than
// guessed as rescued.
func normalizeReverted(entry string) (key string, ok bool) {
	switch entry {
	case "crontab: user crontab restored":
		return "crontab:user", true
	case "iptables: rules restored":
		return "iptables", true
	}
	for _, p := range revertedKeyPrefixes {
		if strings.HasPrefix(entry, p.from) {
			return p.to + strings.TrimPrefix(entry, p.from), true
		}
	}
	return "", false
}

// normalizeRevertedSet builds a lookup set of every reverted[] entry this
// run's whole-run safety net logged, in normalized-key form.
func normalizeRevertedSet(reverted []string) map[string]bool {
	set := make(map[string]bool, len(reverted))
	for _, entry := range reverted {
		if key, ok := normalizeReverted(entry); ok {
			set[key] = true
		}
	}
	return set
}

// buildEnvRestoration computes Environment Restoration metrics from the
// per-step cleanup verdicts already present in the TechniqueMatrix.
func buildEnvRestoration(matrix []TechniqueRow, reverted []string) EnvRestoration {
	revertedSet := normalizeRevertedSet(reverted)
	for i := range matrix {
		if matrix[i].CleanupVerdict != "leaked" && matrix[i].CleanupVerdict != "partial" {
			continue
		}
		for _, key := range matrix[i].CleanupResidual {
			if revertedSet[key] {
				matrix[i].CleanupVerdict = "rescued"
				break
			}
		}
	}

	e := EnvRestoration{
		StepsTotal:    len(matrix),
		RevertedCount: len(reverted),
	}
	for _, r := range matrix {
		switch r.CleanupVerdict {
		case "reverted":
			e.StepsWithCleanup++
			e.StepsCleaned++
		case "rescued":
			e.StepsWithCleanup++
			e.StepsCleaned++
			e.StepsRescued++
		case "partial", "leaked":
			e.StepsWithCleanup++
			e.StepsLeaked++
		default:
			e.StepsNoCleanup++
		}
	}

	// Cleanup Success Rate — denominator excludes steps with no cleanup defined.
	cleanTotal := e.StepsCleaned + e.StepsLeaked
	if cleanTotal == 0 {
		e.CleanupRate = 100.0
	} else {
		e.CleanupRate = float64(e.StepsCleaned) / float64(cleanTotal) * 100
	}
	if e.StepsTotal > 0 {
		e.CoverageRate = float64(e.StepsWithCleanup) / float64(e.StepsTotal) * 100
	}

	switch {
	case e.StepsLeaked == 0:
		e.ImpactLevel = "clean"
		e.ImpactLabel = "No Persistent Changes"
		e.StatusLabel = "Successful"
		if e.StepsCleaned > 0 {
			e.ExecSummary = fmt.Sprintf("All %d simulation-induced changes were reverted. No persistent modifications remain on the endpoint.", e.StepsCleaned)
		} else {
			e.ExecSummary = "No environment changes required cleanup. Simulation left no persistent modifications."
		}
	case e.StepsLeaked <= 3:
		e.ImpactLevel = "minor"
		e.ImpactLabel = fmt.Sprintf("Minor Residual Changes (%d)", e.StepsLeaked)
		e.StatusLabel = "Attention Required"
		e.ExecSummary = fmt.Sprintf("%d simulation change(s) were not successfully reverted and may remain on the endpoint.", e.StepsLeaked)
	default:
		e.ImpactLevel = "persistent"
		e.ImpactLabel = fmt.Sprintf("Persistent Changes Detected (%d)", e.StepsLeaked)
		e.StatusLabel = "Failed"
		e.ExecSummary = fmt.Sprintf("%d simulation changes were not reverted. Manual endpoint remediation is required.", e.StepsLeaked)
	}

	if e.StepsRescued > 0 {
		e.ExecSummary += fmt.Sprintf(" %d of these were cleaned by the safety-net sweep, not by their own script.", e.StepsRescued)
	}

	e.HasData = e.StepsTotal > 0
	return e
}

// ── KEV Exposure ──────────────────────────────────────────────────────────────

// populateKEVExposure batch-queries technique_cve_relationships+cves to
// determine which techniques in the report have active CISA KEV CVEs,
// classifies each by control outcome, and enriches report.TopFindings with KEV
// flags. Only Active relationships with High/Medium effective confidence count
// — a Low-confidence (analyst hypothesis) link never inflates exposure. Silent
// no-op when the cves table is empty (KEV file not loaded).
func (e *Engine) populateKEVExposure(ctx context.Context, report *FullReport) {
	if len(report.TechniqueMatrix) == 0 {
		return
	}
	ids := make([]string, 0, len(report.TechniqueMatrix))
	seen := map[string]bool{}
	for _, r := range report.TechniqueMatrix {
		if r.TechniqueID != "" && !seen[r.TechniqueID] {
			ids = append(ids, r.TechniqueID)
			seen[r.TechniqueID] = true
		}
	}
	if len(ids) == 0 {
		return
	}

	type kevRow struct {
		count      int
		ransomware bool
	}
	kevMap := map[string]kevRow{}

	rows, err := e.db.Query(ctx, `
		SELECT tc.technique_id, COUNT(DISTINCT tc.cve_id) AS kev_count, bool_or(c.known_ransomware) AS ransomware
		FROM technique_cve_relationships tc
		JOIN cves c ON c.cve_id = tc.cve_id AND c.source = 'cisa-kev'
		WHERE tc.technique_id = ANY($1) AND tc.status = 'Active' AND tc.effective_confidence IN ('High','Medium')
		GROUP BY tc.technique_id`, ids)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid string
		var cnt int
		var rw bool
		if err := rows.Scan(&tid, &cnt, &rw); err != nil {
			continue
		}
		kevMap[tid] = kevRow{count: cnt, ransomware: rw}
	}
	if rows.Err() != nil || len(kevMap) == 0 {
		return
	}

	// First verdict seen for each technique (matrix is newest-run-first ordered).
	verdicts := map[string]string{}
	tacticOf := map[string]string{}
	nameOf := map[string]string{}
	for _, row := range report.TechniqueMatrix {
		if _, done := verdicts[row.TechniqueID]; !done {
			verdicts[row.TechniqueID] = row.ExecVerdict
			tacticOf[row.TechniqueID] = row.Tactic
			nameOf[row.TechniqueID] = row.TechniqueName
		}
	}

	exp := KEVExposure{HasData: true}
	for techID, kr := range kevMap {
		v := verdicts[techID]
		if v == "error" || v == "skipped" {
			continue
		}
		exp.TotalKEVTechs++
		if kr.ransomware {
			exp.RansomwareLinked++
		}
		if v == "fail" {
			exp.KEVFailed++
			exp.FailedTechs = append(exp.FailedTechs, KEVTechSummary{
				TechniqueID:      techID,
				Name:             nameOf[techID],
				Tactic:           tacticOf[techID],
				KEVCount:         kr.count,
				RansomwareLinked: kr.ransomware,
				Verdict:          v,
			})
		} else {
			exp.KEVPassed++
		}
	}
	if exp.TotalKEVTechs == 0 {
		return
	}
	sort.SliceStable(exp.FailedTechs, func(i, j int) bool {
		if exp.FailedTechs[i].RansomwareLinked != exp.FailedTechs[j].RansomwareLinked {
			return exp.FailedTechs[i].RansomwareLinked
		}
		return exp.FailedTechs[i].KEVCount > exp.FailedTechs[j].KEVCount
	})
	report.KEVExposure = &exp

	// Enrich TopFindings with KEV flags.
	for i := range report.TopFindings {
		if kr, ok := kevMap[report.TopFindings[i].TechniqueID]; ok {
			report.TopFindings[i].KEV = true
			report.TopFindings[i].KEVCount = kr.count
		}
	}
}

// populateThreatIntel joins run_iocs with ioc_enrichment for the configured
// provider and classifies each indicator into an honest, non-"confidence"
// tier based on raw pulse count. Leaves report.ThreatIntel nil when no
// provider is configured or the run has no extracted IOCs.
func (e *Engine) populateThreatIntel(ctx context.Context, report *FullReport, runID string) {
	if e.threatIntelProvider == "" {
		return
	}
	rows, err := e.db.Query(ctx, `
		SELECT ri.indicator_type, ri.indicator_value, ri.technique_ids, ri.simulation_ids,
		       ie.pulse_count, ie.pulse_names, ie.malware_families, ie.adversary_names,
		       ie.industries, ie.tags, ie.last_success_at
		FROM run_iocs ri
		LEFT JOIN ioc_enrichment ie
		  ON ie.indicator_type = ri.indicator_type
		 AND ie.indicator_value = ri.indicator_value
		 AND ie.provider = $2
		WHERE ri.run_id = $1`, runID, e.threatIntelProvider)
	if err != nil {
		return
	}
	defer rows.Close()

	var allIndicators []ThreatIntelIndicator
	var extracted, pending, unknown, suspicious, malicious int
	for rows.Next() {
		var techniqueIDsJSON, simulationIDsJSON []byte
		var pulseNamesJSON, malwareJSON, adversaryJSON, industriesJSON, tagsJSON []byte
		var pulseCount *int
		var lastSuccessAt *time.Time
		var ind ThreatIntelIndicator
		if err := rows.Scan(&ind.Type, &ind.Value, &techniqueIDsJSON, &simulationIDsJSON,
			&pulseCount, &pulseNamesJSON, &malwareJSON, &adversaryJSON, &industriesJSON, &tagsJSON,
			&lastSuccessAt); err != nil {
			continue
		}
		_ = json.Unmarshal(techniqueIDsJSON, &ind.TechniqueIDs)
		_ = json.Unmarshal(simulationIDsJSON, &ind.SimulationIDs)

		extracted++
		// No row at all (pulseCount nil), or a row that only ever recorded
		// failures (lastSuccessAt nil) -- either way we have no confirmed
		// pulse data to show, so this indicator is "pending", not "unknown".
		if pulseCount == nil || lastSuccessAt == nil {
			ind.Tier = "pending"
			pending++
		} else {
			ind.PulseCount = *pulseCount
			_ = json.Unmarshal(pulseNamesJSON, &ind.PulseNames)
			_ = json.Unmarshal(malwareJSON, &ind.MalwareFamilies)
			_ = json.Unmarshal(adversaryJSON, &ind.AdversaryNames)
			_ = json.Unmarshal(industriesJSON, &ind.Industries)
			_ = json.Unmarshal(tagsJSON, &ind.Tags)
			switch {
			case ind.PulseCount >= 3:
				ind.Tier = "malicious-associated"
				malicious++
			case ind.PulseCount >= 1:
				ind.Tier = "suspicious"
				suspicious++
			default:
				ind.Tier = "unknown"
				unknown++
			}
		}
		allIndicators = append(allIndicators, ind)
	}
	if extracted == 0 {
		return
	}

	tierRank := map[string]int{"malicious-associated": 0, "suspicious": 1, "unknown": 2, "pending": 3}
	sort.Slice(allIndicators, func(i, j int) bool {
		return tierRank[allIndicators[i].Tier] < tierRank[allIndicators[j].Tier]
	})

	report.ThreatIntel = &ThreatIntelSection{
		Provider: e.threatIntelProvider,
		Summary: ThreatIntelSummary{
			ExtractedCount:           extracted,
			PendingCount:             pending,
			UnknownCount:             unknown,
			SuspiciousCount:          suspicious,
			MaliciousAssociatedCount: malicious,
		},
		Indicators: allIndicators,
	}
}

// ── EPSS Priority Scores ──────────────────────────────────────────────────────

// populatePriorityScores computes a composite priority for each tested technique
// using KEV flag (from DB), EPSS score (from cve_epss via
// technique_cve_relationships), and ATT&CK threat-actor count (from embedded
// STIX). Only Active relationships with High/Medium effective confidence
// contribute — a Low-confidence (illustrative) link is shown in the report but
// never moves this score. Techniques with no signal and verdict != fail are
// omitted. Silent no-op when the cve_epss table is empty.
func (e *Engine) populatePriorityScores(ctx context.Context, report *FullReport) {
	if len(report.TechniqueMatrix) == 0 {
		return
	}

	ids := make([]string, 0, len(report.TechniqueMatrix))
	seen := map[string]bool{}
	for _, r := range report.TechniqueMatrix {
		tid := strings.ToUpper(r.TechniqueID)
		if tid != "" && !seen[tid] {
			ids = append(ids, r.TechniqueID) // preserve original case for DB query
			seen[tid] = true
		}
	}
	if len(ids) == 0 {
		return
	}

	// KEV count per technique
	kevMap := map[string]int{}
	if rows, err := e.db.Query(ctx, `
		SELECT tc.technique_id, COUNT(DISTINCT tc.cve_id) AS cnt
		FROM technique_cve_relationships tc
		JOIN cves c ON c.cve_id = tc.cve_id AND c.source = 'cisa-kev'
		WHERE tc.technique_id = ANY($1) AND tc.status = 'Active' AND tc.effective_confidence IN ('High','Medium')
		GROUP BY tc.technique_id`, ids); err == nil {
		for rows.Next() {
			var tid string
			var cnt int
			if rows.Scan(&tid, &cnt) == nil {
				kevMap[strings.ToUpper(tid)] = cnt
			}
		}
		rows.Close()
	}

	// EPSS max score + percentile per technique (via technique_cve_relationships → cve_epss)
	type epssData struct{ score, pct float64 }
	epssMap := map[string]epssData{}
	if rows, err := e.db.Query(ctx, `
		SELECT tc.technique_id, MAX(ce.epss_score), MAX(ce.percentile)
		FROM technique_cve_relationships tc
		JOIN cve_epss ce ON ce.cve_id = tc.cve_id
		WHERE tc.technique_id = ANY($1) AND tc.status = 'Active' AND tc.effective_confidence IN ('High','Medium')
		GROUP BY tc.technique_id`, ids); err == nil {
		for rows.Next() {
			var tid string
			var sc, pct float64
			if rows.Scan(&tid, &sc, &pct) == nil {
				epssMap[strings.ToUpper(tid)] = epssData{sc, pct * 100}
			}
		}
		rows.Close()
	}

	// Relationship count + primary source per technique — provenance for the
	// scored CVEs behind KEV/EPSS, so the report can say why a ranking exists.
	type relProv struct {
		count   int
		primary string
	}
	relMap := map[string]relProv{}
	if rows, err := e.db.Query(ctx, `
		SELECT technique_id, COUNT(*), MAX(primary_source)
		FROM technique_cve_relationships
		WHERE technique_id = ANY($1) AND status = 'Active' AND effective_confidence IN ('High','Medium')
		GROUP BY technique_id`, ids); err == nil {
		for rows.Next() {
			var tid, primary string
			var cnt int
			if rows.Scan(&tid, &cnt, &primary) == nil {
				relMap[strings.ToUpper(tid)] = relProv{cnt, primary}
			}
		}
		rows.Close()
	}

	// Threat actor count per technique from embedded STIX (already loaded)
	actorIdx := attackdata.GroupTechniqueIndex()
	actorCount := make(map[string]int, len(ids))
	for _, techIDs := range actorIdx {
		for _, tid := range techIDs {
			actorCount[strings.ToUpper(tid)]++
		}
	}

	// Sector/region relevance — see
	// docs/superpowers/specs/2026-07-19-sp5-sector-region-weighting-design.md.
	// Returns an empty map immediately (no query) when neither is configured.
	sectorRegionRelevant, err := SectorRegionRelevantTechniques(ctx, e.db, e.sectors, e.regions)
	if err != nil {
		log.Printf("[reporting] sector/region relevance lookup: %v", err)
		sectorRegionRelevant = map[string]bool{}
	}

	// First verdict per technique (matrix is newest-run-first ordered)
	verdicts := map[string]string{}
	nameOf := map[string]string{}
	tacticOf := map[string]string{}
	for _, row := range report.TechniqueMatrix {
		tid := strings.ToUpper(row.TechniqueID)
		if _, done := verdicts[tid]; !done {
			verdicts[tid] = row.ExecVerdict
			nameOf[tid] = row.TechniqueName
			tacticOf[tid] = row.Tactic
		}
	}

	var priorities []TechniquePriority
	for tid, verdict := range verdicts {
		if verdict == "error" || verdict == "skipped" {
			continue
		}
		kevCnt := kevMap[tid]
		ep := epssMap[tid]
		actors := actorCount[tid]
		score := ComputePriorityScore(kevCnt > 0, ep.pct, actors, verdict, sectorRegionRelevant[tid])
		if score == 0 && verdict != "fail" {
			continue // passed with no signal — no actionable output
		}
		rp := relMap[tid]
		priorities = append(priorities, TechniquePriority{
			TechniqueID:       tid,
			Name:              nameOf[tid],
			Tactic:            tacticOf[tid],
			Verdict:           verdict,
			KEV:               kevCnt > 0,
			KEVCount:          kevCnt,
			EPSSScore:         ep.score,
			EPSSPercentile:    ep.pct,
			ThreatActorCount:  actors,
			PriorityScore:     score,
			PriorityTier:      PriorityTierFor(score),
			RelationshipCount: rp.count,
			PrimarySource:     rp.primary,
		})
	}
	if len(priorities) == 0 {
		return
	}

	sort.Slice(priorities, func(i, j int) bool {
		if priorities[i].PriorityScore != priorities[j].PriorityScore {
			return priorities[i].PriorityScore > priorities[j].PriorityScore
		}
		if priorities[i].Verdict != priorities[j].Verdict {
			return priorities[i].Verdict == "fail"
		}
		return priorities[i].TechniqueID < priorities[j].TechniqueID
	})
	report.PriorityScores = priorities
}

// ── Historical Readiness Trends ───────────────────────────────────────────────

// enrichReadinessTrends looks up the most recent prior measurement for each
// actor in the threat_readiness_history table and fills HasTrend, TrendDirection,
// PreventionDelta, and DetectionDelta in place. excludeRunID is the current run
// being reported (excluded so we compare to the PREVIOUS run, not ourselves).
// Silent no-op on any DB error so a missing table never breaks report generation.
func (e *Engine) enrichReadinessTrends(ctx context.Context, agentID string, scores []ReadinessScore, excludeRunID string) {
	if agentID == "" || len(scores) == 0 {
		return
	}
	for i, s := range scores {
		var prevPrev, prevDet float64
		var err error
		if excludeRunID != "" {
			err = e.db.QueryRow(ctx, `
				SELECT prevention, detection
				FROM threat_readiness_history
				WHERE agent_id = $1 AND actor_name = $2 AND run_id != $3
				ORDER BY recorded_at DESC
				LIMIT 1`, agentID, s.GroupName, excludeRunID,
			).Scan(&prevPrev, &prevDet)
		} else {
			err = e.db.QueryRow(ctx, `
				SELECT prevention, detection
				FROM threat_readiness_history
				WHERE agent_id = $1 AND actor_name = $2
				ORDER BY recorded_at DESC
				LIMIT 1`, agentID, s.GroupName,
			).Scan(&prevPrev, &prevDet)
		}
		if err != nil {
			continue // no history yet
		}
		delta := s.PreventionReadiness - prevPrev
		detDelta := s.DetectionReadiness - prevDet
		dir := "stable"
		if delta > 1 {
			dir = "up"
		} else if delta < -1 {
			dir = "down"
		}
		scores[i].HasTrend = true
		scores[i].TrendDirection = dir
		scores[i].PreventionDelta = math.Round(delta*10) / 10
		scores[i].DetectionDelta = math.Round(detDelta*10) / 10
		scores[i].PrevPreventionReadiness = prevPrev
		scores[i].PrevDetectionReadiness = prevDet
	}
}

// persistReadinessHistory upserts the current readiness measurements into
// threat_readiness_history. ON CONFLICT DO NOTHING ensures re-generating a
// report for the same run never overwrites the original measurement.
func (e *Engine) persistReadinessHistory(ctx context.Context, runID, agentID string, scores []ReadinessScore) {
	if runID == "" || agentID == "" || len(scores) == 0 {
		return
	}
	batch := &pgx.Batch{}
	for _, s := range scores {
		batch.Queue(`
			INSERT INTO threat_readiness_history
				(run_id, agent_id, actor_name, prevention, detection, tested, total, confidence)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (run_id, actor_name) DO NOTHING`,
			runID, agentID, s.GroupName,
			s.PreventionReadiness, s.DetectionReadiness,
			s.TestedTechs, s.TotalTechs, s.ConfidenceBand)
	}
	br := e.db.SendBatch(ctx, batch)
	for range scores {
		br.Exec() //nolint:errcheck — history write is best-effort
	}
	br.Close()
}

// ── Campaign Variant Coverage ─────────────────────────────────────────────────

// populateCampaignVariantCoverage reads from campaign_variant_summary (pre-computed
// by refreshCampaignVariantSummary) and populates report.CampaignVariantCoverage.
// No-op when no variant data exists for the campaign.
func (e *Engine) populateCampaignVariantCoverage(ctx context.Context, report *FullReport, campaignID string) {
	var techTested, varExec, blocked, detected, bypassed, runCount int
	var prevScore, detScore float64
	var topBypassesRaw, tacticRaw []byte
	var prevBypassed *int

	if err := e.db.QueryRow(ctx, `
		SELECT techniques_tested, variants_executed, blocked, detected, bypassed, run_count,
		       prevention_score, detection_score, top_bypasses, tactic_breakdown, prev_bypassed
		  FROM campaign_variant_summary
		 WHERE campaign_id = $1`, campaignID,
	).Scan(&techTested, &varExec, &blocked, &detected, &bypassed, &runCount,
		&prevScore, &detScore, &topBypassesRaw, &tacticRaw, &prevBypassed,
	); err != nil || techTested == 0 {
		return
	}

	sec := &CampaignVariantSection{
		HasData:          true,
		TechniquesTested: techTested,
		VariantsExecuted: varExec,
		Blocked:          blocked,
		Detected:         detected,
		Bypassed:         bypassed,
		RunCount:         runCount,
		PreventionScore:  prevScore,
		DetectionScore:   detScore,
	}

	if len(topBypassesRaw) > 0 {
		json.Unmarshal(topBypassesRaw, &sec.TopBypasses)
	}
	if len(tacticRaw) > 0 {
		json.Unmarshal(tacticRaw, &sec.TacticBreakdown)
	}

	if prevBypassed != nil {
		sec.HasTrend = true
		sec.PrevBypassed = *prevBypassed
		delta := bypassed - *prevBypassed
		sec.TrendDelta = delta
		if delta < 0 {
			sec.TrendImproved = true
			if *prevBypassed > 0 {
				sec.ImprovementPct = float64(-delta) / float64(*prevBypassed) * 100
				sec.TrendNote = fmt.Sprintf("Improved %.0f%% — %d fewer bypassed technique(s) vs previous campaign (%d → %d)",
					sec.ImprovementPct, -delta, *prevBypassed, bypassed)
			} else {
				sec.TrendNote = fmt.Sprintf("Improved — %d fewer bypassed technique(s) vs previous campaign", -delta)
			}
		} else if delta > 0 {
			sec.TrendNote = fmt.Sprintf("Regression — %d more bypassed technique(s) vs previous campaign (%d → %d)",
				delta, *prevBypassed, bypassed)
		} else {
			sec.TrendNote = "No change vs previous campaign"
		}
	} else {
		sec.TrendNote = "No prior campaign on record — trend will be available after the next campaign."
	}

	report.CampaignVariantCoverage = sec
}
