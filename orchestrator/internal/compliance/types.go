package compliance

import "time"

// FrameworkMeta is the public metadata for a compliance framework.
type FrameworkMeta struct {
	ID            string `json:"id"            yaml:"id"`
	Name          string `json:"name"          yaml:"name"`
	Version       string `json:"version"       yaml:"version"`
	Regulator     string `json:"regulator"     yaml:"regulator"`
	PublishedYear string `json:"publishedYear" yaml:"published_year"`
	TotalControls int    `json:"totalControls"`
	// MappingWarning is shown wherever this framework's figures are shown. It is set when the control-to-technique
	// mapping is known to be unverified against the regulator's primary text.
	MappingWarning string `json:"mappingWarning,omitempty" yaml:"mapping_warning"`
}

// FrameworkDef is the full parsed YAML for a framework (meta + control list).
type FrameworkDef struct {
	FrameworkMeta `yaml:",inline"`
	Controls      []ControlDef `yaml:"controls"`
}

// ControlDef is a single control entry from the mapping YAML.
type ControlDef struct {
	ID         string   `yaml:"id"`
	Name       string   `yaml:"name"`
	Domain     string   `yaml:"domain"`
	Category   string   `yaml:"category"`
	Techniques []string `yaml:"techniques"` // MITRE technique IDs (base or sub)
	// Reference cites where the regulator's text states the requirement, for example "¶110, ¶114". Empty when the
	// framework's mapping has not been reviewed against the source.
	Reference string `yaml:"reference"`
	// Testable marks whether a control's posture can be validated by executing
	// the mapped ATT&CK techniques. Governance/process/policy controls (board
	// policy, asset inventory, risk-assessment cadence, data residency, IR/DR
	// planning) CANNOT be proven by running an attack — they require manual
	// attestation. Omitted/nil ⇒ true (the technical-control default).
	Testable *bool `yaml:"testable"`
	// Architectures lists the framework's architecture types a control applies to (SWIFT CSCF: A1, A2, A3, A4, B).
	// Empty for frameworks without architecture types.
	Architectures []string `yaml:"architectures"`
	// AdvisoryFor lists the architecture types for which a control is advisory rather than mandatory.
	AdvisoryFor []string `yaml:"advisory_for"`
}

// IsTestable reports whether the control is BAS-testable (default true).
func (c ControlDef) IsTestable() bool { return c.Testable == nil || *c.Testable }

// ComplianceReport is the full output for one framework + one scenario run.
type ComplianceReport struct {
	Framework    FrameworkMeta     `json:"framework"`
	AgentID      string            `json:"agentId"`
	RunID        string            `json:"runId"`
	ScenarioName string            `json:"scenarioName"`
	GeneratedAt  time.Time         `json:"generatedAt"`
	Narrative    string            `json:"narrative"`
	Summary      ComplianceSummary `json:"summary"`
	Domains      []DomainResult    `json:"domains"`
	Controls     []ControlResult   `json:"controls"`
}

// ComplianceSummary holds the top-level aggregate numbers.
//
// TotalControls counts every control in the framework. Of those, TestableControls
// are BAS-validatable and ManualControls require manual attestation. The tested/
// passing/failing/untested tallies and both percentages are computed over the
// TESTABLE subset only — manual controls are never scored as pass/fail.
//
// These are results of simulated attack techniques, not a determination of compliance. Control status is derived from
// technique-level evidence (see ControlResult.Status); the raw execution results are never changed. The legacy field
// names are kept so stored snapshots, history and the risk score keep their meaning:
//
//	TestedControls    controls where at least one mapped technique ran and gave a result (resisted + partial + failed)
//	PassingControls   tested controls where no executed technique succeeded (resisted + partial)
//	FailingControls   controls where at least one executed technique succeeded
//	UntestedControls  testable controls with no executed technique (untested + inconclusive)
//	CompliancePercent the RESISTANCE RATE: PassingControls / TestedControls. It says nothing about the controls that
//	                  were not tested, so it must always be shown with CoveragePercent.
type ComplianceSummary struct {
	TotalControls     int     `json:"totalControls"`
	TestableControls  int     `json:"testableControls"`
	ManualControls    int     `json:"manualControls"`
	TestedControls    int     `json:"testedControls"`
	PassingControls   int     `json:"passingControls"`
	FailingControls   int     `json:"failingControls"`
	UntestedControls  int     `json:"untestedControls"`
	CoveragePercent   float64 `json:"coveragePct"`   // TestedControls / TestableControls * 100
	CompliancePercent float64 `json:"compliancePct"` // the resistance rate: PassingControls / TestedControls * 100

	ResistedControls     int `json:"resistedControls"`     // every mapped technique ran and none succeeded
	PartialControls      int `json:"partialControls"`      // some, not all, mapped techniques ran; none succeeded
	InconclusiveControls int `json:"inconclusiveControls"` // nothing ran cleanly, but steps errored or were vetoed

	TechniquesMapped         int     `json:"techniquesMapped"` // summed over testable controls
	TechniquesTested         int     `json:"techniquesTested"`
	TechniqueCoveragePercent float64 `json:"techniqueCoveragePct"`

	// SufficientCoverage is false while CoveragePercent is below MinConclusiveCoveragePercent. CoverageNote then says
	// so and must be shown beside the resistance rate.
	SufficientCoverage bool   `json:"sufficientCoverage"`
	CoverageNote       string `json:"coverageNote,omitempty"`
}

// MinConclusiveCoveragePercent is the share of a framework's testable controls that must have been tested before a
// framework-level conclusion is reasonable. Below it the report says coverage is insufficient. It is a judgment, not a
// regulatory figure.
const MinConclusiveCoveragePercent = 50.0

// InsufficientCoverageNote is the wording shown beside a resistance rate that rests on too little testing.
const InsufficientCoverageNote = "Insufficient coverage for framework-level conclusions"

// DomainResult is the per-domain (e.g. "Protect") aggregate.
type DomainResult struct {
	Name          string  `json:"name"`
	Total         int     `json:"total"`
	Passing       int     `json:"passing"` // tested with no executed technique succeeding (resisted + partial)
	Failing       int     `json:"failing"`
	Untested      int     `json:"untested"` // untested + inconclusive
	Manual        int     `json:"manual"`
	CompliancePct float64 `json:"compliancePct"` // the domain's resistance rate

	Resisted     int `json:"resisted"`
	Partial      int `json:"partial"`
	Inconclusive int `json:"inconclusive"` // included in Untested
}

// ControlResult is the per-control detail with evidence from BAS results.
type ControlResult struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	Category  string `json:"category"`
	Testable  bool   `json:"testable"`
	Reference string `json:"reference,omitempty"` // where the regulator's text states the requirement
	// Status is derived from technique-level evidence: resisted | failed | partial | inconclusive | untested | manual.
	Status   string              `json:"status"`
	Tested   int                 `json:"tested"` // execution results that gave a verdict (not techniques)
	Passed   int                 `json:"passed"`
	Failed   int                 `json:"failed"`
	Evidence []TechniqueEvidence `json:"evidence"`

	TechniquesMapped       int                 `json:"techniquesMapped"`
	TechniquesTested       int                 `json:"techniquesTested"`
	TechniquesFailed       int                 `json:"techniquesFailed"`
	TechniquesInconclusive int                 `json:"techniquesInconclusive"`
	TechniqueCoverage      []TechniqueCoverage `json:"techniqueCoverage"`
}

// TechniqueCoverage is one mapped technique and what the executed results say about it.
type TechniqueCoverage struct {
	ID    string `json:"id"`
	State string `json:"state"` // resisted | failed | inconclusive | untested
}

// TechniqueEvidence links a BAS result to a compliance control.
type TechniqueEvidence struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	Result        string `json:"result"`
	Details       string `json:"details"`
	Remediation   string `json:"remediation"`
}
