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
}

// ComplianceReport is the full output for one framework + one scenario run.
type ComplianceReport struct {
	Framework    FrameworkMeta     `json:"framework"`
	AgentID      string            `json:"agentId"`
	RunID        string            `json:"runId"`
	ScenarioName string            `json:"scenarioName"`
	GeneratedAt  time.Time         `json:"generatedAt"`
	Summary      ComplianceSummary `json:"summary"`
	Domains      []DomainResult    `json:"domains"`
	Controls     []ControlResult   `json:"controls"`
}

// ComplianceSummary holds the top-level aggregate numbers.
type ComplianceSummary struct {
	TotalControls     int     `json:"totalControls"`
	TestedControls    int     `json:"testedControls"`
	PassingControls   int     `json:"passingControls"`
	FailingControls   int     `json:"failingControls"`
	UntestedControls  int     `json:"untestedControls"`
	CoveragePercent   float64 `json:"coveragePct"`   // TestedControls / TotalControls * 100
	CompliancePercent float64 `json:"compliancePct"` // PassingControls / TestedControls * 100
}

// DomainResult is the per-domain (e.g. "Protect") aggregate.
type DomainResult struct {
	Name          string  `json:"name"`
	Total         int     `json:"total"`
	Passing       int     `json:"passing"`
	Failing       int     `json:"failing"`
	Untested      int     `json:"untested"`
	CompliancePct float64 `json:"compliancePct"`
}

// ControlResult is the per-control detail with evidence from BAS results.
type ControlResult struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Domain   string              `json:"domain"`
	Category string              `json:"category"`
	Status   string              `json:"status"` // pass | fail | untested
	Tested   int                 `json:"tested"`
	Passed   int                 `json:"passed"`
	Failed   int                 `json:"failed"`
	Evidence []TechniqueEvidence `json:"evidence"`
}

// TechniqueEvidence links a BAS result to a compliance control.
type TechniqueEvidence struct {
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	Result        string `json:"result"`
	Details       string `json:"details"`
	Remediation   string `json:"remediation"`
}
