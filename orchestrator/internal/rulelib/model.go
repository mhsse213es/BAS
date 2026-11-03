// Package rulelib is the Detection Rule Library (SP2) — a curated,
// technique-indexed set of Sigma detection rules translated into 5 vendor
// query languages, embedded into the orchestrator binary at build time. See
// docs/superpowers/specs/2026-07-14-detection-rule-library-design.md.
//
// This package does no I/O beyond the embedded JSON — the content is
// generated offline by scripts/rulelib-gen (Python) and committed to git.
package rulelib

// Rule is one curated detection rule: its Sigma content plus every backend
// translation that converted successfully.
type Rule struct {
	ID             string    `json:"id"`      // stable, Audspect-owned: "AUDRULE-000001"
	SigmaID        string    `json:"sigmaId"` // upstream Sigma rule UUID — traceability only
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	TechniqueIDs   []string  `json:"techniqueIds"`
	Severity       string    `json:"severity"`
	Status         string    `json:"status"`
	Author         string    `json:"author"`
	References     []string  `json:"references"`
	FalsePositives []string  `json:"falsePositives"`
	LogSource      LogSource `json:"logSource"`
	Detection      string    `json:"detection"` // raw Sigma YAML, verbatim
	// Tags, Date and Modified are the upstream rule's own, unchanged (ATT&CK and other tags as written).
	Tags     []string `json:"tags"`
	Date     string   `json:"date"`
	Modified string   `json:"modified"`
	// Source is where the rule came from and under what licence. Exports keep it.
	Source       Source               `json:"source"`
	Translations []Translation        `json:"translations"`
	Failures     []TranslationFailure `json:"failures"`
}

// Source is a rule's provenance: the upstream project, the exact commit it was taken from, the path inside that
// checkout, and the licence it is distributed under (SigmaHQ detection rules: DRL 1.1, attribution required).
type Source struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Commit     string `json:"commit"`
	Path       string `json:"path"`
	License    string `json:"license"`
	LicenseURL string `json:"licenseUrl"`
}

type LogSource struct {
	Category string `json:"category"`
	Product  string `json:"product"`
	Service  string `json:"service"`
}

type Translation struct {
	Backend   string `json:"backend"`  // provider-registry key: microsoft_sentinel | microsoft_defender | splunk | elastic | crowdstrike | qradar
	Language  string `json:"language"` // KQL | SPL | Lucene | LogScale | AQL
	Query     string `json:"query"`
	Generator string `json:"generator"`
	// Mapping is "pipeline" when the query was field-mapped for the SIEM (real table / index / event type and
	// field names), or "generic" when it uses Sigma's own field names and needs adapting. A generic query is
	// never presented as ready to paste.
	Mapping string `json:"mapping"`
	// Pipeline names the field-mapping pipeline used; empty when Mapping is "generic".
	Pipeline string `json:"pipeline"`
	// DataSource is what the customer must collect for the query to match anything; empty when generic.
	DataSource string `json:"dataSource"`
}

type TranslationFailure struct {
	Backend string `json:"backend"`
	Reason  string `json:"reason"`
}

// Metadata is the generator's provenance and quality-gate audit trail.
type Metadata struct {
	SchemaVersion        int            `json:"schemaVersion"`
	GeneratorVersion     string         `json:"generatorVersion"`
	SigmaCommit          string         `json:"sigmaCommit"`
	GeneratedAt          string         `json:"generatedAt"`
	SourceLicense        string         `json:"sourceLicense"`
	Attribution          string         `json:"attribution"`
	TestedTechniqueCount int            `json:"testedTechniqueCount"`
	Mappings             map[string]int `json:"mappings"`
	// UnrecognizedTechniqueIds are ATT&CK ids on rules that the bundled ATT&CK data does not know yet
	// (SigmaHQ is newer than the bundle).
	UnrecognizedTechniqueIds []string          `json:"unrecognizedTechniqueIds"`
	RuleCount                int               `json:"ruleCount"`
	TechniqueCount           int               `json:"techniqueCount"`
	Backends                 map[string]int    `json:"backends"`
	TranslationFailures      []MetadataFailure `json:"translationFailures"`
}

type MetadataFailure struct {
	RuleID  string `json:"ruleId"`
	SigmaID string `json:"sigmaId"`
	Backend string `json:"backend"`
	Reason  string `json:"reason"`
}
