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
	ID             string               `json:"id"`      // stable, Audspect-owned: "AUDRULE-000001"
	SigmaID        string               `json:"sigmaId"` // upstream Sigma rule UUID — traceability only
	Title          string               `json:"title"`
	Description    string               `json:"description"`
	TechniqueIDs   []string             `json:"techniqueIds"`
	Severity       string               `json:"severity"`
	Status         string               `json:"status"`
	Author         string               `json:"author"`
	References     []string             `json:"references"`
	FalsePositives []string             `json:"falsePositives"`
	LogSource      LogSource            `json:"logSource"`
	Detection      string               `json:"detection"` // raw Sigma YAML, verbatim
	Translations   []Translation        `json:"translations"`
	Failures       []TranslationFailure `json:"failures"`
}

type LogSource struct {
	Category string `json:"category"`
	Product  string `json:"product"`
	Service  string `json:"service"`
}

type Translation struct {
	Backend   string `json:"backend"`  // provider-registry key: microsoft_sentinel | microsoft_defender | splunk | elastic | crowdstrike
	Language  string `json:"language"` // KQL | SPL | Lucene | LogScale
	Query     string `json:"query"`
	Generator string `json:"generator"`
}

type TranslationFailure struct {
	Backend string `json:"backend"`
	Reason  string `json:"reason"`
}

// Metadata is the generator's provenance and quality-gate audit trail.
type Metadata struct {
	SchemaVersion       int               `json:"schemaVersion"`
	GeneratorVersion    string            `json:"generatorVersion"`
	SigmaCommit         string            `json:"sigmaCommit"`
	GeneratedAt         string            `json:"generatedAt"`
	RuleCount           int               `json:"ruleCount"`
	TechniqueCount      int               `json:"techniqueCount"`
	Backends            map[string]int    `json:"backends"`
	TranslationFailures []MetadataFailure `json:"translationFailures"`
}

type MetadataFailure struct {
	RuleID  string `json:"ruleId"`
	SigmaID string `json:"sigmaId"`
	Backend string `json:"backend"`
	Reason  string `json:"reason"`
}
