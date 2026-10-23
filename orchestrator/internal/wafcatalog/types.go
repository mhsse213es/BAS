// Package wafcatalog is a vendor-neutral, I/O-free, versioned attack-test
// catalog that resolves into internal/wafval's evidence contract. It depends
// on wafval; wafval never depends on it. It imports stdlib only -- no HTTP
// client, no vendor SDK, no ModSecurity/CRS-specific code. Real execution
// against a controlled lab is a separate, deferred package.
package wafcatalog

// AttackFamily is one of the breadth categories this catalog covers.
type AttackFamily string

const (
	FamilySQLInjection     AttackFamily = "sql_injection"
	FamilyXSS              AttackFamily = "xss"
	FamilyPathTraversal    AttackFamily = "path_traversal"
	FamilySSRF             AttackFamily = "ssrf"
	FamilyFileUpload       AttackFamily = "file_upload"
	FamilyHTTPParser       AttackFamily = "http_parser_discrepancy"
	FamilyAPIAbuse         AttackFamily = "api_abuse"
	FamilyAuthAbuse        AttackFamily = "auth_abuse"
	FamilyRateLimit        AttackFamily = "rate_limit"
	FamilyCacheWeakness    AttackFamily = "cache_weakness"
	FamilyPolicyMisconfig  AttackFamily = "policy_misconfig"
	FamilyCommandInjection AttackFamily = "command_injection"
	FamilyFileInclusion    AttackFamily = "file_inclusion"
	FamilyXXE              AttackFamily = "xml_external_entity"
	FamilyNoSQLInjection   AttackFamily = "nosql_injection"
	FamilyLDAPInjection    AttackFamily = "ldap_injection"
	FamilyXPathInjection   AttackFamily = "xpath_injection"
)

// Severity is the catalog entry's declared risk level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// RequestTemplate describes one request shape without executing it.
type RequestTemplate struct {
	Method          string
	Path            string
	PayloadLocation string
	Payload         string
	Description     string
}

// StandardsMapping ties a vector to external references. At least one of
// CWEIDs/WSTGCategory/Top10Category/APITop10Category must be non-empty.
// ATTACKTechniques is always optional.
type StandardsMapping struct {
	CWEIDs           []string
	WSTGCategory     string
	Top10Category    string
	APITop10Category string
	ATTACKTechniques []string
}

// AttackVector is one versioned catalog entry. BenignCounterpart is nil only
// when NoBenignCounterpartReason explains why no legitimate lookalike
// exists -- never a silent omission.
type AttackVector struct {
	ID                        string
	Version                   int
	Family                    AttackFamily
	Name                      string
	Severity                  Severity
	Preconditions             string
	Malicious                 RequestTemplate
	BenignCounterpart         *RequestTemplate
	NoBenignCounterpartReason string
	Standards                 StandardsMapping
	Provenance                string
}
