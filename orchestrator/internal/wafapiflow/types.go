// Package wafapiflow is a vendor-neutral, I/O-free attack-vector catalog
// covering API-schema, authorization-boundary, sensitive-workflow,
// GraphQL, and resource-quantity attacks -- an attack surface
// internal/wafcatalog's generic web-attack catalog does not cover. It
// depends only on internal/wafval, structurally a sibling of wafcatalog
// rather than a consumer of it: no dependency on wafcatalog, wafpolicygap,
// or wafevasion. Every vector's claim is evaluated by the unmodified
// wafval.EvaluateClaim -- zero new wafval verdict logic. Fixture-backed
// only; real execution is deferred.
package wafapiflow

// APIFlowCategory is one of the five breadth categories this catalog
// covers.
type APIFlowCategory string

const (
	CategorySchemaConformance APIFlowCategory = "schema_conformance"
	CategoryAuthBoundary      APIFlowCategory = "auth_boundary"
	CategorySensitiveWorkflow APIFlowCategory = "sensitive_workflow"
	CategoryGraphQLAbuse      APIFlowCategory = "graphql_abuse"
	CategoryResourceControl   APIFlowCategory = "resource_control"
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

// APIFlowVector is one versioned catalog entry. BenignCounterpart is nil
// only when NoBenignCounterpartReason explains why no legitimate lookalike
// exists -- never a silent omission.
type APIFlowVector struct {
	ID                        string
	Version                   int
	Category                  APIFlowCategory
	Name                      string
	Severity                  Severity
	Preconditions             string
	Malicious                 RequestTemplate
	BenignCounterpart         *RequestTemplate
	NoBenignCounterpartReason string
	Standards                 StandardsMapping
	Provenance                string
}
