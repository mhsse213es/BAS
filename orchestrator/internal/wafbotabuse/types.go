// Package wafbotabuse is a vendor-neutral, I/O-free attack-vector catalog
// covering bounded-automation, rate-limit, credential-abuse, and
// distributed-enforcement attack shapes. It depends only on
// internal/wafval, structurally a third sibling of wafcatalog and
// wafapiflow rather than a consumer of either: no dependency on
// wafcatalog, wafpolicygap, wafevasion, or wafapiflow. Every vector's
// claim is evaluated by the unmodified wafval.EvaluateClaim -- zero new
// wafval verdict logic. Fixture-backed only; real execution is deferred.
package wafbotabuse

// BotAbuseCategory is one of the four breadth categories this catalog
// covers.
type BotAbuseCategory string

const (
	CategoryBoundedAutomation      BotAbuseCategory = "bounded_automation"
	CategoryRateLimit              BotAbuseCategory = "rate_limit"
	CategoryCredentialAbuse        BotAbuseCategory = "credential_abuse"
	CategoryDistributedEnforcement BotAbuseCategory = "distributed_enforcement"
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

// BotAbuseVector is one versioned catalog entry. BenignCounterpart is nil
// only when NoBenignCounterpartReason explains why no legitimate lookalike
// exists -- never a silent omission.
type BotAbuseVector struct {
	ID                        string
	Version                   int
	Category                  BotAbuseCategory
	Name                      string
	Severity                  Severity
	Preconditions             string
	Malicious                 RequestTemplate
	BenignCounterpart         *RequestTemplate
	NoBenignCounterpartReason string
	Standards                 StandardsMapping
	Provenance                string
}
