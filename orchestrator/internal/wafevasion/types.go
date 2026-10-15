// Package wafevasion compares a canonical malicious payload against a
// wire-level evasive re-encoding of the same attack: does a WAF that
// reliably blocks the canonical form still catch the re-encoded
// equivalent? It depends on wafval and wafcatalog; neither ever depends
// back on it, and it does not depend on internal/wafpolicygap -- the two
// phases are independent consumers of the same two lower layers, not a
// chain. EvaluateEvasionGap's decision rule lives entirely here, built
// from wafval.EvaluateClaim's existing output -- zero new wafval verdict
// logic. Fixture-backed only; real execution is deferred.
package wafevasion

// EvasionTechnique is one of the six protocol/parser evasion categories
// waf.txt names, each a distinct way a malicious payload can be
// re-expressed at the wire level without changing what the origin
// application ultimately executes.
type EvasionTechnique string

const (
	EvasionEncodingObfuscation           EvasionTechnique = "encoding_obfuscation"
	EvasionNormalizationMismatch         EvasionTechnique = "normalization_mismatch"
	EvasionContentTypeConfusion          EvasionTechnique = "content_type_confusion"
	EvasionHTTPDiscrepancy               EvasionTechnique = "http_discrepancy"
	EvasionMultipartBoundaryManipulation EvasionTechnique = "multipart_boundary_manipulation"
	EvasionRequestBoundaryAbuse          EvasionTechnique = "request_boundary_abuse"
)

// EvasionScenario declares one evasion-technique claim against a specific,
// real AttackVector from internal/wafcatalog. OriginEquivalenceRationale is
// mandatory and distinct from the two payload descriptions: it is the
// documented reason the evasive encoding is expected to decode to the
// identical attack at the origin -- the thing that makes a divergence in
// WAF behavior attributable to the technique rather than to a different
// attack.
type EvasionScenario struct {
	ID                          string
	Technique                   EvasionTechnique
	AttackVectorID              string
	CanonicalPayloadDescription string
	EvasivePayloadDescription   string
	OriginEquivalenceRationale  string
	Provenance                  string
}
