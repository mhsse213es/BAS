package wafevasion

import "fmt"

// AudspectWAFEvasionCatalog returns Audspect's real, current seed evasion
// scenario catalog: exactly one scenario per EvasionTechnique, validated
// before being returned.
func AudspectWAFEvasionCatalog() ([]EvasionScenario, error) {
	type seed struct {
		id, attackVectorID, canonicalDesc, evasiveDesc, originEquivalenceRationale, provenance string
		technique                                                                              EvasionTechnique
	}
	seeds := []seed{
		{
			id: "EVADE-001", technique: EvasionEncodingObfuscation, attackVectorID: "SQLI-002",
			canonicalDesc: "plain SQLi payload in the query parameter",
			evasiveDesc:   "the identical SQLi payload, double-URL-encoded",
			originEquivalenceRationale: "the origin application URL-decodes query parameters twice before passing them to the query layer, so the double-encoded form decodes to the identical payload",
			provenance: "manually authored from waf.txt Phase 4's named encoding category",
		},
		{
			id: "EVADE-002", technique: EvasionNormalizationMismatch, attackVectorID: "PATHTRAV-001",
			canonicalDesc: "plain ../ directory-traversal path segments",
			evasiveDesc:   "the identical traversal expressed with Unicode/overlong-encoded path segments",
			originEquivalenceRationale: "the origin's filesystem path resolver performs Unicode normalization before resolving the path, so the overlong-encoded segments normalize to the identical traversal",
			provenance: "manually authored from waf.txt Phase 4's named normalization category",
		},
		{
			id: "EVADE-003", technique: EvasionContentTypeConfusion, attackVectorID: "FILEUP-001",
			canonicalDesc: "an uploaded file declared with its real executable content-type",
			evasiveDesc:   "the identical file bytes uploaded with a mislabeled benign-looking content-type",
			originEquivalenceRationale: "the origin's upload handler determines file type by inspecting the byte content, not the declared content-type header, so the mislabeled upload is processed identically to the canonical one",
			provenance: "manually authored from waf.txt Phase 4's named content-types category",
		},
		{
			id: "EVADE-004", technique: EvasionHTTPDiscrepancy, attackVectorID: "HTTPPARSE-002",
			canonicalDesc: "a canonical TRACE request directly targeting the method-restricted administrative route",
			evasiveDesc:   "the identical administrative operation requested via an X-HTTP-Method-Override: TRACE header on an outer POST request",
			originEquivalenceRationale: "the origin's HTTP server honors the X-HTTP-Method-Override header and dispatches to the identical TRACE handler regardless of which representation reaches it, so the override-framed request executes the identical administrative action as the canonical direct TRACE request",
			provenance: "manually authored from waf.txt Phase 4's named HTTP-discrepancies category",
		},
		{
			id: "EVADE-005", technique: EvasionMultipartBoundaryManipulation, attackVectorID: "FILEUP-002",
			canonicalDesc: "a multipart upload using a canonical, unambiguous boundary string",
			evasiveDesc:   "the identical upload body framed with a boundary string crafted to be parsed differently by a strict parser than by a lenient one",
			originEquivalenceRationale: "the origin's multipart parser is lenient and extracts the identical file part regardless of which boundary-parsing interpretation is applied",
			provenance: "manually authored from waf.txt Phase 4's named multipart-uploads category",
		},
		{
			id: "EVADE-006", technique: EvasionRequestBoundaryAbuse, attackVectorID: "HTTPPARSE-001",
			canonicalDesc: "a canonical request framed with a single, consistent Content-Length header",
			evasiveDesc:   "the identical request body framed with a Transfer-Encoding/Content-Length conflict",
			originEquivalenceRationale: "the origin's HTTP server resolves the conflicting framing by always preferring Transfer-Encoding, and arrives at the identical body as the canonical Content-Length-framed request",
			provenance: "manually authored from waf.txt Phase 4's named request-boundary category",
		},
	}

	var out []EvasionScenario
	for _, sd := range seeds {
		s, err := NewEvasionScenario(sd.id, sd.technique, sd.attackVectorID, sd.canonicalDesc, sd.evasiveDesc, sd.originEquivalenceRationale, sd.provenance)
		if err != nil {
			return nil, fmt.Errorf("loading seed evasion catalog: %w", err)
		}
		out = append(out, s)
	}

	if err := ValidateEvasionCatalog(out); err != nil {
		return nil, fmt.Errorf("seed evasion catalog failed validation: %w", err)
	}
	return out, nil
}
