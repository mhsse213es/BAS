package wafevasion

import "testing"

func TestAudspectWAFEvasionCatalog_ReturnsSixScenarios(t *testing.T) {
	scenarios, err := AudspectWAFEvasionCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFEvasionCatalog: %v", err)
	}
	if len(scenarios) != 6 {
		t.Fatalf("len(scenarios) = %d, want 6", len(scenarios))
	}
	if err := ValidateEvasionCatalog(scenarios); err != nil {
		t.Errorf("ValidateEvasionCatalog: %v", err)
	}
}

// Review Focus: the catalog must cover all 6 distinct evasion techniques,
// not duplicate one and skip another.
func TestAudspectWAFEvasionCatalog_CoversAllSixTechniques(t *testing.T) {
	scenarios, err := AudspectWAFEvasionCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFEvasionCatalog: %v", err)
	}
	want := []EvasionTechnique{
		EvasionEncodingObfuscation, EvasionNormalizationMismatch, EvasionContentTypeConfusion,
		EvasionHTTPDiscrepancy, EvasionMultipartBoundaryManipulation, EvasionRequestBoundaryAbuse,
	}
	seen := make(map[EvasionTechnique]int)
	for _, s := range scenarios {
		seen[s.Technique]++
	}
	for _, w := range want {
		if seen[w] != 1 {
			t.Errorf("technique %q appears %d times in the catalog, want exactly 1", w, seen[w])
		}
	}
}

// Final review fix (Important finding): EVADE-004 (http_discrepancy) and
// EVADE-006 (request_boundary_abuse) must reference the HTTPPARSE vector
// whose real wafcatalog payload actually matches each scenario's own
// narrative. HTTPPARSE-001's real payload IS a Content-Length/
// Transfer-Encoding conflict (CL.TE request smuggling) -- that is
// RequestBoundaryAbuse's story, not a generic HTTP discrepancy. HTTPPARSE-002
// is verb tampering (TRACE vs POST against a method-keyed access rule) --
// an HTTP-discrepancy story, not a request-framing/boundary story. A prior
// version of this catalog had the two IDs swapped relative to their own
// rationale text; this test pins the corrected mapping as a regression
// guard.
func TestAudspectWAFEvasionCatalog_HTTPVectorAssignmentsMatchTechniqueNarrative(t *testing.T) {
	scenarios, err := AudspectWAFEvasionCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFEvasionCatalog: %v", err)
	}
	byID := make(map[string]EvasionScenario, len(scenarios))
	for _, s := range scenarios {
		byID[s.ID] = s
	}
	evade004, ok := byID["EVADE-004"]
	if !ok {
		t.Fatal("EVADE-004 not found in catalog")
	}
	if evade004.AttackVectorID != "HTTPPARSE-002" {
		t.Errorf("EVADE-004.AttackVectorID = %q, want %q (verb-tampering vector matches an HTTP-discrepancy story)", evade004.AttackVectorID, "HTTPPARSE-002")
	}
	evade006, ok := byID["EVADE-006"]
	if !ok {
		t.Fatal("EVADE-006 not found in catalog")
	}
	if evade006.AttackVectorID != "HTTPPARSE-001" {
		t.Errorf("EVADE-006.AttackVectorID = %q, want %q (CL.TE conflict vector matches a request-boundary-abuse story)", evade006.AttackVectorID, "HTTPPARSE-001")
	}
}
