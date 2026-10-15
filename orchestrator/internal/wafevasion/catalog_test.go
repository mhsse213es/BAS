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
