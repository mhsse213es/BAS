package wafevasion

import "testing"

func TestNewEvasionScenario_Valid_Succeeds(t *testing.T) {
	s, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002",
		"plain SQLi payload in the query parameter",
		"the identical SQLi payload, double-URL-encoded",
		"the origin application URL-decodes query parameters twice before passing them to the query layer, so the double-encoded form decodes to the identical payload",
		"manually authored")
	if err != nil {
		t.Fatalf("NewEvasionScenario: %v", err)
	}
	if s.ID != "EVADE-001" {
		t.Errorf("ID = %q, want %q", s.ID, "EVADE-001")
	}
}

func TestNewEvasionScenario_EmptyID_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("", EvasionEncodingObfuscation, "SQLI-002", "x", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for empty ID, got nil")
	}
}

func TestNewEvasionScenario_UnknownTechnique_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionTechnique("bogus_technique"), "SQLI-002", "x", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for unknown Technique, got nil")
	}
}

// Review Focus: an AttackVectorID referencing a non-existent vector must be
// rejected at construction, not silently carried to evaluation time.
func TestNewEvasionScenario_UnknownAttackVectorID_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "FAKE-999", "x", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for an AttackVectorID that does not exist in wafcatalog, got nil")
	}
}

func TestNewEvasionScenario_EmptyCanonicalDesc_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002", "", "x", "x", "x")
	if err == nil {
		t.Fatal("want error for empty CanonicalPayloadDescription, got nil")
	}
}

func TestNewEvasionScenario_EmptyEvasiveDesc_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002", "x", "", "x", "x")
	if err == nil {
		t.Fatal("want error for empty EvasivePayloadDescription, got nil")
	}
}

func TestNewEvasionScenario_EmptyOriginEquivalenceRationale_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002", "x", "x", "", "x")
	if err == nil {
		t.Fatal("want error for empty OriginEquivalenceRationale, got nil")
	}
}

func TestNewEvasionScenario_EmptyProvenance_Rejected(t *testing.T) {
	_, err := NewEvasionScenario("EVADE-001", EvasionEncodingObfuscation, "SQLI-002", "x", "x", "x", "")
	if err == nil {
		t.Fatal("want error for empty Provenance, got nil")
	}
}

func TestEvasionTechnique_AllSixConstantsDistinct(t *testing.T) {
	all := []EvasionTechnique{
		EvasionEncodingObfuscation, EvasionNormalizationMismatch, EvasionContentTypeConfusion,
		EvasionHTTPDiscrepancy, EvasionMultipartBoundaryManipulation, EvasionRequestBoundaryAbuse,
	}
	seen := make(map[EvasionTechnique]bool)
	for _, t2 := range all {
		if seen[t2] {
			t.Errorf("duplicate EvasionTechnique value %q", t2)
		}
		seen[t2] = true
	}
	if len(seen) != 6 {
		t.Errorf("len(seen) = %d, want 6", len(seen))
	}
}
