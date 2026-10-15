package wafcatalog

import "testing"

func TestSsrfVectors_ValidAndUnique(t *testing.T) {
	vectors, err := ssrfVectors()
	if err != nil {
		t.Fatalf("ssrfVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	foundNoCounterpart := false
	for _, v := range vectors {
		if v.BenignCounterpart == nil {
			foundNoCounterpart = true
			if v.NoBenignCounterpartReason == "" {
				t.Errorf("vector %q has nil BenignCounterpart but empty NoBenignCounterpartReason", v.ID)
			}
		}
	}
	if !foundNoCounterpart {
		t.Error("expected at least one SSRF vector with no benign counterpart (metadata-endpoint probe)")
	}
}

func TestFileUploadVectors_ValidAndUnique(t *testing.T) {
	vectors, err := fileUploadVectors()
	if err != nil {
		t.Fatalf("fileUploadVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

func TestHttpParserVectors_ValidAndUnique(t *testing.T) {
	vectors, err := httpParserVectors()
	if err != nil {
		t.Fatalf("httpParserVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}
