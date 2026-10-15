package wafcatalog

import "testing"

func TestApiAbuseVectors_ValidAndUnique(t *testing.T) {
	vectors, err := apiAbuseVectors()
	if err != nil {
		t.Fatalf("apiAbuseVectors: %v", err)
	}
	if len(vectors) != 3 {
		t.Fatalf("len(vectors) = %d, want 3", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Standards.APITop10Category == "" {
			t.Errorf("vector %q has no APITop10Category mapping", v.ID)
		}
	}
}

func TestAuthAbuseVectors_ValidAndUnique(t *testing.T) {
	vectors, err := authAbuseVectors()
	if err != nil {
		t.Fatalf("authAbuseVectors: %v", err)
	}
	if len(vectors) != 3 {
		t.Fatalf("len(vectors) = %d, want 3", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}
