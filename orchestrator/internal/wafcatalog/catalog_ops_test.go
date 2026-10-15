package wafcatalog

import "testing"

func TestRateLimitVectors_ValidAndUnique(t *testing.T) {
	vectors, err := rateLimitVectors()
	if err != nil {
		t.Fatalf("rateLimitVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

func TestCacheWeaknessVectors_ValidAndUnique(t *testing.T) {
	vectors, err := cacheWeaknessVectors()
	if err != nil {
		t.Fatalf("cacheWeaknessVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

func TestPolicyMisconfigVectors_ValidAndUnique(t *testing.T) {
	vectors, err := policyMisconfigVectors()
	if err != nil {
		t.Fatalf("policyMisconfigVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}
