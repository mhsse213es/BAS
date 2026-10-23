package wafcatalog

import "testing"

func TestSqlInjectionVectors_ValidAndUnique(t *testing.T) {
	vectors, err := sqlInjectionVectors()
	if err != nil {
		t.Fatalf("sqlInjectionVectors: %v", err)
	}
	if len(vectors) != 3 {
		t.Fatalf("len(vectors) = %d, want 3", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Family != FamilySQLInjection {
			t.Errorf("vector %q Family = %q, want %q", v.ID, v.Family, FamilySQLInjection)
		}
	}
}

func TestXssVectors_ValidAndUnique(t *testing.T) {
	vectors, err := xssVectors()
	if err != nil {
		t.Fatalf("xssVectors: %v", err)
	}
	if len(vectors) != 6 {
		t.Fatalf("len(vectors) = %d, want 6", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

func TestPathTraversalVectors_ValidAndUnique(t *testing.T) {
	vectors, err := pathTraversalVectors()
	if err != nil {
		t.Fatalf("pathTraversalVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}
