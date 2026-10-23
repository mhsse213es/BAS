package wafcatalog

import "testing"

func TestCommandInjectionVectors_ValidAndUnique(t *testing.T) {
	vectors, err := commandInjectionVectors()
	if err != nil {
		t.Fatalf("commandInjectionVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Family != FamilyCommandInjection {
			t.Errorf("vector %q Family = %q, want %q", v.ID, v.Family, FamilyCommandInjection)
		}
	}
}

func TestFileInclusionVectors_ValidAndUnique(t *testing.T) {
	vectors, err := fileInclusionVectors()
	if err != nil {
		t.Fatalf("fileInclusionVectors: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("len(vectors) = %d, want 2", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Family != FamilyFileInclusion {
			t.Errorf("vector %q Family = %q, want %q", v.ID, v.Family, FamilyFileInclusion)
		}
	}
}

func TestXxeVectors_ValidAndUnique(t *testing.T) {
	vectors, err := xxeVectors()
	if err != nil {
		t.Fatalf("xxeVectors: %v", err)
	}
	if len(vectors) != 1 {
		t.Fatalf("len(vectors) = %d, want 1", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Family != FamilyXXE {
			t.Errorf("vector %q Family = %q, want %q", v.ID, v.Family, FamilyXXE)
		}
	}
}

func TestNoSQLInjectionVectors_ValidAndUnique(t *testing.T) {
	vectors, err := noSQLInjectionVectors()
	if err != nil {
		t.Fatalf("noSQLInjectionVectors: %v", err)
	}
	if len(vectors) != 1 {
		t.Fatalf("len(vectors) = %d, want 1", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Family != FamilyNoSQLInjection {
			t.Errorf("vector %q Family = %q, want %q", v.ID, v.Family, FamilyNoSQLInjection)
		}
	}
}

func TestLdapInjectionVectors_ValidAndUnique(t *testing.T) {
	vectors, err := ldapInjectionVectors()
	if err != nil {
		t.Fatalf("ldapInjectionVectors: %v", err)
	}
	if len(vectors) != 1 {
		t.Fatalf("len(vectors) = %d, want 1", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Family != FamilyLDAPInjection {
			t.Errorf("vector %q Family = %q, want %q", v.ID, v.Family, FamilyLDAPInjection)
		}
	}
}

func TestXPathInjectionVectors_ValidAndUnique(t *testing.T) {
	vectors, err := xpathInjectionVectors()
	if err != nil {
		t.Fatalf("xpathInjectionVectors: %v", err)
	}
	if len(vectors) != 1 {
		t.Fatalf("len(vectors) = %d, want 1", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
	for _, v := range vectors {
		if v.Family != FamilyXPathInjection {
			t.Errorf("vector %q Family = %q, want %q", v.ID, v.Family, FamilyXPathInjection)
		}
	}
}
