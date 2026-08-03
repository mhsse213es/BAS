package endpointrisk

import "testing"

func TestNewCatalog_LoadsEmbeddedFile(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	entry, ok := c.Lookup("Adobe Flash Player 32.0.0.465", "32.0.0.465")
	if !ok {
		t.Fatal("expected Adobe Flash Player to match")
	}
	if entry.Risk != "critical" {
		t.Errorf("Risk = %q, want critical", entry.Risk)
	}
}

func TestCatalogLookup_CaseInsensitiveAndNormalized(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	_, ok := c.Lookup("java(tm) 8 update 451", "8.0.451")
	if !ok {
		t.Error("expected normalized lowercase match with (TM) stripped")
	}
}

func TestCatalogLookup_VersionMaxGating(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	// Java 8 has version_max "8" -- a hypothetical "Java 8" name with a
	// version that doesn't parse should still match (never blocks on
	// ambiguous versions).
	_, ok := c.Lookup("Java 8 Update 451", "8u451")
	if !ok {
		t.Error("expected match when version doesn't parse as a leading integer (never blocks on ambiguity)")
	}
}

func TestCatalogLookup_NoMatch(t *testing.T) {
	c, err := NewCatalog()
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	_, ok := c.Lookup("Google Chrome", "120.0.0.0")
	if ok {
		t.Error("expected no match for software not in the catalog")
	}
}
