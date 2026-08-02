package endpointrisk

import "testing"

func TestNewTaxonomy_LoadsEmbeddedFile(t *testing.T) {
	tx, err := NewTaxonomy()
	if err != nil {
		t.Fatalf("NewTaxonomy: %v", err)
	}
	cat, weight, ok := tx.CategoryForCheck("windows-firewall-enabled")
	if !ok {
		t.Fatal("expected windows-firewall-enabled to be mapped")
	}
	if cat != "security-configuration" {
		t.Errorf("category = %q, want security-configuration", cat)
	}
	if weight != 1.0 {
		t.Errorf("weight = %v, want 1.0", weight)
	}
}

func TestCategoryForCheck_UnknownCheckID_NotOK(t *testing.T) {
	tx, err := NewTaxonomy()
	if err != nil {
		t.Fatalf("NewTaxonomy: %v", err)
	}
	_, _, ok := tx.CategoryForCheck("no-such-check")
	if ok {
		t.Error("expected ok=false for an unmapped check_id")
	}
}

func TestNewTaxonomy_LinuxChecksMapped(t *testing.T) {
	tx, err := NewTaxonomy()
	if err != nil {
		t.Fatalf("NewTaxonomy: %v", err)
	}
	cat, _, ok := tx.CategoryForCheck("linux-ssh-root-login-disabled")
	if !ok || cat != "identity" {
		t.Errorf("linux-ssh-root-login-disabled: cat=%q ok=%v, want identity/true", cat, ok)
	}
}
