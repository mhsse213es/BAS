package controlhealth

import "testing"

func TestNewMapper_LoadsAllCategories(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	cats := m.Categories()
	if len(cats) != 10 {
		t.Fatalf("got %d categories, want 10", len(cats))
	}
	want := "endpoint-protection"
	if cats[0].ID != want {
		t.Errorf("first category = %q, want %q (file order)", cats[0].ID, want)
	}
}

func TestMapper_PrimaryTechniques(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	techs := m.PrimaryTechniques("endpoint-protection")
	if len(techs) == 0 {
		t.Fatal("expected endpoint-protection to have mapped techniques")
	}
	found := false
	for _, id := range techs {
		if id == "T1059" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected T1059 in endpoint-protection's primary techniques, got %v", techs)
	}
}

func TestMapper_CategoriesForTechnique_PrimaryAndSecondary(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	primary, all := m.CategoriesForTechnique("T1059")
	if primary != "endpoint-protection" {
		t.Errorf("T1059 primary = %q, want endpoint-protection", primary)
	}
	if len(all) < 2 {
		t.Errorf("T1059 should touch multiple categories (primary + secondary), got %v", all)
	}
}

func TestMapper_CategoriesForTechnique_SubTechniqueMatchesBase(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	primary, _ := m.CategoriesForTechnique("T1059.001")
	if primary != "endpoint-protection" {
		t.Errorf("T1059.001 should match base T1059's primary, got %q", primary)
	}
}

func TestMapper_CategoriesForTechnique_Unmapped(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	primary, all := m.CategoriesForTechnique("T9999")
	if primary != "" || len(all) != 0 {
		t.Errorf("unmapped technique should return empty, got primary=%q all=%v", primary, all)
	}
}
