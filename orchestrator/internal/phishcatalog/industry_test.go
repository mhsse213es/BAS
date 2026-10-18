package phishcatalog

import "testing"

func TestNewIndustryProfile_UnknownPriorityScenarioID_Errors(t *testing.T) {
	if _, err := NewIndustryProfile("x", []string{"PH-FAKE-999"}, nil, nil, ""); err == nil {
		t.Error("NewIndustryProfile() with an unknown priority scenario ID = nil error, want an error")
	}
}

func TestNewIndustryProfile_UnknownBusinessImpactWeightScenarioID_Errors(t *testing.T) {
	if _, err := NewIndustryProfile("x", nil, nil, map[string]float64{"PH-FAKE-999": 0.5}, ""); err == nil {
		t.Error("NewIndustryProfile() with an unknown weight scenario ID = nil error, want an error")
	}
}

func TestNewIndustryProfile_EmptyName_Errors(t *testing.T) {
	if _, err := NewIndustryProfile("", nil, nil, nil, ""); err == nil {
		t.Error("NewIndustryProfile() with an empty name = nil error, want an error")
	}
}

func TestNewIndustryProfile_BusinessImpactWeightOutOfRange_Errors(t *testing.T) {
	if _, err := NewIndustryProfile("x", nil, nil, map[string]float64{"PH-BEC-002": 1.5}, ""); err == nil {
		t.Error("NewIndustryProfile() with weight 1.5 = nil error, want an error")
	}
	if _, err := NewIndustryProfile("x", nil, nil, map[string]float64{"PH-BEC-002": -0.1}, ""); err == nil {
		t.Error("NewIndustryProfile() with weight -0.1 = nil error, want an error")
	}
}

func TestNewIndustryProfile_ValidScenarioIDs_Succeeds(t *testing.T) {
	if _, err := NewIndustryProfile("x", []string{"PH-BEC-002"}, nil, map[string]float64{"PH-BEC-002": 0.5}, ""); err != nil {
		t.Errorf("NewIndustryProfile() with real scenario IDs error = %v, want nil", err)
	}
}

func TestBFSINBFCProfile_RealScenarioReferences(t *testing.T) {
	p, err := BFSINBFCProfile()
	if err != nil {
		t.Fatalf("BFSINBFCProfile() error = %v", err)
	}
	scenarios, err := AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("AudspectPhishingCatalog() error = %v", err)
	}
	if got := p.PrioritySummary(scenarios); got == "" {
		t.Error("PrioritySummary() = \"\", want a non-empty rendered summary")
	}
	if got := p.Describe(); got == p.Name {
		t.Errorf("Describe() = %q, want it to include the profile's Note", got)
	}
}

func TestIndustryProfileNames_IncludesAllElevenShippedProfiles(t *testing.T) {
	names := IndustryProfileNames()
	want := map[string]bool{
		"bfsi": true, "healthcare": true, "manufacturing-ot": true,
		"government": true, "insurance": true, "telecom": true, "retail": true,
		"education": true, "logistics": true, "professional-services": true, "technology": true,
	}
	if len(names) != len(want) {
		t.Fatalf("IndustryProfileNames() = %v (%d), want exactly %d names", names, len(names), len(want))
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("IndustryProfileNames() contains unexpected name %q", n)
		}
	}
}

// TestAllShippedProfiles_PriorityScenariosAllResolveAndCompleteness is
// the profile-completeness check the item-3 acceptance criteria asked
// for: every shipped profile must build without error (NewIndustryProfile
// already validates every ID against the real catalog at construction
// time, so a stale or fictional scenario ID fails here, not silently).
func TestAllShippedProfiles_PriorityScenariosAllResolveAndCompleteness(t *testing.T) {
	scenarios, err := AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("AudspectPhishingCatalog() error = %v", err)
	}
	for _, name := range IndustryProfileNames() {
		profile, ok, err := BuildIndustryProfile(name)
		if !ok {
			t.Fatalf("BuildIndustryProfile(%q) ok = false, want true", name)
		}
		if err != nil {
			t.Fatalf("BuildIndustryProfile(%q) error = %v", name, err)
		}
		if len(profile.PriorityScenarioIDs) == 0 {
			t.Errorf("profile %q has no PriorityScenarioIDs -- every shipped profile must name real priorities", name)
		}
		if got := profile.PrioritySummary(scenarios); got == "" {
			t.Errorf("profile %q PrioritySummary() = \"\", want a non-empty summary", name)
		}
	}
}

func TestIndustryProfile_FilterScenarios_ReturnsOnlyPrioritiesInWeightOrder(t *testing.T) {
	p, err := BFSINBFCProfile()
	if err != nil {
		t.Fatalf("BFSINBFCProfile() error = %v", err)
	}
	scenarios, err := AudspectPhishingCatalog()
	if err != nil {
		t.Fatalf("AudspectPhishingCatalog() error = %v", err)
	}
	filtered := p.FilterScenarios(scenarios)
	if len(filtered) != len(p.PriorityScenarioIDs) {
		t.Fatalf("FilterScenarios() returned %d scenarios, want %d (one per PriorityScenarioID)", len(filtered), len(p.PriorityScenarioIDs))
	}
	if filtered[0].ID != "PH-BEC-002" { // BFSINBFCProfile's own highest-weighted priority
		t.Errorf("FilterScenarios()[0].ID = %q, want %q (highest BusinessImpactWeight first)", filtered[0].ID, "PH-BEC-002")
	}
	for _, s := range filtered {
		found := false
		for _, id := range p.PriorityScenarioIDs {
			if s.ID == id {
				found = true
			}
		}
		if !found {
			t.Errorf("FilterScenarios() returned scenario %q, which is not one of this profile's priorities", s.ID)
		}
	}

	// The explicit negative: FilterScenarios must actually SELECT a
	// subset, not just annotate the full catalog. PH-ATT-002 is a real
	// catalog scenario (confirmed via AudspectPhishingCatalog above)
	// that is not one of BFSINBFCProfile's priorities -- it must be
	// absent from the filtered result, proving this is real selection
	// behavior a caller could dispatch against, not display metadata.
	for _, s := range filtered {
		if s.ID == "PH-ATT-002" {
			t.Error("FilterScenarios() included PH-ATT-002, which is not a BFSI/NBFC priority -- this proves FilterScenarios is not actually filtering")
		}
	}
	if len(filtered) >= len(scenarios) {
		t.Errorf("FilterScenarios() returned %d scenarios, the full catalog has %d -- a profile with only 3 priorities must select a strict subset", len(filtered), len(scenarios))
	}
}

func TestIndustryProfile_FilterScenarios_SkipsUnresolvedIDsSilently(t *testing.T) {
	p, err := NewIndustryProfile("x", []string{"PH-BEC-002"}, nil, nil, "")
	if err != nil {
		t.Fatalf("NewIndustryProfile() error = %v", err)
	}
	filtered := p.FilterScenarios(nil) // no scenarios at all -- PH-BEC-002 cannot resolve
	if len(filtered) != 0 {
		t.Errorf("FilterScenarios(nil) = %v, want an empty slice", filtered)
	}
}

func TestBuildIndustryProfile_UnknownName_ReturnsFalse(t *testing.T) {
	_, ok, err := BuildIndustryProfile("not-a-real-profile")
	if ok {
		t.Error("BuildIndustryProfile() with an unknown name ok = true, want false")
	}
	if err != nil {
		t.Errorf("BuildIndustryProfile() with an unknown name error = %v, want nil", err)
	}
}
