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

func TestIndustryProfileNames_IncludesAllThreeShippedProfiles(t *testing.T) {
	names := IndustryProfileNames()
	want := map[string]bool{"bfsi": true, "healthcare": true, "manufacturing-ot": true}
	if len(names) != len(want) {
		t.Fatalf("IndustryProfileNames() = %v, want exactly %v", names, want)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("IndustryProfileNames() contains unexpected name %q", n)
		}
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
