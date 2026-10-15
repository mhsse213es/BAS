package webgwefficacy

import "testing"

func TestNewIndustryProfile_UnknownPriorityDomainID_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", []string{"99"}, nil, nil, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for an unknown priority domain ID, got nil")
	}
}

func TestNewIndustryProfile_UnknownBusinessImpactWeightDomainID_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", nil, nil, map[string]float64{"99": 1.0}, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for an unknown business-impact-weight domain ID, got nil")
	}
}

func TestNewIndustryProfile_EmptyName_Errors(t *testing.T) {
	_, err := NewIndustryProfile("", []string{"01"}, nil, nil, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for an empty name, got nil")
	}
}

func TestNewIndustryProfile_BusinessImpactWeightBelowZero_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", nil, nil, map[string]float64{"01": -0.1}, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for a business-impact weight below 0, got nil")
	}
}

func TestNewIndustryProfile_BusinessImpactWeightAboveOne_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", nil, nil, map[string]float64{"01": 1.1}, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for a business-impact weight above 1, got nil")
	}
}

func TestNewIndustryProfile_ValidDomainIDs_Succeeds(t *testing.T) {
	_, err := NewIndustryProfile("test", []string{"01", "02"}, []string{"PII"}, map[string]float64{"01": 1.0}, "note")
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
}

func TestBFSINBFCProfile_RealDomainReferences(t *testing.T) {
	profile, err := BFSINBFCProfile()
	if err != nil {
		t.Fatalf("BFSINBFCProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestHealthcareProfile_RealDomainReferences(t *testing.T) {
	profile, err := HealthcareProfile()
	if err != nil {
		t.Fatalf("HealthcareProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestManufacturingOTProfile_RealDomainReferences(t *testing.T) {
	profile, err := ManufacturingOTProfile()
	if err != nil {
		t.Fatalf("ManufacturingOTProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestMSPSharedTenantProfile_RealDomainReferences(t *testing.T) {
	profile, err := MSPSharedTenantProfile()
	if err != nil {
		t.Fatalf("MSPSharedTenantProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}
