package avcatalog

import (
	"testing"

	"github.com/audspect/bas/internal/avval"
)

func validPrimary() ExecutionTemplate {
	return ExecutionTemplate{Executor: "powershell", Command: "Write-Output test", Description: "benign marker write"}
}

func validStandards() StandardsMapping {
	return StandardsMapping{ATTACKTechniques: []string{"T1059.001"}}
}

func TestNewVector_Valid_Succeeds(t *testing.T) {
	reason := "no legitimate counterpart needed for this test"
	v, err := NewVector("AV-TEST-001", 1, FamilyScriptFileless, "test vector", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"preconditions", avval.ClaimPrevention, validPrimary(), nil, reason,
		"delete the marker file", "", validStandards(), "manually authored")
	if err != nil {
		t.Fatalf("NewVector: %v", err)
	}
	if v.ID != "AV-TEST-001" {
		t.Errorf("ID = %q, want AV-TEST-001", v.ID)
	}
}

func TestNewVector_EmptyID_Rejected(t *testing.T) {
	_, err := NewVector("", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "r", "c", "", validStandards(), "p")
	if err == nil {
		t.Error("empty id should be rejected")
	}
}

func TestNewVector_NoPlatforms_Rejected(t *testing.T) {
	_, err := NewVector("AV-TEST-002", 1, FamilyScriptFileless, "n", SeverityHigh,
		nil, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "r", "c", "", validStandards(), "p")
	if err == nil {
		t.Error("no platforms should be rejected")
	}
}

func TestNewVector_NoCapabilities_Rejected(t *testing.T) {
	_, err := NewVector("AV-TEST-003", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, nil,
		"", avval.ClaimPrevention, validPrimary(), nil, "r", "c", "", validStandards(), "p")
	if err == nil {
		t.Error("no capabilities should be rejected")
	}
}

func TestNewVector_NoATTACKTechnique_Rejected(t *testing.T) {
	_, err := NewVector("AV-TEST-004", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "r", "c", "", StandardsMapping{}, "p")
	if err == nil {
		t.Error("missing ATT&CK technique should be rejected")
	}
}

func TestNewVector_MalformedATTACKTechnique_Rejected(t *testing.T) {
	_, err := NewVector("AV-TEST-005", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "r", "c", "",
		StandardsMapping{ATTACKTechniques: []string{"not-a-technique"}}, "p")
	if err == nil {
		t.Error("malformed ATT&CK technique should be rejected")
	}
}

func TestNewVector_BothCounterpartAndReason_Rejected(t *testing.T) {
	cp := validPrimary()
	_, err := NewVector("AV-TEST-006", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), &cp, "also a reason", "c", "", validStandards(), "p")
	if err == nil {
		t.Error("both counterpart and reason set should be rejected")
	}
}

func TestNewVector_NeitherCounterpartNorReason_Rejected(t *testing.T) {
	_, err := NewVector("AV-TEST-007", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "", "c", "", validStandards(), "p")
	if err == nil {
		t.Error("neither counterpart nor reason set should be rejected")
	}
}

func TestNewVector_NoCleanupRequirement_Rejected(t *testing.T) {
	_, err := NewVector("AV-TEST-008", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "r", "", "", validStandards(), "p")
	if err == nil {
		t.Error("missing cleanup requirement should be rejected")
	}
}

func TestExpectations_PrimaryOnly_SingleLeg(t *testing.T) {
	v, err := NewVector("AV-TEST-009", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "no counterpart needed", "c", "", validStandards(), "p")
	if err != nil {
		t.Fatalf("NewVector: %v", err)
	}
	legs := v.Expectations("baseline-policy")
	if len(legs) != 1 {
		t.Fatalf("len(legs) = %d, want 1", len(legs))
	}
	if legs[0].Leg != LegPrimary || legs[0].Expectation.Claim != avval.ClaimPrevention {
		t.Errorf("legs[0] = %+v, want LegPrimary/ClaimPrevention", legs[0])
	}
}

func TestExpectations_WithCounterpart_TwoLegsOppositeClaims(t *testing.T) {
	cp := ExecutionTemplate{Executor: "powershell", Command: "Write-Output legit", Description: "legitimate counterpart"}
	v, err := NewVector("AV-TEST-010", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), &cp, "", "c", "", validStandards(), "p")
	if err != nil {
		t.Fatalf("NewVector: %v", err)
	}
	legs := v.Expectations("baseline-policy")
	if len(legs) != 2 {
		t.Fatalf("len(legs) = %d, want 2", len(legs))
	}
	if legs[0].Expectation.Claim != avval.ClaimPrevention {
		t.Errorf("legs[0].Expectation.Claim = %q, want %q", legs[0].Expectation.Claim, avval.ClaimPrevention)
	}
	if legs[1].Leg != LegCounterpart || legs[1].Expectation.Claim != avval.ClaimFalsePositive {
		t.Errorf("legs[1] = %+v, want LegCounterpart/ClaimFalsePositive", legs[1])
	}
}

func TestExpectations_PrimaryClaimFalsePositive_CounterpartClaimIsPrevention(t *testing.T) {
	cp := ExecutionTemplate{Executor: "powershell", Command: "Invoke-Malicious", Description: "adversarial counterpart"}
	v, err := NewVector("AV-TEST-011", 1, FamilyFalsePositiveResilience, "n", SeverityLow,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimFalsePositive, validPrimary(), &cp, "", "c", "", validStandards(), "p")
	if err != nil {
		t.Fatalf("NewVector: %v", err)
	}
	legs := v.Expectations("baseline-policy")
	if legs[0].Expectation.Claim != avval.ClaimFalsePositive {
		t.Errorf("legs[0].Expectation.Claim = %q, want %q", legs[0].Expectation.Claim, avval.ClaimFalsePositive)
	}
	if legs[1].Expectation.Claim != avval.ClaimPrevention {
		t.Errorf("legs[1].Expectation.Claim = %q, want %q", legs[1].Expectation.Claim, avval.ClaimPrevention)
	}
}

func TestValidateCatalog_DuplicateID_Rejected(t *testing.T) {
	v, _ := NewVector("AV-TEST-012", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "r", "c", "", validStandards(), "p")
	if err := ValidateCatalog([]Vector{v, v}); err == nil {
		t.Error("duplicate ID should be rejected")
	}
}

func TestValidateCatalog_AllUnique_Succeeds(t *testing.T) {
	v1, _ := NewVector("AV-TEST-013", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "r", "c", "", validStandards(), "p")
	v2, _ := NewVector("AV-TEST-014", 1, FamilyScriptFileless, "n", SeverityHigh,
		[]Platform{PlatformWindowsWorkstation}, []RequiredCapability{CapabilityBehavioralNGAV},
		"", avval.ClaimPrevention, validPrimary(), nil, "r", "c", "", validStandards(), "p")
	if err := ValidateCatalog([]Vector{v1, v2}); err != nil {
		t.Errorf("unique IDs should succeed, got %v", err)
	}
}
