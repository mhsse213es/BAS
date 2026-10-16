package avprofile

import (
	"testing"

	"github.com/audspect/bas/internal/avcatalog"
)

func TestAudspectAVProfileCatalog_ReturnsSevenProfiles(t *testing.T) {
	profiles, err := AudspectAVProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectAVProfileCatalog: %v", err)
	}
	if len(profiles) != 7 {
		t.Fatalf("len(profiles) = %d, want 7", len(profiles))
	}
	var industry, regional int
	for _, p := range profiles {
		switch p.Kind {
		case ProfileIndustry:
			industry++
		case ProfileRegional:
			regional++
		}
	}
	if industry != 5 {
		t.Errorf("industry profiles = %d, want 5", industry)
	}
	if regional != 2 {
		t.Errorf("regional profiles = %d, want 2", regional)
	}
}

// Review Focus: the Government profile's ControlObjectives record must
// be present and must honestly mix Covered and Gap entries -- this is
// the test that would catch a regression back to a flat, no-gaps claim.
func TestAudspectAVProfileCatalog_GovernmentHasHonestControlObjectiveMix(t *testing.T) {
	profiles, err := AudspectAVProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectAVProfileCatalog: %v", err)
	}
	var government Profile
	for _, p := range profiles {
		if p.ID == "AVPROFILE-GOVERNMENT" {
			government = p
		}
	}
	if government.ID == "" {
		t.Fatal("AVPROFILE-GOVERNMENT not found in the real profile catalog")
	}
	if len(government.ControlObjectives) != 6 {
		t.Fatalf("len(ControlObjectives) = %d, want 6 (av.txt names 6 Government priorities)", len(government.ControlObjectives))
	}
	var covered, gap int
	for _, o := range government.ControlObjectives {
		switch o.Status {
		case CoverageStatusCovered:
			covered++
		case CoverageStatusGap:
			gap++
		}
	}
	if covered == 0 {
		t.Error("want at least one real Covered objective, got zero")
	}
	if gap == 0 {
		t.Error("want at least one honest Gap objective, got zero -- a profile with zero gaps here would mean a vector was forced onto a priority it doesn't test")
	}
	if covered+gap != len(government.ControlObjectives) {
		t.Errorf("covered(%d)+gap(%d) != total(%d)", covered, gap, len(government.ControlObjectives))
	}
}

// Review Focus: MSPControlObjectives must be a pure, fully-gapped record
// -- no AVPROFILE-MSP Profile should exist anywhere in the catalog.
func TestMSPControlObjectives_AllFiveAreGaps_NoMSPProfileMinted(t *testing.T) {
	objectives, err := MSPControlObjectives()
	if err != nil {
		t.Fatalf("MSPControlObjectives: %v", err)
	}
	if len(objectives) != 5 {
		t.Fatalf("len(objectives) = %d, want 5 (av.txt names 5 MSP priorities)", len(objectives))
	}
	for _, o := range objectives {
		if o.Status != CoverageStatusGap {
			t.Errorf("objective %q has status %v, want Gap -- no avcatalog vector honestly maps to any MSP priority", o.Objective, o.Status)
		}
	}
	profiles, err := AudspectAVProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectAVProfileCatalog: %v", err)
	}
	for _, p := range profiles {
		if p.ID == "AVPROFILE-MSP" {
			t.Fatal("AVPROFILE-MSP must not exist -- MSP priorities are fully gapped, see MSPControlObjectives")
		}
	}
}

// Review Focus: validate against the REAL avcatalog output, not a
// fixture -- this test would catch a genuine drift between this seed
// data and the real upstream catalog.
func TestAudspectAVProfileCatalog_EachProfileValidatesAgainstRealCatalog(t *testing.T) {
	profiles, err := AudspectAVProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectAVProfileCatalog: %v", err)
	}
	realCatalog, err := avcatalog.AudspectAVAttackCatalog()
	if err != nil {
		t.Fatalf("avcatalog.AudspectAVAttackCatalog: %v", err)
	}
	for _, p := range profiles {
		if err := ValidateAgainstCatalog(p, realCatalog); err != nil {
			t.Errorf("profile %q failed ValidateAgainstCatalog against the real catalog: %v", p.ID, err)
		}
	}
}

func TestAudspectAVProfileCatalog_EveryComplianceReferenceIsUnverifiedWithANote(t *testing.T) {
	profiles, err := AudspectAVProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectAVProfileCatalog: %v", err)
	}
	for _, p := range profiles {
		for _, ref := range p.ComplianceReferences {
			if ref.VerificationStatus != Unverified {
				t.Errorf("profile %q reference %q has status %q, want %q", p.ID, ref.Framework, ref.VerificationStatus, Unverified)
			}
			if ref.Note == "" {
				t.Errorf("profile %q reference %q has an empty Note", p.ID, ref.Framework)
			}
		}
	}
}
