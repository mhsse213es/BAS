package dlpprofile

import "testing"

func TestAudspectDLPProfileCatalog_ReturnsSevenProfiles(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
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

func TestAudspectDLPProfileCatalog_EachProfileValidatesAgainstRealScenarioIDs(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, p := range profiles {
		if err := ValidateAgainstCatalog(p, RealDLPScenarioIDs()); err != nil {
			t.Errorf("profile %q failed ValidateAgainstCatalog: %v", p.ID, err)
		}
	}
}

func TestAudspectDLPProfileCatalog_EveryComplianceReferenceIsUnverifiedWithANote(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
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

// Review Focus: no profile may cite the stale dlp-exfiltration-multichannel
// scenario as evidence of coverage (see spec: it's missing 4 of 9 real
// channels despite its own description claiming full coverage).
func TestAudspectDLPProfileCatalog_NoProfileCitesStaleMultichannelScenario(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, p := range profiles {
		for _, id := range p.VectorIDs {
			if id == "dlp-exfiltration-multichannel" {
				t.Errorf("profile %q cites dlp-exfiltration-multichannel, which is stale relative to its own description and must never be used as a coverage claim", p.ID)
			}
		}
	}
}

// Review Focus: BFSI and India are the two profiles whose real payload
// (PAN/Aadhaar/SWIFT/UPI/credit-card) matches what the scenarios actually
// test -- they must NOT carry a payload-fidelity gap, which would be a
// false-negative regression understating real coverage.
func TestAudspectDLPProfileCatalog_BFSIAndIndiaHaveNoControlObjectives(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, id := range []string{"DLPPROFILE-BFSI", "DLPPROFILE-INDIA"} {
		found := false
		for _, p := range profiles {
			if p.ID == id {
				found = true
				if len(p.ControlObjectives) != 0 {
					t.Errorf("profile %q has %d ControlObjectives, want 0 -- its real payload matches what the scenarios test, so no payload-fidelity gap applies", id, len(p.ControlObjectives))
				}
			}
		}
		if !found {
			t.Errorf("profile %q not found in catalog", id)
		}
	}
}

// Review Focus: the direct regression test for the builder-check finding
// this plan exists to fix -- Healthcare/Manufacturing/Government/ITSAAS/UAE
// must each honestly record their payload-fidelity gap, never silently
// claim full coverage via a flat VectorIDs list alone.
func TestAudspectDLPProfileCatalog_NonBFSIProfilesRecordPayloadFidelityGap(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, id := range []string{"DLPPROFILE-HEALTHCARE", "DLPPROFILE-MANUFACTURING", "DLPPROFILE-GOVERNMENT", "DLPPROFILE-ITSAAS", "DLPPROFILE-UAE"} {
		found := false
		for _, p := range profiles {
			if p.ID == id {
				found = true
				if len(p.ControlObjectives) != 1 {
					t.Errorf("profile %q has %d ControlObjectives, want exactly 1 payload-fidelity gap", id, len(p.ControlObjectives))
					continue
				}
				if p.ControlObjectives[0].Status != CoverageStatusGap {
					t.Errorf("profile %q ControlObjectives[0].Status = %v, want Gap", id, p.ControlObjectives[0].Status)
				}
			}
		}
		if !found {
			t.Errorf("profile %q not found in catalog", id)
		}
	}
}
