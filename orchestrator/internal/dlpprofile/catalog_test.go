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

// Review Focus: UAE has no content-diversity step anywhere testing
// Emirates ID/IBAN formats (final review independently confirmed this via
// grep across every scenario file) -- it must record a pure Gap, never a
// disguised Covered entry.
func TestAudspectDLPProfileCatalog_UAERecordsPayloadFidelityGapOnly(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, p := range profiles {
		if p.ID != "DLPPROFILE-UAE" {
			continue
		}
		if len(p.ControlObjectives) != 1 {
			t.Fatalf("DLPPROFILE-UAE has %d ControlObjectives, want exactly 1 payload-fidelity gap", len(p.ControlObjectives))
		}
		if p.ControlObjectives[0].Status != CoverageStatusGap {
			t.Errorf("DLPPROFILE-UAE ControlObjectives[0].Status = %v, want Gap", p.ControlObjectives[0].Status)
		}
		return
	}
	t.Fatal("DLPPROFILE-UAE not found in catalog")
}

// Review Focus: the direct regression test for the final-review finding
// (2026-10-17) that the original single-Gap-per-profile model overclaimed
// a gap that real scenario content-diversity steps already disprove --
// confirmed by reading scenarios/dlp-exfiltration-{smtp,coderepo,cloud-storage}.yaml
// directly (Medical Record / Patient,MRN,Diagnosis in smtp; PHP/Perl
// source code + Azure/DB2 credentials in coderepo; AWS credentials/C#
// source code in cloud-storage; Employment Contract in smtp; Partnership
// Agreement in cloud-storage). Each of these four profiles must now
// record BOTH a real Covered entry (citing the scenario ID and step that
// actually exists) AND a narrower, still-genuinely-untested Gap --
// neither a disguised full-Gap (the bug this test catches) nor a
// disguised full-Covered (which would overclaim the opposite direction).
func TestAudspectDLPProfileCatalog_FourProfilesRecordBothCoveredAndNarrowedGap(t *testing.T) {
	profiles, err := AudspectDLPProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectDLPProfileCatalog: %v", err)
	}
	for _, id := range []string{"DLPPROFILE-HEALTHCARE", "DLPPROFILE-MANUFACTURING", "DLPPROFILE-GOVERNMENT", "DLPPROFILE-ITSAAS"} {
		found := false
		for _, p := range profiles {
			if p.ID != id {
				continue
			}
			found = true
			if len(p.ControlObjectives) != 2 {
				t.Errorf("profile %q has %d ControlObjectives, want exactly 2 (one real Covered, one narrowed Gap)", id, len(p.ControlObjectives))
				continue
			}
			var covered, gap int
			for _, o := range p.ControlObjectives {
				switch o.Status {
				case CoverageStatusCovered:
					covered++
					if o.VectorID == "" {
						t.Errorf("profile %q Covered entry has an empty VectorID", id)
					}
				case CoverageStatusGap:
					gap++
				}
			}
			if covered != 1 {
				t.Errorf("profile %q has %d Covered entries, want exactly 1", id, covered)
			}
			if gap != 1 {
				t.Errorf("profile %q has %d Gap entries, want exactly 1", id, gap)
			}
		}
		if !found {
			t.Errorf("profile %q not found in catalog", id)
		}
	}
}
