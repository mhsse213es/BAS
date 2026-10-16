package wafprofile

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func TestAudspectWAFProfileCatalog_ReturnsSixProfiles(t *testing.T) {
	profiles, err := AudspectWAFProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFProfileCatalog: %v", err)
	}
	if len(profiles) != 6 {
		t.Fatalf("len(profiles) = %d, want 6", len(profiles))
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
	if industry != 4 {
		t.Errorf("industry profiles = %d, want 4", industry)
	}
	if regional != 2 {
		t.Errorf("regional profiles = %d, want 2", regional)
	}
}

// Review Focus: validate against the REAL wafcatalog output, not a
// fixture -- this test would catch a genuine drift between this
// phase's seed data and the real upstream catalog.
func TestAudspectWAFProfileCatalog_EachProfileValidatesAgainstRealCatalog(t *testing.T) {
	profiles, err := AudspectWAFProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFProfileCatalog: %v", err)
	}
	realCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("wafcatalog.AudspectWAFAttackCatalog: %v", err)
	}
	for _, p := range profiles {
		if err := ValidateAgainstCatalog(p, realCatalog); err != nil {
			t.Errorf("profile %q failed ValidateAgainstCatalog against the real catalog: %v", p.ID, err)
		}
	}
}

func TestAudspectWAFProfileCatalog_EveryComplianceReferenceIsUnverifiedWithANote(t *testing.T) {
	profiles, err := AudspectWAFProfileCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFProfileCatalog: %v", err)
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
