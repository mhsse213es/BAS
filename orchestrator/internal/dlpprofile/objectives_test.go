package dlpprofile

import "testing"

func TestNewControlObjectiveCoverage_Covered_Succeeds(t *testing.T) {
	o, err := NewControlObjectiveCoverage("endpoint-to-cloud channel delivery", "dlp-exfiltration-cloud-storage",
		"covers cloud-storage exfiltration channel delivery", "sink-receipt evidence from internal/cloudsink", CoverageStatusCovered)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Status != CoverageStatusCovered {
		t.Errorf("Status = %v, want Covered", o.Status)
	}
}

func TestNewControlObjectiveCoverage_Gap_Succeeds(t *testing.T) {
	o, err := NewControlObjectiveCoverage("patient/clinical record data-type fidelity", "", "no scenario payload is healthcare-shaped", "", CoverageStatusGap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Status != CoverageStatusGap {
		t.Errorf("Status = %v, want Gap", o.Status)
	}
	if o.VectorID != "" {
		t.Errorf("VectorID = %q, want empty for a gap", o.VectorID)
	}
}

func TestNewControlObjectiveCoverage_EmptyObjective_Rejected(t *testing.T) {
	if _, err := NewControlObjectiveCoverage("", "", "reason", "", CoverageStatusGap); err == nil {
		t.Fatal("expected error for empty objective")
	}
}

func TestNewControlObjectiveCoverage_EmptyRationale_Rejected(t *testing.T) {
	if _, err := NewControlObjectiveCoverage("some objective", "", "", "", CoverageStatusGap); err == nil {
		t.Fatal("expected error for empty rationale")
	}
}

func TestNewControlObjectiveCoverage_CoveredWithoutVectorID_Rejected(t *testing.T) {
	if _, err := NewControlObjectiveCoverage("obj", "", "rationale", "evidence", CoverageStatusCovered); err == nil {
		t.Fatal("expected error: covered status requires a vectorID")
	}
}

func TestNewControlObjectiveCoverage_CoveredWithoutRequiredEvidence_Rejected(t *testing.T) {
	if _, err := NewControlObjectiveCoverage("obj", "dlp-exfiltration-sftp", "rationale", "", CoverageStatusCovered); err == nil {
		t.Fatal("expected error: covered status requires requiredEvidence")
	}
}

// Review Focus: a gap must never carry a disguised scenario mapping --
// this is the specific case the design spec calls out (a Healthcare/
// Manufacturing/Government/IT-SaaS/UAE payload-fidelity gap must never be
// forced onto a scenario ID whose payload doesn't actually test it).
func TestNewControlObjectiveCoverage_GapWithVectorID_Rejected(t *testing.T) {
	if _, err := NewControlObjectiveCoverage("obj", "dlp-exfiltration-sftp", "rationale", "", CoverageStatusGap); err == nil {
		t.Fatal("expected error: a gap must not name a vectorID")
	}
}

func TestNewControlObjectiveCoverage_GapWithRequiredEvidence_Rejected(t *testing.T) {
	if _, err := NewControlObjectiveCoverage("obj", "", "rationale", "evidence that shouldn't exist", CoverageStatusGap); err == nil {
		t.Fatal("expected error: a gap must not carry requiredEvidence")
	}
}

func TestNewControlObjectiveCoverage_UnknownStatus_Rejected(t *testing.T) {
	if _, err := NewControlObjectiveCoverage("obj", "", "rationale", "", CoverageStatus("unknown")); err == nil {
		t.Fatal("expected error for unknown CoverageStatus")
	}
}

func TestValidateControlObjectivesAgainstCatalog_StaleVectorID_Rejected(t *testing.T) {
	covered, err := NewControlObjectiveCoverage("obj", "dlp-exfiltration-does-not-exist", "rationale", "evidence", CoverageStatusCovered)
	if err != nil {
		t.Fatalf("unexpected error building fixture: %v", err)
	}
	known := map[string]bool{"dlp-exfiltration-sftp": true}
	if err := ValidateControlObjectivesAgainstCatalog([]ControlObjectiveCoverage{covered}, known); err == nil {
		t.Fatal("expected error for a covered objective naming a scenario ID absent from the catalog")
	}
}

func TestValidateControlObjectivesAgainstCatalog_GapsNeverChecked(t *testing.T) {
	gap, err := NewControlObjectiveCoverage("obj", "", "no mapping exists", "", CoverageStatusGap)
	if err != nil {
		t.Fatalf("unexpected error building fixture: %v", err)
	}
	if err := ValidateControlObjectivesAgainstCatalog([]ControlObjectiveCoverage{gap}, map[string]bool{}); err != nil {
		t.Errorf("unexpected error for a gap entry against an empty catalog: %v", err)
	}
}
