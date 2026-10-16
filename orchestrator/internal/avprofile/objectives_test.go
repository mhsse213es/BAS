package avprofile

import "testing"

func TestNewControlObjectiveCoverage_Covered_Succeeds(t *testing.T) {
	o, err := NewControlObjectiveCoverage("restricted or disconnected networks", "AV-CONFIG-002",
		"covers degraded/offline operation", "prevention evidence while cloud lookup is unavailable", CoverageStatusCovered)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Status != CoverageStatusCovered {
		t.Errorf("Status = %v, want Covered", o.Status)
	}
}

func TestNewControlObjectiveCoverage_Gap_Succeeds(t *testing.T) {
	o, err := NewControlObjectiveCoverage("legacy and unsupported endpoints", "", "no vector tests EOL/unsupported OS compatibility", "", CoverageStatusGap)
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
	if _, err := NewControlObjectiveCoverage("obj", "AV-CONFIG-002", "rationale", "", CoverageStatusCovered); err == nil {
		t.Fatal("expected error: covered status requires requiredEvidence")
	}
}

// Review Focus: a gap must never carry a disguised vector mapping --
// this is the specific case av.txt's own directive calls out ("mark the
// requirement as a gap rather than assigning an unrelated vector").
func TestNewControlObjectiveCoverage_GapWithVectorID_Rejected(t *testing.T) {
	if _, err := NewControlObjectiveCoverage("obj", "AV-CONFIG-002", "rationale", "", CoverageStatusGap); err == nil {
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
	covered, err := NewControlObjectiveCoverage("obj", "AV-DOES-NOT-EXIST", "rationale", "evidence", CoverageStatusCovered)
	if err != nil {
		t.Fatalf("unexpected error building fixture: %v", err)
	}
	known := map[string]bool{"AV-CONFIG-002": true}
	if err := ValidateControlObjectivesAgainstCatalog([]ControlObjectiveCoverage{covered}, known); err == nil {
		t.Fatal("expected error for a covered objective naming a vector ID absent from the catalog")
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
