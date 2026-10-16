package wafverify

import "testing"

func TestAudspectWAFVerifyCatalog_ReturnsFiveScenariosTotal(t *testing.T) {
	regression, benchmark, reproduction, remediation, coverageGate, err := AudspectWAFVerifyCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFVerifyCatalog: %v", err)
	}
	if len(regression) != 1 {
		t.Errorf("len(regression) = %d, want 1", len(regression))
	}
	if len(benchmark) != 1 {
		t.Errorf("len(benchmark) = %d, want 1", len(benchmark))
	}
	if len(reproduction) != 1 {
		t.Errorf("len(reproduction) = %d, want 1", len(reproduction))
	}
	if len(remediation) != 1 {
		t.Errorf("len(remediation) = %d, want 1", len(remediation))
	}
	if len(coverageGate) != 1 {
		t.Errorf("len(coverageGate) = %d, want 1", len(coverageGate))
	}
}
