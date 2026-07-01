package compliance

import (
	"testing"
)

func TestFrameworksLoad(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	fws := m.Frameworks()
	ids := make(map[string]int, len(fws))
	for _, fw := range fws {
		ids[fw.ID] = fw.TotalControls
		t.Logf("%-20s  %-40s  controls=%d", fw.ID, fw.Name, fw.TotalControls)
	}
	want := []string{"CERT_IN", "IRDAI_CSF", "ISO_27001_2022", "NIST_CSF_2", "PCI_DSS_V4", "RBI_CSF", "SEBI_CSCRF"}
	for _, id := range want {
		if ids[id] == 0 {
			t.Errorf("framework %s missing or has 0 controls", id)
		}
	}
	if ids["PCI_DSS_V4"] < 40 {
		t.Errorf("PCI_DSS_V4 has only %d controls, expected >=40", ids["PCI_DSS_V4"])
	}
}
