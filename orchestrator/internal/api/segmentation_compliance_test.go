package api

import "testing"

// Segmentation probes test PCI DSS v4's segmentation requirements. They are not evidence for other frameworks,
// so they must not change those frameworks' scores.
func TestSegmentationEvidenceAppliesOnlyToPCI(t *testing.T) {
	if !segmentationEvidenceApplies("PCI_DSS_V4") {
		t.Fatal("PCI_DSS_V4 must receive segmentation evidence")
	}
	for _, fw := range []string{"RBI_CSF", "NIST_CSF_2", "ISO_27001_2022", "SWIFT_CSCF_2027", ""} {
		if segmentationEvidenceApplies(fw) {
			t.Errorf("%s must not receive segmentation evidence", fw)
		}
	}
}
