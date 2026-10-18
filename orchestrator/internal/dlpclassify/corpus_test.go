package dlpclassify

import "testing"

func TestNewGroundTruth_ValidInput_Succeeds(t *testing.T) {
	if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClass("pci"), "rationale", "csv", "", "", ""); err != nil {
		t.Fatalf("NewGroundTruth: %v", err)
	}
}

func TestNewGroundTruth_EmptySampleID_Errors(t *testing.T) {
	if _, err := NewGroundTruth("", "hash-001", SensitivityClass("pci"), "rationale", "csv", "", "", ""); err == nil {
		t.Fatal("want error for empty sampleID")
	}
}

func TestNewGroundTruth_EmptyContentHash_Errors(t *testing.T) {
	if _, err := NewGroundTruth("sample-001", "", SensitivityClass("pci"), "rationale", "csv", "", "", ""); err == nil {
		t.Fatal("want error for empty contentHash")
	}
}

func TestNewGroundTruth_EmptyRationale_Errors(t *testing.T) {
	if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClass("pci"), "", "csv", "", "", ""); err == nil {
		t.Fatal("want error for empty rationale")
	}
}

func TestNewGroundTruth_EmptyFormat_Errors(t *testing.T) {
	if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClass("pci"), "rationale", "", "", "", ""); err == nil {
		t.Fatal("want error for empty format")
	}
}

func TestNewGroundTruth_AmbiguousWithoutAdjudicationPolicy_Errors(t *testing.T) {
	if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClassAmbiguous, "rationale", "csv", "", "", ""); err == nil {
		t.Fatal("want error: AdjudicationPolicy required when IntendedClass is Ambiguous")
	}
}

func TestNewGroundTruth_AmbiguousWithAdjudicationPolicy_Succeeds(t *testing.T) {
	if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClassAmbiguous, "rationale", "csv", "", "a benign near-match of a PCI pattern; score as inconclusive", ""); err != nil {
		t.Fatalf("NewGroundTruth: %v", err)
	}
}

func TestNewGroundTruth_NonAmbiguousAdjudicationPolicyNotRequired_Succeeds(t *testing.T) {
	if _, err := NewGroundTruth("sample-001", "hash-001", SensitivityClassNone, "rationale", "csv", "", "", ""); err != nil {
		t.Fatalf("NewGroundTruth: %v", err)
	}
}

func TestValidateCorpus_EmptyCorpus_Succeeds(t *testing.T) {
	if err := ValidateCorpus(nil); err != nil {
		t.Fatalf("ValidateCorpus: %v", err)
	}
}

func TestValidateCorpus_NoIssues_Succeeds(t *testing.T) {
	a, _ := NewGroundTruth("sample-001", "hash-a", SensitivityClass("pci"), "r", "csv", "", "", "")
	b, _ := NewGroundTruth("sample-002", "hash-b", SensitivityClassNone, "r", "pdf", "", "", "")
	if err := ValidateCorpus([]GroundTruth{a, b}); err != nil {
		t.Fatalf("ValidateCorpus: %v", err)
	}
}

func TestValidateCorpus_DuplicateSampleID_Errors(t *testing.T) {
	a, _ := NewGroundTruth("sample-001", "hash-a", SensitivityClass("pci"), "r", "csv", "", "", "")
	b, _ := NewGroundTruth("sample-001", "hash-b", SensitivityClassNone, "r", "pdf", "", "", "")
	if err := ValidateCorpus([]GroundTruth{a, b}); err == nil {
		t.Fatal("want error for duplicate SampleID")
	}
}

func TestValidateCorpus_DanglingTransformationOf_Errors(t *testing.T) {
	a, _ := NewGroundTruth("sample-001", "hash-a", SensitivityClass("pci"), "r", "csv", "sample-nonexistent", "", "")
	if err := ValidateCorpus([]GroundTruth{a}); err == nil {
		t.Fatal("want error for TransformationOf referencing a SampleID absent from the corpus")
	}
}

func TestValidateCorpus_TransformationOfReferencingRealSample_Succeeds(t *testing.T) {
	a, _ := NewGroundTruth("sample-001", "hash-a", SensitivityClass("pci"), "r", "csv", "", "", "")
	b, _ := NewGroundTruth("sample-001-ocr", "hash-b", SensitivityClass("pci"), "r", "scanned-image", "sample-001", "", "")
	if err := ValidateCorpus([]GroundTruth{a, b}); err != nil {
		t.Fatalf("ValidateCorpus: %v", err)
	}
}

func TestValidateCorpus_DuplicateContentHashSameClass_Errors(t *testing.T) {
	a, _ := NewGroundTruth("sample-001", "hash-shared", SensitivityClass("pci"), "r", "csv", "", "", "")
	b, _ := NewGroundTruth("sample-002", "hash-shared", SensitivityClass("pci"), "r", "csv", "", "", "")
	if err := ValidateCorpus([]GroundTruth{a, b}); err == nil {
		t.Fatal("want error for duplicate-content leakage (same ContentHash, same class)")
	}
}

func TestValidateCorpus_DuplicateContentHashDifferentClass_Errors(t *testing.T) {
	a, _ := NewGroundTruth("sample-001", "hash-shared", SensitivityClass("pci"), "r", "csv", "", "", "")
	b, _ := NewGroundTruth("sample-002", "hash-shared", SensitivityClassNone, "r", "csv", "", "", "")
	if err := ValidateCorpus([]GroundTruth{a, b}); err == nil {
		t.Fatal("want error for a contradictory label on identical content")
	}
}
