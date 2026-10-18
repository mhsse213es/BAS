package dlpclassify

import "testing"

func result(sampleID string, verdict DLPCLSVerdict, observedClass SensitivityClass) SampleResult {
	return SampleResult{SampleID: sampleID, Verdict: verdict, ObservedClass: observedClass}
}

func truthsByID(ts ...GroundTruth) map[string]GroundTruth {
	m := make(map[string]GroundTruth, len(ts))
	for _, t := range ts {
		m[t.SampleID] = t
	}
	return m
}

func TestAggregateCorpusMetrics_EmptyCorpus_ReturnsZeroedUndefinedRates(t *testing.T) {
	got := AggregateCorpusMetrics(nil, nil)
	if got.TotalSamples != 0 {
		t.Errorf("TotalSamples = %d, want 0", got.TotalSamples)
	}
	if got.Precision.Defined {
		t.Error("Precision.Defined = true, want false for an empty corpus")
	}
}

func TestAggregateCorpusMetrics_CountsEachOutcomeCategory(t *testing.T) {
	truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
	truthB, _ := NewGroundTruth("B", "hB", SensitivityClassNone, "r", "csv", "", "", "")
	truthC, _ := NewGroundTruth("C", "hC", SensitivityClass("pci"), "r", "csv", "", "", "")
	samples := []SampleResult{
		result("A", DLPCLSVerdict{Outcome: OutcomeTruePositive}, SensitivityClass("pci")),
		result("B", DLPCLSVerdict{Outcome: OutcomeFalsePositive}, SensitivityClass("pci")),
		result("C", DLPCLSVerdict{Outcome: OutcomeInconclusive}, ""),
	}
	got := AggregateCorpusMetrics(samples, truthsByID(truthA, truthB, truthC))
	if got.TotalSamples != 3 {
		t.Errorf("TotalSamples = %d, want 3", got.TotalSamples)
	}
	if got.Evaluated != 2 {
		t.Errorf("Evaluated = %d, want 2", got.Evaluated)
	}
	if got.Inconclusive != 1 {
		t.Errorf("Inconclusive = %d, want 1", got.Inconclusive)
	}
	if got.TruePositives != 1 || got.FalsePositives != 1 {
		t.Errorf("TruePositives=%d FalsePositives=%d, want 1,1", got.TruePositives, got.FalsePositives)
	}
}

func TestAggregateCorpusMetrics_MisclassifiedExcludedFromBinaryCounters(t *testing.T) {
	truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
	samples := []SampleResult{result("A", DLPCLSVerdict{Outcome: OutcomeMisclassified}, SensitivityClass("phi"))}
	got := AggregateCorpusMetrics(samples, truthsByID(truthA))
	if got.Misclassified != 1 {
		t.Errorf("Misclassified = %d, want 1", got.Misclassified)
	}
	if got.TruePositives != 0 || got.FalsePositives != 0 || got.FalseNegatives != 0 || got.TrueNegatives != 0 {
		t.Error("a Misclassified verdict must not increment any binary counter")
	}
	if got.Evaluated != 1 {
		t.Errorf("Evaluated = %d, want 1 -- Misclassified still counts toward Evaluated", got.Evaluated)
	}
}

func TestAggregateCorpusMetrics_PrecisionUndefinedWhenNoPositivesFired(t *testing.T) {
	truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
	samples := []SampleResult{result("A", DLPCLSVerdict{Outcome: OutcomeFalseNegative}, "")}
	got := AggregateCorpusMetrics(samples, truthsByID(truthA))
	if got.Precision.Defined {
		t.Error("Precision.Defined = true, want false -- the product never fired a positive classification at all")
	}
}

func TestAggregateCorpusMetrics_PrecisionDefinedWhenPositivesExist(t *testing.T) {
	truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
	truthB, _ := NewGroundTruth("B", "hB", SensitivityClassNone, "r", "csv", "", "", "")
	samples := []SampleResult{
		result("A", DLPCLSVerdict{Outcome: OutcomeTruePositive}, SensitivityClass("pci")),
		result("B", DLPCLSVerdict{Outcome: OutcomeFalsePositive}, SensitivityClass("pci")),
	}
	got := AggregateCorpusMetrics(samples, truthsByID(truthA, truthB))
	if !got.Precision.Defined {
		t.Fatal("Precision.Defined = false, want true")
	}
	if got.Precision.Value != 0.5 {
		t.Errorf("Precision.Value = %v, want 0.5", got.Precision.Value)
	}
}

func TestAggregateCorpusMetrics_RecallUndefinedWhenNoSensitiveTruthExists(t *testing.T) {
	truthB, _ := NewGroundTruth("B", "hB", SensitivityClassNone, "r", "csv", "", "", "")
	samples := []SampleResult{result("B", DLPCLSVerdict{Outcome: OutcomeTrueNegative}, "")}
	got := AggregateCorpusMetrics(samples, truthsByID(truthB))
	if got.Recall.Defined {
		t.Error("Recall.Defined = true, want false -- no TruePositive or FalseNegative exists")
	}
}

func TestAggregateCorpusMetrics_ConfusionMatrixBenignKeyIsSensitivityClassNoneNotEmptyString(t *testing.T) {
	truthA, _ := NewGroundTruth("A", "hA", SensitivityClassNone, "r", "csv", "", "", "")
	samples := []SampleResult{result("A", DLPCLSVerdict{Outcome: OutcomeTrueNegative}, "")}
	got := AggregateCorpusMetrics(samples, truthsByID(truthA))
	row, ok := got.ConfusionMatrix[SensitivityClassNone]
	if !ok {
		t.Fatal("ConfusionMatrix has no row for SensitivityClassNone")
	}
	if row[SensitivityClassNone] != 1 {
		t.Errorf("ConfusionMatrix[none][none] = %d, want 1 -- the benign observed-axis key must be SensitivityClassNone, not the empty string", row[SensitivityClassNone])
	}
	if _, badKey := row[""]; badKey {
		t.Error("ConfusionMatrix must not use the empty string as an observed-axis key")
	}
}

func TestAggregateCorpusMetrics_ConfusionMatrixMisclassifiedOffDiagonalCell(t *testing.T) {
	truthA, _ := NewGroundTruth("A", "hA", SensitivityClass("pci"), "r", "csv", "", "", "")
	samples := []SampleResult{result("A", DLPCLSVerdict{Outcome: OutcomeMisclassified}, SensitivityClass("phi"))}
	got := AggregateCorpusMetrics(samples, truthsByID(truthA))
	if got.ConfusionMatrix[SensitivityClass("pci")][SensitivityClass("phi")] != 1 {
		t.Error("ConfusionMatrix[pci][phi] must be 1 for a PCI sample misclassified as PHI")
	}
}

func TestCompareChannelVerdicts_SameOutcome_ReturnsTrue(t *testing.T) {
	a := DLPCLSVerdict{Outcome: OutcomeTruePositive}
	b := DLPCLSVerdict{Outcome: OutcomeTruePositive, Reason: "irrelevant metadata difference"}
	if !CompareChannelVerdicts(a, b) {
		t.Error("want true -- same Outcome must agree regardless of Reason text")
	}
}

func TestCompareChannelVerdicts_DifferentOutcome_ReturnsFalse(t *testing.T) {
	a := DLPCLSVerdict{Outcome: OutcomeTruePositive}
	b := DLPCLSVerdict{Outcome: OutcomeFalseNegative}
	if CompareChannelVerdicts(a, b) {
		t.Error("want false for differing Outcome")
	}
}
