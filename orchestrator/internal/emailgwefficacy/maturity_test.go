package emailgwefficacy

import "testing"

func simpleEntry(ids ...string) ScenarioRegistryEntry {
	return ScenarioRegistryEntry{ScenarioID: "TEST", Name: "test", ExpectationIDs: ids}
}

func TestClassifyScenarioMaturity_NoRecordsAtAll_ImplementedNotExecutable(t *testing.T) {
	entry := simpleEntry("a.known-good", "a.known-bad")
	got := ClassifyScenarioMaturity(entry, nil)
	if got != MaturityImplementedNotExecutable {
		t.Errorf("got %q, want %q -- a registry entry with zero attempted records must never be read as executed", got, MaturityImplementedNotExecutable)
	}
}

func TestClassifyScenarioMaturity_FixtureOnlyRecord_ExecutedWithoutEvidence(t *testing.T) {
	entry := simpleEntry("a.known-good")
	records := []ScenarioExecutionRecord{
		{ExpectationID: "a.known-good", Verdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: false},
	}
	got := ClassifyScenarioMaturity(entry, records)
	if got != MaturityExecutedWithoutEvidence {
		t.Errorf("got %q, want %q -- a fixture-only record (ViaLiveAdapter=false) must never count as verified", got, MaturityExecutedWithoutEvidence)
	}
}

func TestClassifyScenarioMaturity_LiveButInconclusive_ExecutedWithoutEvidence(t *testing.T) {
	entry := simpleEntry("a.known-good")
	records := []ScenarioExecutionRecord{
		{ExpectationID: "a.known-good", Verdict: VerdictDetail{Verdict: VerdictInconclusive}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
	}
	got := ClassifyScenarioMaturity(entry, records)
	if got != MaturityExecutedWithoutEvidence {
		t.Errorf("got %q, want %q -- Inconclusive must never be read as verification", got, MaturityExecutedWithoutEvidence)
	}
}

func TestClassifyScenarioMaturity_LiveButNotTested_ExecutedWithoutEvidence(t *testing.T) {
	entry := simpleEntry("a.known-good")
	records := []ScenarioExecutionRecord{
		{ExpectationID: "a.known-good", Verdict: VerdictDetail{Verdict: VerdictNotTested}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
	}
	got := ClassifyScenarioMaturity(entry, records)
	if got != MaturityExecutedWithoutEvidence {
		t.Errorf("got %q, want %q -- NotTested must never be read as verification", got, MaturityExecutedWithoutEvidence)
	}
}

func TestClassifyScenarioMaturity_LiveDefinitiveButInferredProvenance_ExecutedWithoutEvidence(t *testing.T) {
	entry := simpleEntry("a.known-good")
	records := []ScenarioExecutionRecord{
		{ExpectationID: "a.known-good", Verdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}, Provenance: Provenance{Kind: ProvenanceInferred, Basis: "guessed"}, ViaLiveAdapter: true},
	}
	got := ClassifyScenarioMaturity(entry, records)
	if got != MaturityExecutedWithoutEvidence {
		t.Errorf("got %q, want %q -- Inferred provenance must never count as sufficient evidence, even with a definitive verdict", got, MaturityExecutedWithoutEvidence)
	}
}

func TestClassifyScenarioMaturity_OneOfTwoRequiredIDsQualifies_ExecutedWithoutEvidence(t *testing.T) {
	entry := simpleEntry("a.known-good", "a.known-bad")
	records := []ScenarioExecutionRecord{
		{ExpectationID: "a.known-good", Verdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
		// a.known-bad never attempted at all
	}
	got := ClassifyScenarioMaturity(entry, records)
	if got != MaturityExecutedWithoutEvidence {
		t.Errorf("got %q, want %q -- proving only the known-good direction must never be read as the scenario being fully verified", got, MaturityExecutedWithoutEvidence)
	}
}

func TestClassifyScenarioMaturity_BothDirectionsLiveDefinitiveObserved_VerifiedThroughExecution(t *testing.T) {
	entry := simpleEntry("a.known-good", "a.known-bad")
	records := []ScenarioExecutionRecord{
		{ExpectationID: "a.known-good", Verdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
		{ExpectationID: "a.known-bad", Verdict: VerdictDetail{Verdict: VerdictConfirmedFailure}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
	}
	got := ClassifyScenarioMaturity(entry, records)
	if got != MaturityVerifiedThroughExecution {
		t.Errorf("got %q, want %q", got, MaturityVerifiedThroughExecution)
	}
}

// TestClassifyScenarioMaturity_DefinitiveFailureQualifiesJustLikeSuccess
// is the explicit rule: a definitive ConfirmedFailure proves a
// weakness exists -- it is not read as the control having passed, but
// it IS a valid, qualifying verification of what actually happens,
// exactly as much as a ConfirmedSuccess is.
func TestClassifyScenarioMaturity_DefinitiveFailureQualifiesJustLikeSuccess(t *testing.T) {
	entry := simpleEntry("a.known-bad")
	records := []ScenarioExecutionRecord{
		{ExpectationID: "a.known-bad", Verdict: VerdictDetail{Verdict: VerdictConfirmedFailure, Reason: "gateway delivered a message expected to be quarantined"}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
	}
	got := ClassifyScenarioMaturity(entry, records)
	if got != MaturityVerifiedThroughExecution {
		t.Errorf("got %q, want %q -- a definitive, well-evidenced failure is itself a verified finding", got, MaturityVerifiedThroughExecution)
	}
}

func TestClassifyScenarioMaturity_Correlation_IndependentlyQualifyingButDifferentKeys_ExecutedWithoutEvidence(t *testing.T) {
	entry := ScenarioRegistryEntry{ScenarioID: "TEST", ExpectationIDs: []string{"x.detection", "x.response"}, RequiresCorrelation: true}
	records := []ScenarioExecutionRecord{
		{ExpectationID: "x.detection", CorrelationKey: "run-1", Verdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
		{ExpectationID: "x.response", CorrelationKey: "run-2", Verdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
	}
	got := ClassifyScenarioMaturity(entry, records)
	if got != MaturityExecutedWithoutEvidence {
		t.Errorf("got %q, want %q -- two independently-qualifying records from DIFFERENT runs must never satisfy a correlation requirement; they must share one CorrelationKey", got, MaturityExecutedWithoutEvidence)
	}
}

func TestClassifyScenarioMaturity_Correlation_SameKeyBothQualify_VerifiedThroughExecution(t *testing.T) {
	entry := ScenarioRegistryEntry{ScenarioID: "TEST", ExpectationIDs: []string{"x.detection", "x.response"}, RequiresCorrelation: true}
	records := []ScenarioExecutionRecord{
		{ExpectationID: "x.detection", CorrelationKey: "alert-1", Verdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
		{ExpectationID: "x.response", CorrelationKey: "alert-1", Verdict: VerdictDetail{Verdict: VerdictConfirmedSuccess}, Provenance: Provenance{Kind: ProvenanceObserved}, ViaLiveAdapter: true},
	}
	got := ClassifyScenarioMaturity(entry, records)
	if got != MaturityVerifiedThroughExecution {
		t.Errorf("got %q, want %q", got, MaturityVerifiedThroughExecution)
	}
}

func TestBuildScenarioMaturityReport_UnregisteredID_NotImplemented(t *testing.T) {
	report := BuildScenarioMaturityReport(nil, nil)
	if len(report) != len(AllEmailGWScenarioIDs()) {
		t.Fatalf("report has %d rows, want %d -- every catalogue ID must get a row even with an empty registry", len(report), len(AllEmailGWScenarioIDs()))
	}
	for _, row := range report {
		if row.Maturity != MaturityNotImplemented {
			t.Errorf("row %q = %q, want %q for an empty registry", row.ScenarioID, row.Maturity, MaturityNotImplemented)
		}
	}
}

func TestBuildScenarioMaturityReport_NeverSkipsACatalogueID(t *testing.T) {
	report := BuildScenarioMaturityReport(EmailGWScenarioRegistry(), nil)
	seen := map[string]bool{}
	for _, row := range report {
		seen[row.ScenarioID] = true
	}
	for _, id := range AllEmailGWScenarioIDs() {
		if !seen[id] {
			t.Errorf("catalogue ID %q is missing from the report", id)
		}
	}
}
