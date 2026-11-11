package riskinputs

import (
	"testing"

	"github.com/audspect/bas/internal/riskquant"
)

// Only open findings in the report count. An input for a technique that is not open is ignored, and a
// technique listed twice counts once.
func TestExposuresForReportCountsOnlyOpenFindings(t *testing.T) {
	inputs := []Input{
		{TechniqueID: "T1", Label: "one", Frequency: riskquant.Range{Low: 1, Likely: 1, High: 1}, Magnitude: riskquant.Range{Low: 5, Likely: 5, High: 5}},
		{TechniqueID: "T3", Label: "not open", Frequency: riskquant.Range{Low: 9, Likely: 9, High: 9}, Magnitude: riskquant.Range{Low: 9, Likely: 9, High: 9}},
	}
	open := []OpenFinding{{TechniqueID: "T1", Label: "Phishing"}, {TechniqueID: "T2", Label: "Lateral"}, {TechniqueID: "T1", Label: "Phishing"}}
	got := ExposuresForReport(open, inputs)
	if len(got) != 2 {
		t.Fatalf("exposures = %d, want 2 (T1 once, T2)", len(got))
	}
	if got[0].ID != "T1" || got[0].Frequency == nil || got[0].Magnitude == nil {
		t.Errorf("T1 must carry its inputs, got %+v", got[0])
	}
	if got[1].ID != "T2" || got[1].Frequency != nil {
		t.Errorf("T2 has no input and must be unquantified, got %+v", got[1])
	}
}

// A report with open findings but no inputs for them has no loss figure to show.
func TestAnyInputReportsWhetherAnyExposureIsQuantified(t *testing.T) {
	none := ExposuresForReport([]OpenFinding{{TechniqueID: "T2"}}, nil)
	if AnyInput(none) {
		t.Error("no inputs for open findings: AnyInput must be false")
	}
	some := ExposuresForReport([]OpenFinding{{TechniqueID: "T1"}}, []Input{{TechniqueID: "T1", Frequency: riskquant.Range{Low: 1, Likely: 1, High: 1}, Magnitude: riskquant.Range{Low: 1, Likely: 1, High: 1}}})
	if !AnyInput(some) {
		t.Error("an input for an open finding: AnyInput must be true")
	}
}
