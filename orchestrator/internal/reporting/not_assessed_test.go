package reporting

import (
	"strings"
	"testing"
)

// A run where nothing executed must not claim a prevention rate or a risk class. The narrative says why nothing
// was measured, using the veto and skip counts.
func TestNarrative_NotAssessedStatesNothingWasMeasured(t *testing.T) {
	rep := &FullReport{Summary: ExecutiveSummary{
		Assessed:          false,
		Classification:    "Not assessed",
		TotalTechniques:   6,
		VetoedTechniques:  3,
		SkippedTechniques: 3,
	}}
	text := (&rpt{}).narrative(rep)
	if strings.Contains(text, "prevention effectiveness of") {
		t.Errorf("narrative states a prevention effectiveness for a run that executed nothing:\n%s", text)
	}
	if strings.Contains(text, "risk classification of") {
		t.Errorf("narrative states a risk classification for a run that executed nothing:\n%s", text)
	}
	if !strings.Contains(text, "3 technique(s) were vetoed") || !strings.Contains(text, "and 3 were skipped") {
		t.Errorf("narrative does not say why nothing ran:\n%s", text)
	}
}
