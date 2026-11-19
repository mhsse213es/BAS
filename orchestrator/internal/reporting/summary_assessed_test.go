package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// A score stored before NotAssessed existed has no flag. A run whose stored counts show no executed step must still
// be reported as not assessed, not as "Protected" from its 0% score.
func TestSummaryClassification_StoredRunWithNoExecutedStepIsNotAssessed(t *testing.T) {
	stored := models.Score{Classification: "Protected", RiskScore: 0, VetoedTechniques: 3, SkippedTechniques: 3}
	if got := summaryClassification(stored); got != "Not assessed" {
		t.Errorf("summaryClassification = %q, want Not assessed", got)
	}
	if scoreAssessed(stored) {
		t.Error("scoreAssessed = true for a stored run with no executed step")
	}
}

func TestSummaryClassification_ExecutedRunKeepsClassification(t *testing.T) {
	ok := models.Score{Classification: "Low Risk", PassedTechniques: 4, FailedTechniques: 1}
	if got := summaryClassification(ok); got != "Low Risk" {
		t.Errorf("summaryClassification = %q, want Low Risk", got)
	}
}
