package dlpreport

import (
	"testing"

	"github.com/audspect/bas/internal/dlpclassify"
)

func TestClassificationOutcomeFromDLPCLS_TruePositiveAndTrueNegative_AreCorrect(t *testing.T) {
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeTruePositive); got != ClassificationCorrect {
		t.Errorf("OutcomeTruePositive -> %v, want ClassificationCorrect", got)
	}
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeTrueNegative); got != ClassificationCorrect {
		t.Errorf("OutcomeTrueNegative -> %v, want ClassificationCorrect", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_Misclassified_IsIncorrectNotCorrect(t *testing.T) {
	got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeMisclassified)
	if got != ClassificationIncorrect {
		t.Errorf("OutcomeMisclassified -> %v, want ClassificationIncorrect", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_FalsePositiveAndFalseNegative_AreIncorrect(t *testing.T) {
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeFalsePositive); got != ClassificationIncorrect {
		t.Errorf("OutcomeFalsePositive -> %v, want ClassificationIncorrect", got)
	}
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeFalseNegative); got != ClassificationIncorrect {
		t.Errorf("OutcomeFalseNegative -> %v, want ClassificationIncorrect", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_Unsupported_IsUnsupported(t *testing.T) {
	got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeUnsupported)
	if got != ClassificationUnsupported {
		t.Errorf("OutcomeUnsupported -> %v, want ClassificationUnsupported", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_NotTestedAndInconclusive_AreNotEvaluated(t *testing.T) {
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeNotTested); got != ClassificationNotEvaluated {
		t.Errorf("OutcomeNotTested -> %v, want ClassificationNotEvaluated", got)
	}
	if got := ClassificationOutcomeFromDLPCLS(dlpclassify.OutcomeInconclusive); got != ClassificationNotEvaluated {
		t.Errorf("OutcomeInconclusive -> %v, want ClassificationNotEvaluated", got)
	}
}

func TestClassificationOutcomeFromDLPCLS_LabelLifecycleOutcomes_AreUnknownNotCorrect(t *testing.T) {
	labelOutcomes := []dlpclassify.DLPCLSOutcome{
		dlpclassify.OutcomeLabelMissing,
		dlpclassify.OutcomeLabelIncorrect,
		dlpclassify.OutcomeLabelWrongInheritance,
		dlpclassify.OutcomeLabelStale,
		dlpclassify.OutcomeLabelCurrent,
	}
	for _, o := range labelOutcomes {
		if got := ClassificationOutcomeFromDLPCLS(o); got != ClassificationUnknown {
			t.Errorf("%v -> %v, want ClassificationUnknown", o, got)
		}
	}
}

func TestClassificationOutcomeFromDLPCLS_UnrecognizedValue_IsUnknown(t *testing.T) {
	got := ClassificationOutcomeFromDLPCLS(dlpclassify.DLPCLSOutcome("some-future-outcome"))
	if got != ClassificationUnknown {
		t.Errorf("unrecognized outcome -> %v, want ClassificationUnknown", got)
	}
}

func TestRecordValidate_UncertainDimensionWithEmptyLimitations_IsError(t *testing.T) {
	r := Record{Enforcement: EnforcementUnknown, Limitations: ""}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for EnforcementUnknown with empty Limitations, got nil")
	}
}

func TestRecordValidate_UncertainDimensionWithPopulatedLimitations_IsNoError(t *testing.T) {
	r := Record{Enforcement: EnforcementUnknown, Limitations: "local observer could not distinguish Allow from Warn"}
	if err := r.Validate(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRecordValidate_AllCertainWithEmptyLimitations_IsNoError(t *testing.T) {
	r := Record{
		Enforcement:    EnforcementBlocked,
		Classification: ClassificationCorrect,
		Telemetry:      TelemetryPresent,
		Response:       ResponseAlerted,
		Limitations:    "",
	}
	if err := r.Validate(); err != nil {
		t.Errorf("unexpected error for a fully-certain record: %v", err)
	}
}

func TestRecordValidate_TelemetryUnverifiableWithEmptyLimitations_IsError(t *testing.T) {
	r := Record{Telemetry: TelemetryUnverifiable, Limitations: ""}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for TelemetryUnverifiable with empty Limitations, got nil")
	}
}

func TestRecordValidate_ResponseNotTestedWithEmptyLimitations_IsError(t *testing.T) {
	r := Record{Response: ResponseNotTested, Limitations: ""}
	if err := r.Validate(); err == nil {
		t.Fatal("expected an error for ResponseNotTested with empty Limitations, got nil")
	}
}
