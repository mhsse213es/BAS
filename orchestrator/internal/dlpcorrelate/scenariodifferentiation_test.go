package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/reporting"
)

func TestEvaluateScenarioDifferentiation_AllMatch_DifferentiatesCorrectly(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Match},
		{Label: "justified-override", ExpectedToSucceed: true, Comparison: reporting.Match},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Match},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiatesCorrectly {
		t.Errorf("Verdict = %v, want DifferentiatesCorrectly", got.Verdict)
	}
	if len(got.Cases) != 3 {
		t.Fatalf("Cases len = %d, want 3", len(got.Cases))
	}
}

func TestEvaluateScenarioDifferentiation_LegitimateCaseBlocked_OverBlocking(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Mismatch},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Match},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != OverBlocking {
		t.Errorf("Verdict = %v, want OverBlocking (a legitimate case was blocked), not UnderBlocking or any other verdict", got.Verdict)
	}
}

func TestEvaluateScenarioDifferentiation_UnauthorizedCaseGotThrough_UnderBlocking(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Match},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Mismatch},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != UnderBlocking {
		t.Errorf("Verdict = %v, want UnderBlocking (the unauthorized case got through) -- the real-risk finding, must not be masked by the other case's Match", got.Verdict)
	}
}

func TestEvaluateScenarioDifferentiation_BothDirectionsFail_MixedDifferentiationFailure(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Mismatch},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Mismatch},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != MixedDifferentiationFailure {
		t.Errorf("Verdict = %v, want MixedDifferentiationFailure -- must never silently pick just OverBlocking or just UnderBlocking when both are present", got.Verdict)
	}
}

func TestEvaluateScenarioDifferentiation_AllMissingEvidence_InsufficientEvidence(t *testing.T) {
	cases := []ScenarioCase{
		{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.MissingEvidence},
		{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.MissingEvidence},
	}
	got, err := EvaluateScenarioDifferentiation(cases)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiationInsufficientEvidence {
		t.Errorf("Verdict = %v, want DifferentiationInsufficientEvidence -- must never default to DifferentiatesCorrectly", got.Verdict)
	}
}

func TestEvaluateScenarioDifferentiation_EmptyInput_IsError(t *testing.T) {
	_, err := EvaluateScenarioDifferentiation(nil)
	if err == nil {
		t.Error("expected an error for an empty cases slice")
	}
}

func TestCampaign03EmailPolicyAndExceptionFailure_JustifiedOverrideExpectedToSucceed(t *testing.T) {
	normalDelivery := ScenarioCase{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Match}
	justifiedOverride := ScenarioCase{Label: "justified-override", ExpectedToSucceed: true, Comparison: reporting.Match}
	unauthorizedSharing := ScenarioCase{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Match}

	got, err := Campaign03EmailPolicyAndExceptionFailure(normalDelivery, justifiedOverride, unauthorizedSharing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiatesCorrectly {
		t.Errorf("Verdict = %v, want DifferentiatesCorrectly", got.Verdict)
	}
	for _, c := range got.Cases {
		if c.Label == "justified-override" && !c.ExpectedToSucceed {
			t.Error("justified-override must be wired with ExpectedToSucceed=true -- an authorized exception is supposed to succeed, not treated like the unauthorized case")
		}
	}
}

func TestCampaign03EmailPolicyAndExceptionFailure_OverrideWronglyBlocked_OverBlocking(t *testing.T) {
	normalDelivery := ScenarioCase{Label: "normal-delivery", ExpectedToSucceed: true, Comparison: reporting.Match}
	justifiedOverride := ScenarioCase{Label: "justified-override", ExpectedToSucceed: true, Comparison: reporting.Mismatch}
	unauthorizedSharing := ScenarioCase{Label: "unauthorized-sharing", ExpectedToSucceed: false, Comparison: reporting.Match}

	got, err := Campaign03EmailPolicyAndExceptionFailure(normalDelivery, justifiedOverride, unauthorizedSharing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != OverBlocking {
		t.Errorf("Verdict = %v, want OverBlocking -- an authorized override that gets blocked anyway is a false positive, not a safety success", got.Verdict)
	}
}
