package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/reporting"
)

func TestCampaign06BusinessContinuityVersusDataProtection_AllCorrect_DifferentiatesCorrectly(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "finance shares quarterly report via approved SharePoint link", ExpectedToSucceed: true, Comparison: reporting.Match, Reason: "allowed as expected"},
	}
	prohibited := []ScenarioCase{
		{Label: "unauthorized bulk export to personal email", ExpectedToSucceed: false, Comparison: reporting.Match, Reason: "blocked as expected"},
	}
	got, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiatesCorrectly {
		t.Errorf("Verdict = %v, want DifferentiatesCorrectly", got.Verdict)
	}
	if len(got.Cases) != 2 {
		t.Errorf("len(Cases) = %d, want 2", len(got.Cases))
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_LegitimateCaseBlocked_OverBlocking(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "HR shares offer letter via approved vendor portal", ExpectedToSucceed: true, Comparison: reporting.Mismatch, Reason: "wrongly blocked"},
	}
	prohibited := []ScenarioCase{
		{Label: "unauthorized bulk export to personal email", ExpectedToSucceed: false, Comparison: reporting.Match, Reason: "blocked as expected"},
	}
	got, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != OverBlocking {
		t.Errorf("Verdict = %v, want OverBlocking", got.Verdict)
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_ProhibitedCaseGotThrough_UnderBlocking(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "finance shares quarterly report via approved SharePoint link", ExpectedToSucceed: true, Comparison: reporting.Match, Reason: "allowed as expected"},
	}
	prohibited := []ScenarioCase{
		{Label: "unauthorized bulk export to personal email", ExpectedToSucceed: false, Comparison: reporting.Mismatch, Reason: "wrongly allowed through"},
	}
	got, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, prohibited)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != UnderBlocking {
		t.Errorf("Verdict = %v, want UnderBlocking", got.Verdict)
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_LegitimateCaseFlaggedProhibited_IsError(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "mislabeled case", ExpectedToSucceed: false, Comparison: reporting.Match},
	}
	_, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, nil)
	if err == nil {
		t.Fatal("expected an error for a legitimate-bucket case with ExpectedToSucceed=false, got nil")
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_ProhibitedCaseFlaggedLegitimate_IsError(t *testing.T) {
	prohibited := []ScenarioCase{
		{Label: "mislabeled case", ExpectedToSucceed: true, Comparison: reporting.Match},
	}
	_, err := Campaign06BusinessContinuityVersusDataProtection(nil, prohibited)
	if err == nil {
		t.Fatal("expected an error for a prohibited-bucket case with ExpectedToSucceed=true, got nil")
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_OneBucketEmpty_StillEvaluates(t *testing.T) {
	legitimate := []ScenarioCase{
		{Label: "finance shares quarterly report via approved SharePoint link", ExpectedToSucceed: true, Comparison: reporting.Match, Reason: "allowed as expected"},
	}
	got, err := Campaign06BusinessContinuityVersusDataProtection(legitimate, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != DifferentiatesCorrectly {
		t.Errorf("Verdict = %v, want DifferentiatesCorrectly", got.Verdict)
	}
}

func TestCampaign06BusinessContinuityVersusDataProtection_BothBucketsEmpty_IsError(t *testing.T) {
	_, err := Campaign06BusinessContinuityVersusDataProtection(nil, nil)
	if err == nil {
		t.Fatal("expected an error for both buckets empty, got nil")
	}
}
