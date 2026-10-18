package dlpcorrelate

import (
	"testing"

	"github.com/audspect/bas/internal/reporting"
)

func TestEvaluateChannelConsistency_AllMatch_ConsistentEnforcement(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.Match},
		{Channel: "browser-upload", Comparison: reporting.Match},
		{Channel: "approved-cloud-transfer", Comparison: reporting.Match},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != ConsistentEnforcement {
		t.Errorf("Verdict = %v, want ConsistentEnforcement", got.Verdict)
	}
	if len(got.ChannelResults) != 3 {
		t.Fatalf("ChannelResults len = %d, want 3", len(got.ChannelResults))
	}
}

func TestEvaluateChannelConsistency_AllMismatch_ConsistentFailure(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.Mismatch},
		{Channel: "browser-upload", Comparison: reporting.Mismatch},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != ConsistentFailure {
		t.Errorf("Verdict = %v, want ConsistentFailure (uniform gap, distinct from InconsistentEnforcement)", got.Verdict)
	}
}

func TestEvaluateChannelConsistency_MixedWithOneInconclusive_InconsistentEnforcement(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.Match},
		{Channel: "browser-upload", Comparison: reporting.Mismatch},
		{Channel: "approved-cloud-transfer", Comparison: reporting.MissingEvidence},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != InconsistentEnforcement {
		t.Errorf("Verdict = %v, want InconsistentEnforcement", got.Verdict)
	}
}

func TestEvaluateChannelConsistency_AllMissingEvidence_InsufficientEvidence(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.MissingEvidence},
		{Channel: "browser-upload", Comparison: reporting.MissingEvidence},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != InsufficientEvidence {
		t.Errorf("Verdict = %v, want InsufficientEvidence -- must never default an absence of evidence to looking consistent", got.Verdict)
	}
}

func TestEvaluateChannelConsistency_SingleResult_NeverInconsistent(t *testing.T) {
	results := []ChannelResult{
		{Channel: "usb", Comparison: reporting.Match},
	}
	got, err := EvaluateChannelConsistency(results)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict == InconsistentEnforcement {
		t.Error("a single channel result has nothing to disagree with -- must not be InconsistentEnforcement")
	}
	if got.Verdict != ConsistentEnforcement {
		t.Errorf("Verdict = %v, want ConsistentEnforcement for a single Match", got.Verdict)
	}
}

func TestEvaluateChannelConsistency_EmptyInput_IsError(t *testing.T) {
	_, err := EvaluateChannelConsistency(nil)
	if err == nil {
		t.Error("expected an error for an empty results slice -- nothing to assess consistency over")
	}
}

func TestCampaign02EndpointToCloudLeakage_PreservesChannelLabels(t *testing.T) {
	usb := ChannelResult{Channel: "usb", Comparison: reporting.Match}
	browserUpload := ChannelResult{Channel: "browser-upload", Comparison: reporting.Mismatch}
	cloudTransfer := ChannelResult{Channel: "approved-cloud-transfer", Comparison: reporting.Match}

	got, err := Campaign02EndpointToCloudLeakage(usb, browserUpload, cloudTransfer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Verdict != InconsistentEnforcement {
		t.Errorf("Verdict = %v, want InconsistentEnforcement", got.Verdict)
	}
	foundBrowserMismatch := false
	for _, r := range got.ChannelResults {
		if r.Channel == "browser-upload" && r.Comparison == reporting.Mismatch {
			foundBrowserMismatch = true
		}
	}
	if !foundBrowserMismatch {
		t.Error("ChannelResults must preserve each input's own Channel label so a caller can tell which channel disagreed")
	}
}
