package rwevidence

import (
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestDetectionFromProfileResult_VerifiedIsPass(t *testing.T) {
	cr := DetectionFromProfileResult(VSSInhibition(), true, true, "Defender verified vss-delete-edr")
	if cr.Capability != CapabilityDetection {
		t.Fatalf("capability = %q, want detection", cr.Capability)
	}
	if cr.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for PASS", cr.SkipReason)
	}
}

func TestDetectionFromProfileResult_NotVerifiedIsFail(t *testing.T) {
	cr := DetectionFromProfileResult(VSSInhibition(), true, false, "Defender did not alert")
	if cr.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for FAIL", cr.SkipReason)
	}
}

func TestDetectionFromProfileResult_NotTestedIsSkippedNotTested(t *testing.T) {
	cr := DetectionFromProfileResult(VSSInhibition(), false, false, "")
	if cr.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", cr.Verdict)
	}
	if cr.SkipReason != controlval.SkipNotTested {
		t.Fatalf("skipReason = %q, want not_tested", cr.SkipReason)
	}
}
