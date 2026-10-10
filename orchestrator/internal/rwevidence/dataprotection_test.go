package rwevidence

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/controlval"
)

func TestDataExfiltrationToCloud_StableIdentity(t *testing.T) {
	tech := DataExfiltrationToCloud()
	if tech.ID != "data-exfiltration-to-cloud" {
		t.Fatalf("id = %q", tech.ID)
	}
	if tech.MitreID != "T1567.002" {
		t.Fatalf("mitreID = %q, want T1567.002", tech.MitreID)
	}
	if tech.RiskClass != adprimitive.RiskNonDestructive {
		t.Fatalf("riskClass = %q, want non_destructive (reachability probe only, no upload -- matches clop-kill-chain.yaml Stage 4's own comment)", tech.RiskClass)
	}
}

func TestDataProtectionFromDLPResult_DetectedIsPass(t *testing.T) {
	cr := DataProtectionFromDLPResult(DataExfiltrationToCloud(), "Detected", "DLP policy blocked the staged-file transfer")
	if cr.Capability != CapabilityDataProtection {
		t.Fatalf("capability = %q, want data_protection", cr.Capability)
	}
	if cr.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for PASS", cr.SkipReason)
	}
}

func TestDataProtectionFromDLPResult_NotDetectedIsFail(t *testing.T) {
	cr := DataProtectionFromDLPResult(DataExfiltrationToCloud(), "NotDetected", "DLP policy did not intervene")
	if cr.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for FAIL", cr.SkipReason)
	}
}

func TestDataProtectionFromDLPResult_NotApplicableIsSkippedNotApplicable(t *testing.T) {
	cr := DataProtectionFromDLPResult(DataExfiltrationToCloud(), "NotApplicable", "no DLP product deployed in this environment")
	if cr.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", cr.Verdict)
	}
	if cr.SkipReason != controlval.SkipNotApplicable {
		t.Fatalf("skipReason = %q, want not_applicable", cr.SkipReason)
	}
}

func TestDataProtectionFromDLPResult_UnknownOrUnrecognizedIsSkippedInsufficientEvidence(t *testing.T) {
	for _, status := range []string{"Unknown", "something-unrecognized"} {
		cr := DataProtectionFromDLPResult(DataExfiltrationToCloud(), status, "")
		if cr.Verdict != controlval.VerdictSkipped {
			t.Fatalf("status %q: verdict = %q, want SKIPPED", status, cr.Verdict)
		}
		if cr.SkipReason != controlval.SkipInsufficientEvidence {
			t.Fatalf("status %q: skipReason = %q, want insufficient_evidence (fail closed on anything unrecognized)", status, cr.SkipReason)
		}
	}
}
