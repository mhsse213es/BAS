package rwevidence

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestCapabilityResult_Valid_DelegatesToControlval(t *testing.T) {
	good := CapabilityResult{Verdict: controlval.VerdictSkipped, SkipReason: controlval.SkipNotTested}
	if err := good.Valid(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	bad := CapabilityResult{Verdict: controlval.VerdictFail, SkipReason: controlval.SkipInsufficientEvidence}
	if err := bad.Valid(); err == nil {
		t.Fatal("expected rejection for FAIL carrying a SkipReason")
	}
}

func TestAllShippedProducers_AlwaysProduceValidCapabilityResults(t *testing.T) {
	vss := VSSInhibition()
	encrypt := DataEncryptedForImpact()
	exfil := DataExfiltrationToCloud()

	preventionPass := PreventionFromValidation(vss, controlval.Evaluate(PreventionExpectationFor(vss),
		&controlval.Observation{Outcome: controlval.OutcomeBlocked, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh}, nil))
	preventionSkipped := PreventionFromValidation(vss, controlval.Evaluate(PreventionExpectationFor(vss), nil, nil))

	results := []CapabilityResult{
		preventionPass,
		preventionSkipped,
		RecoveryFromSurvival(vss, SurvivalConfirmed, ""),
		RecoveryFromSurvival(vss, SurvivalLost, ""),
		RecoveryFromSurvival(vss, SurvivalIndeterminate, ""),
		RecoveryResultFor(vss, SurvivalConfirmed, context.DeadlineExceeded, ""),
		DetectionFromProfileResult(vss, true, true, ""),
		DetectionFromProfileResult(vss, true, false, ""),
		DetectionFromProfileResult(vss, false, false, ""),
		DataProtectionFromDLPResult(exfil, "Detected", ""),
		DataProtectionFromDLPResult(exfil, "NotDetected", ""),
		DataProtectionFromDLPResult(exfil, "NotApplicable", ""),
		DataProtectionFromDLPResult(exfil, "Unknown", ""),
		NotApplicable(CapabilityRecovery, encrypt, "T1486 does not apply"),
		NotTested(CapabilityRecovery, vss, "no observer was ever invoked for this run"),
	}
	for i, cr := range results {
		if err := cr.Valid(); err != nil {
			t.Errorf("result[%d] (%s/%s) is invalid: %v", i, cr.Capability, cr.TechniqueID, err)
		}
	}
}

func TestNotTested_IsSkippedWithNotTestedReason(t *testing.T) {
	cr := NotTested(CapabilityRecovery, VSSInhibition(), "no observer was ever invoked for this run")
	if cr.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", cr.Verdict)
	}
	if cr.SkipReason != controlval.SkipNotTested {
		t.Fatalf("skipReason = %q, want not_tested", cr.SkipReason)
	}
	if cr.Capability != CapabilityRecovery {
		t.Fatalf("capability = %q, want recovery", cr.Capability)
	}
	if cr.TechniqueID != "T1490" {
		t.Fatalf("techniqueID = %q, want T1490", cr.TechniqueID)
	}
	if cr.Reason == "" {
		t.Fatal("not_tested must always carry a reason explaining why")
	}
}

func TestNotTested_DistinctFromIndeterminate(t *testing.T) {
	// The gap the pasted testing-protocol review named: "no evaluation
	// performed" (not_tested) must be reachable as something OTHER than
	// "observer ran but came back ambiguous" (insufficient_evidence).
	neverRan := NotTested(CapabilityRecovery, VSSInhibition(), "")
	ranButAmbiguous := RecoveryFromSurvival(VSSInhibition(), SurvivalIndeterminate, "")
	if neverRan.SkipReason == ranButAmbiguous.SkipReason {
		t.Fatalf("not_tested and insufficient_evidence must be distinct reasons, both came back %q", neverRan.SkipReason)
	}
}
