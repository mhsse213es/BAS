package rwevidence

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestPreventionExpectationFor_ExpectsBlocked(t *testing.T) {
	exp := PreventionExpectationFor(VSSInhibition())
	if exp.Expected != controlval.OutcomeBlocked {
		t.Fatalf("expected = %q, want blocked", exp.Expected)
	}
}

func TestPreventionFromValidation_TranslatesVerbatim(t *testing.T) {
	tech := VSSInhibition()
	key := controlval.CorrelationKey{RunID: "r1", Target: "ws01", Action: tech.ID}
	provider := &controlval.FakeProvider{ProviderName: "microsoft_defender", Obs: map[string]controlval.Observation{
		tech.ID: {Outcome: controlval.OutcomeBlocked, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
	}}
	o, err := provider.Observe(context.Background(), key)
	v := controlval.Evaluate(PreventionExpectationFor(tech), &o, err)
	result := PreventionFromValidation(tech, v)
	if result.Capability != CapabilityPrevention {
		t.Fatalf("capability = %q, want prevention", result.Capability)
	}
	if result.TechniqueID != "T1490" {
		t.Fatalf("techniqueID = %q, want T1490", result.TechniqueID)
	}
	if result.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (Defender blocked the attempt)", result.Verdict)
	}
	if result.Provenance != key {
		t.Fatalf("provenance = %+v, want %+v", result.Provenance, key)
	}
}

func TestPreventionFromValidation_NeverOverridesVerdict(t *testing.T) {
	// Adapter-only discipline: a FAIL stays FAIL, never recomputed.
	tech := VSSInhibition()
	allowed := &controlval.Observation{Outcome: controlval.OutcomeAllowed, EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh}
	v := controlval.Evaluate(PreventionExpectationFor(tech), allowed, nil)
	result := PreventionFromValidation(tech, v)
	if result.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (control allowed a destructive attempt through)", result.Verdict)
	}
}
