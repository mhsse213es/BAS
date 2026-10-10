package controlval

import (
	"errors"
	"testing"
)

func obs(o Outcome, ek EvidenceKind, c Confidence) *Observation {
	return &Observation{Provider: "fake", Outcome: o, EvidenceKind: ek, Confidence: c, Source: "test"}
}

func TestEvaluate_ObservedMatchExpectationPasses(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh},
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictPass {
		t.Fatalf("verdict = %q, want PASS (%s)", v.Verdict, v.Reason)
	}
}

func TestEvaluate_ExpectedBlockObservedAllowedIsGapFail(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh},
		obs(OutcomeAllowed, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", v.Verdict)
	}
	if v.Reason == "" {
		t.Fatal("gap FAIL must carry a reason")
	}
}

func TestEvaluate_ExpectedAllowedObservedBlockedIsUnexpectedDenial(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeAllowed, MinConfidence: ConfidenceHigh},
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (unexpected denial)", v.Verdict)
	}
}

func TestEvaluate_ProviderErrorIsError(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked}, nil, errors.New("api down"))
	if v.Verdict != VerdictError {
		t.Fatalf("verdict = %q, want ERROR", v.Verdict)
	}
}

func TestEvaluate_ErrorTakesPrecedenceOverObservation(t *testing.T) {
	// Criterion 4: a technical error yields ERROR even when an observation is
	// present; the observation must not manufacture a verdict.
	o := obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh)
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, o, errors.New("api down"))
	if v.Verdict != VerdictError {
		t.Fatalf("verdict = %q, want ERROR (error precedes a present observation)", v.Verdict)
	}
}

func TestEvaluate_MissingObservationIsSkipped(t *testing.T) { // Invariant B
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, nil, nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (missing stream must never be fabricated)", v.Verdict)
	}
}

func TestEvaluate_UnknownOutcomeIsSkipped(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceLow},
		obs(OutcomeUnknown, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", v.Verdict)
	}
}

func TestEvaluate_BelowConfidenceFloorIsSkipped(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh},
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceLow), nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (below floor)", v.Verdict)
	}
}

func TestEvaluate_NoneConfidenceIsSkipped(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceNone},
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceNone), nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (none confidence is never sufficient)", v.Verdict)
	}
}

func TestEvaluate_InferredPreventionIsSkipped(t *testing.T) { // Invariant A
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh},
		obs(OutcomeBlocked, EvidenceInferred, ConfidenceHigh), nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (inferred cannot establish prevention)", v.Verdict)
	}
}

func TestEvaluate_InferredAllowedCanPass(t *testing.T) {
	// Allowed is NOT a prevention outcome, so inferred evidence may ground it.
	v := Evaluate(Expectation{Expected: OutcomeAllowed, MinConfidence: ConfidenceHigh},
		obs(OutcomeAllowed, EvidenceInferred, ConfidenceHigh), nil)
	if v.Verdict != VerdictPass {
		t.Fatalf("verdict = %q, want PASS", v.Verdict)
	}
}

func TestEvaluate_CarriesObservationKey(t *testing.T) {
	o := obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh)
	o.Key = CorrelationKey{RunID: "r1", Target: "dc01", Action: "dcsync"}
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, o, nil)
	if v.Key.Action != "dcsync" {
		t.Fatalf("key.Action = %q, want dcsync", v.Key.Action)
	}
}

func TestEvaluate_DoesNotAlterPolicyVerified(t *testing.T) {
	// Criterion 5: a test-supplied rationale with PolicyVerified=false must stay
	// false; Evaluate never asserts a policy was verified.
	exp := Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh,
		PolicyBasis: "virtual-fencing policy", PolicyVerified: false}
	v := Evaluate(exp, obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh), nil)
	if v.Expectation.PolicyVerified {
		t.Fatal("Evaluate must never set PolicyVerified true")
	}
}

func TestEvaluate_IsDeterministic(t *testing.T) {
	// Criterion 6: same inputs -> same output, no hidden state/clock/provider.
	exp := Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}
	o := obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh)
	first := Evaluate(exp, o, nil)
	for i := 0; i < 100; i++ {
		got := Evaluate(exp, o, nil)
		if got.Verdict != first.Verdict || got.Reason != first.Reason {
			t.Fatalf("non-deterministic: %q/%q vs %q/%q", got.Verdict, got.Reason, first.Verdict, first.Reason)
		}
	}
}
