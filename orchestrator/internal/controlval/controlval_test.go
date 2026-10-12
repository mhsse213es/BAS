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

func TestValidSkipPair_RequiredTestMatrix(t *testing.T) {
	cases := []struct {
		name    string
		verdict Verdict
		reason  SkipReason
		wantErr bool
	}{
		{"valid PASS, empty reason", VerdictPass, "", false},
		{"valid FAIL, empty reason", VerdictFail, "", false},
		{"valid ERROR, empty reason", VerdictError, "", false},
		{"SKIPPED + insufficient_evidence", VerdictSkipped, SkipInsufficientEvidence, false},
		{"SKIPPED + not_applicable", VerdictSkipped, SkipNotApplicable, false},
		{"SKIPPED + not_tested", VerdictSkipped, SkipNotTested, false},
		{"SKIPPED with no reason", VerdictSkipped, "", true},
		{"PASS with a skip reason", VerdictPass, SkipInsufficientEvidence, true},
		{"unknown skip reason", VerdictSkipped, SkipReason("made_up"), true},
	}
	for _, c := range cases {
		err := ValidSkipPair(c.verdict, c.reason)
		if c.wantErr && err == nil {
			t.Errorf("%s: want rejected, got accepted", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: want accepted, got rejected: %v", c.name, err)
		}
	}
}

func TestValidation_Valid_DelegatesToValidSkipPair(t *testing.T) {
	v := Validation{Verdict: VerdictSkipped, SkipReason: SkipInsufficientEvidence}
	if err := v.Valid(); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	bad := Validation{Verdict: VerdictPass, SkipReason: SkipNotTested}
	if err := bad.Valid(); err == nil {
		t.Fatal("expected rejection for PASS carrying a SkipReason")
	}
}

func TestEvaluate_OutputIsAlwaysStructurallyValid(t *testing.T) {
	// Every branch Evaluate can take must produce a Valid() result -- this
	// is the structural counterpart to TestEvaluate_SkippedAlwaysHasRecognizedReason/
	// TestEvaluate_NonSkippedNeverHasSkipReason, checked via the shared
	// validator rather than re-deriving the rule.
	cases := []struct {
		exp Expectation
		obs *Observation
		err error
	}{
		{Expectation{Expected: OutcomeBlocked}, nil, errors.New("api down")},
		{Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, nil, nil},
		{Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceLow}, obs(OutcomeUnknown, EvidenceObserved, ConfidenceHigh), nil},
		{Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeBlocked, EvidenceObserved, ConfidenceLow), nil},
		{Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeBlocked, EvidenceInferred, ConfidenceHigh), nil},
		{Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh), nil},
		{Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeAllowed, EvidenceObserved, ConfidenceHigh), nil},
	}
	for _, c := range cases {
		v := Evaluate(c.exp, c.obs, c.err)
		if err := v.Valid(); err != nil {
			t.Errorf("Evaluate produced an invalid Validation: %v (verdict=%q skipReason=%q)", err, v.Verdict, v.SkipReason)
		}
	}
}

func TestEvaluate_SkippedAlwaysHasRecognizedReason(t *testing.T) {
	recognized := map[SkipReason]bool{
		SkipInsufficientEvidence: true,
		SkipNotApplicable:        true,
		SkipNotTested:            true,
	}
	cases := []struct {
		name string
		exp  Expectation
		obs  *Observation
	}{
		{"nil observation", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, nil},
		{"unknown outcome", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceLow}, obs(OutcomeUnknown, EvidenceObserved, ConfidenceHigh)},
		{"below confidence floor", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeBlocked, EvidenceObserved, ConfidenceLow)},
		{"inferred cannot establish prevention", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeBlocked, EvidenceInferred, ConfidenceHigh)},
	}
	for _, c := range cases {
		v := Evaluate(c.exp, c.obs, nil)
		if v.Verdict != VerdictSkipped {
			t.Fatalf("%s: verdict = %q, want SKIPPED", c.name, v.Verdict)
		}
		if !recognized[v.SkipReason] {
			t.Fatalf("%s: SkipReason = %q, want one of the 3 recognized reasons", c.name, v.SkipReason)
		}
	}
}

func TestEvaluate_NonSkippedNeverHasSkipReason(t *testing.T) {
	cases := []struct {
		name string
		exp  Expectation
		obs  *Observation
		err  error
	}{
		{"error", Expectation{Expected: OutcomeBlocked}, nil, errors.New("api down")},
		{"pass", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh), nil},
		{"fail", Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh}, obs(OutcomeAllowed, EvidenceObserved, ConfidenceHigh), nil},
	}
	for _, c := range cases {
		v := Evaluate(c.exp, c.obs, c.err)
		if v.Verdict == VerdictSkipped {
			t.Fatalf("%s: unexpectedly SKIPPED", c.name)
		}
		if v.SkipReason != "" {
			t.Fatalf("%s: verdict %q has non-empty SkipReason %q, want empty", c.name, v.Verdict, v.SkipReason)
		}
	}
}

func TestEvaluate_UnsetMinConfidenceIsStrict(t *testing.T) {
	// Locked ruling 2 (strict default): an unset MinConfidence resolves to a
	// HIGH floor, so a medium-confidence observed outcome fails closed to
	// SKIPPED rather than silently passing on weak evidence.
	v := Evaluate(Expectation{Expected: OutcomeBlocked}, // MinConfidence unset
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceMedium), nil)
	if v.Verdict != VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (unset floor is strict/high)", v.Verdict)
	}
}

func TestEvaluate_UnsetMinConfidenceHighObservedPasses(t *testing.T) {
	v := Evaluate(Expectation{Expected: OutcomeBlocked}, // MinConfidence unset
		obs(OutcomeBlocked, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictPass {
		t.Fatalf("verdict = %q, want PASS (high clears the strict default floor)", v.Verdict)
	}
}

func TestEvaluate_DifferentPreventionOutcomesFailExactMatch(t *testing.T) {
	// Locked ruling 3 (exact-match): a prevention outcome that is not the EXACT
	// expected one is a FAIL -- the control prevented, but not the way policy
	// specified (terminated session vs blocked auth).
	v := Evaluate(Expectation{Expected: OutcomeBlocked, MinConfidence: ConfidenceHigh},
		obs(OutcomeTerminated, EvidenceObserved, ConfidenceHigh), nil)
	if v.Verdict != VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (terminated != blocked, exact-match)", v.Verdict)
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
