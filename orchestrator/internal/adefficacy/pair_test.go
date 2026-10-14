package adefficacy

import (
	"testing"

	"github.com/audspect/bas/internal/adcontrolval"
	"github.com/audspect/bas/internal/controlval"
)

func pass() controlval.Validation {
	return controlval.Validation{Verdict: controlval.VerdictPass, Reason: "ok"}
}

func TestPair_NegativePassAcceptedWhenPositivePass(t *testing.T) {
	v, _ := Pair{Positive: pass(), Negative: pass()}.AcceptedNegativeVerdict()
	if v != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (positive succeeded, denial trustworthy)", v)
	}
}

func TestPair_NegativePassNotTrustedWhenPositiveNotPass(t *testing.T) {
	// Positive control FAILED: the negative denial must NOT be a trustworthy PASS.
	neg := pass()
	v, reason := Pair{Positive: controlval.Validation{Verdict: controlval.VerdictFail}, Negative: neg}.AcceptedNegativeVerdict()
	if v != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (harness not shown capable of success)", v)
	}
	if reason == "" {
		t.Fatal("downgrade must carry a reason")
	}
}

func TestPair_DoesNotMutateRawOrUpgrade(t *testing.T) {
	neg := pass()
	p := Pair{Positive: controlval.Validation{Verdict: controlval.VerdictFail}, Negative: neg}
	_, _ = p.AcceptedNegativeVerdict()
	if p.Negative.Verdict != controlval.VerdictPass {
		t.Fatal("raw negative Validation must be untouched")
	}
	// Never upgrades: a negative FAIL stays FAIL even if positive passed.
	v2, _ := Pair{Positive: pass(), Negative: controlval.Validation{Verdict: controlval.VerdictFail}}.AcceptedNegativeVerdict()
	if v2 != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (never upgraded)", v2)
	}
}

func TestMapping_ThroughAdcontrolvalIsFaithful(t *testing.T) {
	v := controlval.Validation{
		Verdict:     controlval.VerdictPass,
		Expectation: controlval.Expectation{Expected: controlval.OutcomeBlocked},
		Observation: &controlval.Observation{Provider: "native-ad", Outcome: controlval.OutcomeBlocked,
			EvidenceKind: controlval.EvidenceObserved, Confidence: controlval.ConfidenceHigh},
	}
	s := adcontrolval.ToEfficacyState(v)
	if !s.Evaluated || s.Verdict != "PASS" || s.Provider != "native-ad" || s.Observed != "blocked" {
		t.Fatalf("mapping not faithful: %+v", s)
	}
}
