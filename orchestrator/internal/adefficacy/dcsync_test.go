package adefficacy

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestDCSyncPrimitive_IsCatalogEntry(t *testing.T) {
	if DCSyncPrimitive().ID != "dcsync" {
		t.Fatalf("id = %q, want dcsync", DCSyncPrimitive().ID)
	}
}

func TestKeyFor_UsesDcsyncAction(t *testing.T) {
	k := KeyFor("r1", "dc01", controlval.TimeWindow{})
	if k.Action != "dcsync" || k.RunID != "r1" || k.Target != "dc01" {
		t.Fatalf("key = %+v", k)
	}
}

func TestExpectations_PolicyNotVerified(t *testing.T) {
	for _, e := range []controlval.Expectation{NegativeExpectation(), PositiveExpectation()} {
		if e.PolicyVerified {
			t.Fatal("PolicyVerified must be false (lab intended config, not verified)")
		}
		if e.PolicyBasis == "" || e.MinConfidence != controlval.ConfidenceHigh {
			t.Fatalf("expectation under-specified: %+v", e)
		}
	}
	if NegativeExpectation().Expected != controlval.OutcomeBlocked {
		t.Fatal("negative must expect blocked")
	}
	if PositiveExpectation().Expected != controlval.OutcomeAllowed {
		t.Fatal("positive must expect allowed")
	}
}

func eval(t *testing.T, exp controlval.Expectation, d ControlDecision) controlval.Validation {
	t.Helper()
	p := &NativeADProvider{Src: fakeSource{dec: d}}
	obs, err := p.Observe(context.Background(), KeyFor("r1", "dc01", controlval.TimeWindow{}))
	return controlval.Evaluate(exp, &obs, err)
}

func TestEndToEnd_LabuserDeniedIsPass(t *testing.T) {
	v := eval(t, NegativeExpectation(), ControlDecision{DRSUAPI: DRSUAPIAccessDenied, Audit4662: Corroborated, Correlated: true})
	if v.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (control denied unauthorized DCSync)", v.Verdict)
	}
}

func TestEndToEnd_LabuserAllowedIsGapFail(t *testing.T) {
	v := eval(t, NegativeExpectation(), ControlDecision{DRSUAPI: DRSUAPISucceeded, Audit4662: Corroborated, Correlated: true})
	if v.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (unauthorized DCSync succeeded -- control gap)", v.Verdict)
	}
}

func TestEndToEnd_AttackerAllowedIsPass(t *testing.T) {
	v := eval(t, PositiveExpectation(), ControlDecision{DRSUAPI: DRSUAPISucceeded, Audit4662: Corroborated, Correlated: true})
	if v.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (authorized DCSync succeeded)", v.Verdict)
	}
}

func TestEndToEnd_IndeterminateIsSkipped(t *testing.T) {
	v := eval(t, NegativeExpectation(), ControlDecision{DRSUAPI: DRSUAPIIndeterminate, Audit4662: Corroborated, Correlated: true})
	if v.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (ambiguous evidence, no false protection claim)", v.Verdict)
	}
}
