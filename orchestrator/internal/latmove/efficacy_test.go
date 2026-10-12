package latmove

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func ckey(runID, target string) controlval.CorrelationKey {
	return controlval.CorrelationKey{RunID: runID, Target: target, Action: WMIRemoteProcessCreation().ID}
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
		t.Fatal("negative (unprivileged) must expect blocked")
	}
	if PositiveExpectation().Expected != controlval.OutcomeAllowed {
		t.Fatal("positive (authorized) must expect allowed")
	}
}

func TestControlProvider_ExecutedMapsToAllowedHighConfidence(t *testing.T) {
	obs := Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}}
	p := &ControlProvider{Obs: &FakeObserver{Obs: map[string]Observation{"r1/" + WMIRemoteProcessCreation().ID: obs}}}
	got, err := p.Observe(context.Background(), ckey("r1", "ws02"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != controlval.OutcomeAllowed || got.Confidence != controlval.ConfidenceHigh || got.EvidenceKind != controlval.EvidenceObserved {
		t.Fatalf("got %+v, want allowed/high/observed", got)
	}
}

func TestControlProvider_AccessDeniedMapsToBlocked(t *testing.T) {
	obs := Observation{Call: CallAccessDenied, Marker: MarkerCheck{Correlated: true, Found: false}}
	p := &ControlProvider{Obs: &FakeObserver{Obs: map[string]Observation{"r1/" + WMIRemoteProcessCreation().ID: obs}}}
	got, _ := p.Observe(context.Background(), ckey("r1", "ws02"))
	if got.Outcome != controlval.OutcomeBlocked || got.Confidence != controlval.ConfidenceHigh {
		t.Fatalf("got %+v, want blocked/high", got)
	}
}

func TestControlProvider_IndeterminateMapsToUnknownNoneConfidence(t *testing.T) {
	obs := Observation{Call: CallUnknown, Marker: MarkerCheck{Correlated: false}}
	p := &ControlProvider{Obs: &FakeObserver{Obs: map[string]Observation{"r1/" + WMIRemoteProcessCreation().ID: obs}}}
	got, _ := p.Observe(context.Background(), ckey("r1", "ws02"))
	if got.Outcome != controlval.OutcomeUnknown || got.Confidence != controlval.ConfidenceNone {
		t.Fatalf("got %+v, want unknown/none (ambiguous evidence must never be promoted)", got)
	}
}

func TestControlProvider_ObserverErrorPropagates(t *testing.T) {
	p := &ControlProvider{Obs: &FakeObserver{Err: map[string]error{"boom/" + WMIRemoteProcessCreation().ID: errors.New("wmi down")}}}
	if _, err := p.Observe(context.Background(), ckey("boom", "ws02")); err == nil {
		t.Fatal("expected observer error to propagate")
	}
}

func evalWMI(t *testing.T, exp controlval.Expectation, obs Observation, runID string) controlval.Validation {
	t.Helper()
	p := &ControlProvider{Obs: &FakeObserver{Obs: map[string]Observation{runID + "/" + WMIRemoteProcessCreation().ID: obs}}}
	o, err := p.Observe(context.Background(), ckey(runID, "ws02"))
	return controlval.Evaluate(exp, &o, err)
}

func TestEndToEnd_UnprivilegedDeniedIsPass(t *testing.T) {
	v := evalWMI(t, NegativeExpectation(), Observation{Call: CallAccessDenied, Marker: MarkerCheck{Correlated: true, Found: false}}, "r-neg")
	if v.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (unauthorized WMI correctly denied)", v.Verdict)
	}
}

func TestEndToEnd_UnprivilegedExecutedIsGapFail(t *testing.T) {
	v := evalWMI(t, NegativeExpectation(), Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}}, "r-gap")
	if v.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (unauthorized WMI execution succeeded -- control gap)", v.Verdict)
	}
}

func TestEndToEnd_AuthorizedExecutedIsPass(t *testing.T) {
	v := evalWMI(t, PositiveExpectation(), Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}}, "r-pos")
	if v.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (authorized WMI execution succeeded)", v.Verdict)
	}
}

func TestEndToEnd_IndeterminateIsSkipped(t *testing.T) {
	v := evalWMI(t, NegativeExpectation(), Observation{Call: CallErrored, Marker: MarkerCheck{Correlated: true, Found: false}}, "r-amb")
	if v.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (ambiguous evidence, no false claim)", v.Verdict)
	}
}

func passV() controlval.Validation {
	return controlval.Validation{Verdict: controlval.VerdictPass, Reason: "ok"}
}

func TestEndToEnd_GeneralizesToASecondTechnique(t *testing.T) {
	// Proves the Vertical 1b layer is technique-agnostic, not WMI-specific:
	// the same ControlProvider/ClassifyAttempt pipeline, pointed at
	// RemoteServiceCreation's expectations, grades a denied unauthorized
	// attempt correctly.
	tech := RemoteServiceCreation()
	key := controlval.CorrelationKey{RunID: "r-svc", Target: "ws02", Action: tech.ID}
	obs := Observation{Call: CallAccessDenied, Marker: MarkerCheck{Correlated: true, Found: false}}
	p := &ControlProvider{ProviderName: "latmove-remote-service", Obs: &FakeObserver{Obs: map[string]Observation{"r-svc/" + tech.ID: obs}}}
	o, err := p.Observe(context.Background(), key)
	v := controlval.Evaluate(NegativeExpectationFor(tech), &o, err)
	if v.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (unauthorized remote-service-creation correctly denied)", v.Verdict)
	}
	if o.Provider != "latmove-remote-service" {
		t.Fatalf("provider = %q, want latmove-remote-service", o.Provider)
	}
}

func TestPair_NegativePassAcceptedWhenPositivePass(t *testing.T) {
	v, _ := Pair{Positive: passV(), Negative: passV()}.AcceptedNegativeVerdict()
	if v != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS", v)
	}
}

func TestPair_NegativePassNotTrustedWhenPositiveNotPass(t *testing.T) {
	v, reason := Pair{Positive: controlval.Validation{Verdict: controlval.VerdictFail}, Negative: passV()}.AcceptedNegativeVerdict()
	if v != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED (harness not shown capable of authorized success)", v)
	}
	if reason == "" {
		t.Fatal("downgrade must carry a reason")
	}
}

func TestEndToEnd_AuthorizedExecutedAgainstDCIsPass(t *testing.T) {
	// Vertical 1c: the SAME code generalizes to Destination="dc01" with no
	// production change -- AttemptKey.Destination is already a plain string.
	obs := Observation{Call: CallSucceeded, Marker: MarkerCheck{Correlated: true, Found: true}}
	p := &ControlProvider{Obs: &FakeObserver{Obs: map[string]Observation{"r-dc/" + WMIRemoteProcessCreation().ID: obs}}}
	o, err := p.Observe(context.Background(), ckey("r-dc", "dc01"))
	v := controlval.Evaluate(PositiveExpectation(), &o, err)
	if v.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS (client-to-dc target, same vertical)", v.Verdict)
	}
	if v.Key.Target != "dc01" {
		t.Fatalf("target = %q, want dc01", v.Key.Target)
	}
}

func TestPair_DoesNotMutateRawOrUpgrade(t *testing.T) {
	neg := passV()
	p := Pair{Positive: controlval.Validation{Verdict: controlval.VerdictFail}, Negative: neg}
	_, _ = p.AcceptedNegativeVerdict()
	if p.Negative.Verdict != controlval.VerdictPass {
		t.Fatal("raw negative Validation must be untouched")
	}
	v2, _ := Pair{Positive: passV(), Negative: controlval.Validation{Verdict: controlval.VerdictFail}}.AcceptedNegativeVerdict()
	if v2 != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL (never upgraded)", v2)
	}
}
