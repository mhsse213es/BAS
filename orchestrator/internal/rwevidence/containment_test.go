package rwevidence

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestFakeContainmentObserver_ReturnsCannedResult(t *testing.T) {
	key := AttemptKey{RunID: "r1", TechniqueID: "T1486"}
	f := &FakeContainmentObserver{Results: map[string]ContainmentResult{"r1/T1486": ContainmentConfirmed}}
	got, err := f.ObserveContainment(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if got != ContainmentConfirmed {
		t.Fatalf("result = %q, want confirmed", got)
	}
}

func TestFakeContainmentObserver_UncapturedKeyIsIndeterminate(t *testing.T) {
	f := &FakeContainmentObserver{Results: map[string]ContainmentResult{"other/x": ContainmentConfirmed}}
	got, err := f.ObserveContainment(context.Background(), AttemptKey{RunID: "r2", TechniqueID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got != ContainmentIndeterminate {
		t.Fatalf("result = %q, want indeterminate (never guessed from another key's data)", got)
	}
}

func TestFakeContainmentObserver_ConfiguredErrorPropagates(t *testing.T) {
	f := &FakeContainmentObserver{Err: map[string]error{"boom/x": errors.New("edr api unreachable")}}
	if _, err := f.ObserveContainment(context.Background(), AttemptKey{RunID: "boom", TechniqueID: "x"}); err == nil {
		t.Fatal("expected the configured error to propagate")
	}
}

func TestContainmentFromObservation_ConfirmedIsPass(t *testing.T) {
	cr := ContainmentFromObservation(DataEncryptedForImpact(), ContainmentConfirmed, "")
	if cr.Capability != CapabilityContainment {
		t.Fatalf("capability = %q, want containment", cr.Capability)
	}
	if cr.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for PASS", cr.SkipReason)
	}
}

func TestContainmentFromObservation_FailedIsFail(t *testing.T) {
	cr := ContainmentFromObservation(DataEncryptedForImpact(), ContainmentFailed, "")
	if cr.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for FAIL", cr.SkipReason)
	}
}

func TestContainmentFromObservation_IndeterminateIsSkippedInsufficientEvidence(t *testing.T) {
	cr := ContainmentFromObservation(DataEncryptedForImpact(), ContainmentIndeterminate, "")
	if cr.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", cr.Verdict)
	}
	if cr.SkipReason != controlval.SkipInsufficientEvidence {
		t.Fatalf("skipReason = %q, want insufficient_evidence", cr.SkipReason)
	}
}

func TestContainmentFromObservation_CorroborationNeverChangesVerdict(t *testing.T) {
	withCorrob := ContainmentFromObservation(DataEncryptedForImpact(), ContainmentConfirmed, "edr-isolate-success fired")
	withoutCorrob := ContainmentFromObservation(DataEncryptedForImpact(), ContainmentConfirmed, "")
	if withCorrob.Verdict != withoutCorrob.Verdict {
		t.Fatalf("corroboration changed the verdict: %q vs %q", withCorrob.Verdict, withoutCorrob.Verdict)
	}
}

func TestContainmentFromObservation_ReasonNeverGeneralizesBeyondTargetedHost(t *testing.T) {
	cr := ContainmentFromObservation(DataEncryptedForImpact(), ContainmentConfirmed, "")
	if !strings.Contains(cr.Reason, "not a claim about overall containment posture") {
		t.Fatalf("reason = %q, must explicitly scope the claim", cr.Reason)
	}
}

func TestContainmentResultFor_ObserverErrorTakesPrecedence(t *testing.T) {
	cr := ContainmentResultFor(DataEncryptedForImpact(), ContainmentConfirmed, errors.New("edr api unreachable"), "")
	if cr.Verdict != controlval.VerdictError {
		t.Fatalf("verdict = %q, want ERROR (operational failure takes precedence over any ContainmentResult)", cr.Verdict)
	}
}

func TestContainmentResultFor_NoErrorDelegatesToContainmentResult(t *testing.T) {
	cr := ContainmentResultFor(DataEncryptedForImpact(), ContainmentFailed, nil, "")
	if cr.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", cr.Verdict)
	}
}

// T1567.002's blast radius is already DataProtection's job (did the exfil
// data leave) -- Containment doesn't apply to it, same NotApplicable pattern
// used for e.g. T1486's Recovery.
func TestContainment_DoesNotApplyToDataExfiltration(t *testing.T) {
	cr := NotApplicable(CapabilityContainment, DataExfiltrationToCloud(), "containment of an exfil channel is covered by the DataProtection capability, not a separate Containment check")
	if err := cr.Valid(); err != nil {
		t.Fatalf("expected valid NotApplicable result: %v", err)
	}
	if cr.SkipReason != controlval.SkipNotApplicable {
		t.Fatalf("skipReason = %q, want not_applicable", cr.SkipReason)
	}
}
