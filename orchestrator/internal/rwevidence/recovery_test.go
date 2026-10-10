package rwevidence

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestFakeRecoveryObserver_ReturnsCannedResult(t *testing.T) {
	key := AttemptKey{RunID: "r1", TechniqueID: "T1490"}
	f := &FakeRecoveryObserver{Results: map[string]SurvivalResult{"r1/T1490": SurvivalConfirmed}}
	got, err := f.ObserveSurvival(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if got != SurvivalConfirmed {
		t.Fatalf("result = %q, want confirmed", got)
	}
}

func TestFakeRecoveryObserver_UncapturedKeyIsIndeterminate(t *testing.T) {
	f := &FakeRecoveryObserver{Results: map[string]SurvivalResult{"other/x": SurvivalConfirmed}}
	got, err := f.ObserveSurvival(context.Background(), AttemptKey{RunID: "r2", TechniqueID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got != SurvivalIndeterminate {
		t.Fatalf("result = %q, want indeterminate (never guessed from another key's data)", got)
	}
}

func TestFakeRecoveryObserver_ConfiguredErrorPropagates(t *testing.T) {
	f := &FakeRecoveryObserver{Err: map[string]error{"boom/x": errors.New("wmi unreachable")}}
	if _, err := f.ObserveSurvival(context.Background(), AttemptKey{RunID: "boom", TechniqueID: "x"}); err == nil {
		t.Fatal("expected the configured error to propagate")
	}
}

func TestRecoveryFromSurvival_ConfirmedIsPass(t *testing.T) {
	cr := RecoveryFromSurvival(VSSInhibition(), SurvivalConfirmed, "")
	if cr.Capability != CapabilityRecovery {
		t.Fatalf("capability = %q, want recovery", cr.Capability)
	}
	if cr.Verdict != controlval.VerdictPass {
		t.Fatalf("verdict = %q, want PASS", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for PASS", cr.SkipReason)
	}
}

func TestRecoveryFromSurvival_LostIsFail(t *testing.T) {
	cr := RecoveryFromSurvival(VSSInhibition(), SurvivalLost, "")
	if cr.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", cr.Verdict)
	}
	if cr.SkipReason != "" {
		t.Fatalf("skipReason = %q, want empty for FAIL", cr.SkipReason)
	}
}

func TestRecoveryFromSurvival_IndeterminateIsSkippedInsufficientEvidence(t *testing.T) {
	cr := RecoveryFromSurvival(VSSInhibition(), SurvivalIndeterminate, "")
	if cr.Verdict != controlval.VerdictSkipped {
		t.Fatalf("verdict = %q, want SKIPPED", cr.Verdict)
	}
	if cr.SkipReason != controlval.SkipInsufficientEvidence {
		t.Fatalf("skipReason = %q, want insufficient_evidence", cr.SkipReason)
	}
}

func TestRecoveryFromSurvival_CorroborationNeverChangesVerdict(t *testing.T) {
	withCorrob := RecoveryFromSurvival(VSSInhibition(), SurvivalConfirmed, "vss-delete-edr fired")
	withoutCorrob := RecoveryFromSurvival(VSSInhibition(), SurvivalConfirmed, "")
	if withCorrob.Verdict != withoutCorrob.Verdict {
		t.Fatalf("corroboration changed the verdict: %q vs %q", withCorrob.Verdict, withoutCorrob.Verdict)
	}
}

func TestRecoveryFromSurvival_ReasonNeverGeneralizesBeyondTargetedData(t *testing.T) {
	cr := RecoveryFromSurvival(VSSInhibition(), SurvivalConfirmed, "")
	if !strings.Contains(cr.Reason, "not a claim about overall backup recoverability") {
		t.Fatalf("reason = %q, must explicitly scope the claim", cr.Reason)
	}
}

func TestRecoveryResultFor_ObserverErrorTakesPrecedence(t *testing.T) {
	cr := RecoveryResultFor(VSSInhibition(), SurvivalConfirmed, errors.New("wmi unreachable"), "")
	if cr.Verdict != controlval.VerdictError {
		t.Fatalf("verdict = %q, want ERROR (operational failure takes precedence over any SurvivalResult)", cr.Verdict)
	}
}

func TestRecoveryResultFor_NoErrorDelegatesToSurvivalResult(t *testing.T) {
	cr := RecoveryResultFor(VSSInhibition(), SurvivalLost, nil, "")
	if cr.Verdict != controlval.VerdictFail {
		t.Fatalf("verdict = %q, want FAIL", cr.Verdict)
	}
}
