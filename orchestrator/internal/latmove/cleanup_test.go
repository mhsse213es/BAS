package latmove

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestRequiresCleanupVerification_PersistentArtifactTechniques(t *testing.T) {
	for _, tech := range []Technique{RemoteServiceCreation(), ScheduledTaskRemote()} {
		if !RequiresCleanupVerification(tech) {
			t.Fatalf("%s creates a persistent artifact and must require cleanup verification", tech.ID)
		}
		if tech.RiskClass != adprimitive.RiskPotentiallyDestructive {
			t.Fatalf("%s should be potentially_destructive", tech.ID)
		}
	}
}

func TestRequiresCleanupVerification_OneShotTechniquesDoNot(t *testing.T) {
	for _, tech := range []Technique{WMIRemoteProcessCreation(), WinRMRemoteExecution(), RDPInteractiveLogon()} {
		if RequiresCleanupVerification(tech) {
			t.Fatalf("%s is one-shot (no persistent artifact) and must not require cleanup verification", tech.ID)
		}
	}
}

func TestFakeCleanupVerifier_ReturnsCannedResult(t *testing.T) {
	tech := RemoteServiceCreation()
	k := AttemptKey{RunID: "r1", Technique: tech.ID}
	f := &FakeCleanupVerifier{Results: map[string]CleanupResult{"r1/" + tech.ID: CleanupConfirmed}}
	got, err := f.VerifyCleanup(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if got != CleanupConfirmed {
		t.Fatalf("result = %q, want confirmed", got)
	}
}

func TestFakeCleanupVerifier_UncapturedKeyIsIndeterminate(t *testing.T) {
	f := &FakeCleanupVerifier{Results: map[string]CleanupResult{"other/x": CleanupConfirmed}}
	got, err := f.VerifyCleanup(context.Background(), AttemptKey{RunID: "r2", Technique: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got != CleanupIndeterminate {
		t.Fatalf("result = %q, want indeterminate (never guessed Confirmed or Failed)", got)
	}
}

func TestFakeCleanupVerifier_ConfiguredErrorPropagates(t *testing.T) {
	f := &FakeCleanupVerifier{Err: map[string]error{"boom/x": errors.New("rpc down")}}
	if _, err := f.VerifyCleanup(context.Background(), AttemptKey{RunID: "boom", Technique: "x"}); err == nil {
		t.Fatal("expected the configured error to propagate")
	}
}
