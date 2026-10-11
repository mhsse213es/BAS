package rwevidence

import (
	"context"
	"testing"
)

func TestFakeRecoveryObserver_DifferentActionsSameTechniqueStayIndependent(t *testing.T) {
	f := &FakeRecoveryObserver{Results: map[string]SurvivalResult{
		recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "aaa11111"}): SurvivalConfirmed,
		recoveryKey(AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "bbb22222"}): SurvivalLost,
	}}
	got1, err1 := f.ObserveSurvival(context.Background(), AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "aaa11111"})
	if err1 != nil || got1 != SurvivalConfirmed {
		t.Fatalf("action aaa11111: got %q, err %v, want confirmed", got1, err1)
	}
	got2, err2 := f.ObserveSurvival(context.Background(), AttemptKey{RunID: "r1", TechniqueID: "T1490", Action: "bbb22222"})
	if err2 != nil || got2 != SurvivalLost {
		t.Fatalf("action bbb22222: got %q, err %v, want lost -- two actions sharing a technique must never collapse into one result", got2, err2)
	}
}
