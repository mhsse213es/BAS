package sched

import (
	"context"
	"testing"
	"time"
)

func TestRiskGate_DefaultPolicyAdmitsEverything(t *testing.T) {
	g := NewRiskGate()
	if !g.Allow(context.Background(), "anything") {
		t.Error("a freshly-constructed RiskGate must admit any risk string by default")
	}
	if !g.Allow(context.Background(), RiskUnknown) {
		t.Error("default policy must also admit RiskUnknown")
	}
}

// TestRiskGate_BlocksThenUnblocksOnSetPolicy proves Allow genuinely blocks
// (not merely "runs later") while the policy rejects the risk, and unblocks
// the instant SetPolicy changes to one that admits it -- same shape as
// ConcurrencyLimiter's TestConcurrencyLimiter_BlocksBeyondLimitUntilRelease.
func TestRiskGate_BlocksThenUnblocksOnSetPolicy(t *testing.T) {
	g := NewRiskGate()
	g.SetPolicy(func(risk string) bool { return false }) // reject everything

	admitted := make(chan bool, 1)
	go func() {
		admitted <- g.Allow(context.Background(), RiskModification)
	}()

	select {
	case <-admitted:
		t.Fatal("Allow returned before SetPolicy admitted the risk -- policy was not enforced")
	case <-time.After(30 * time.Millisecond):
		// expected: still blocked
	}

	g.SetPolicy(func(risk string) bool { return true }) // now admit everything

	select {
	case ok := <-admitted:
		if !ok {
			t.Error("Allow returned false after SetPolicy admitted the risk")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Allow did not unblock after SetPolicy admitted the risk")
	}
}

// TestRiskGate_ContextCancelReturnsFalsePromptly proves a blocked Allow gives
// up promptly when its context is cancelled, rather than waiting for a
// SetPolicy that may never come.
func TestRiskGate_ContextCancelReturnsFalsePromptly(t *testing.T) {
	g := NewRiskGate()
	g.SetPolicy(func(risk string) bool { return false })

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() { result <- g.Allow(ctx, RiskPersistence) }()

	time.Sleep(20 * time.Millisecond) // let it actually block
	cancel()

	select {
	case ok := <-result:
		if ok {
			t.Error("Allow returned true after its context was cancelled")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Allow did not return after context cancellation")
	}
}

// TestRiskGate_SetPolicyNilResetsToAdmitEverything documents the fallback
// behavior explicitly rather than leaving nil-policy undefined.
func TestRiskGate_SetPolicyNilResetsToAdmitEverything(t *testing.T) {
	g := NewRiskGate()
	g.SetPolicy(func(risk string) bool { return false })
	g.SetPolicy(nil)
	if !g.Allow(context.Background(), RiskModification) {
		t.Error("SetPolicy(nil) must reset to admit-everything, not stay rejecting or panic")
	}
}

func TestEffectiveRisk(t *testing.T) {
	cases := []struct {
		name string
		p    *ResourceProfile
		want string
	}{
		{"nil profile", nil, RiskUnknown},
		{"empty Risk field", &ResourceProfile{Domains: []ResourceLock{{Domain: "registry"}}}, RiskUnknown},
		{"observation", &ResourceProfile{Risk: RiskObservation}, RiskObservation},
		{"modification", &ResourceProfile{Risk: RiskModification}, RiskModification},
		{"persistence", &ResourceProfile{Risk: RiskPersistence}, RiskPersistence},
	}
	for _, c := range cases {
		if got := EffectiveRisk(c.p); got != c.want {
			t.Errorf("%s: EffectiveRisk() = %q, want %q", c.name, got, c.want)
		}
	}
}
