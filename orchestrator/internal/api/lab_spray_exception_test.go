package api

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestLabExceptionFor(t *testing.T) {
	cases := []struct {
		name     string
		scenario string
		lab      bool
		want     bool
	}{
		{"lab agent, spray scenario", "ad-password-spray-lab", true, true},
		{"lab agent, guessing scenario", "ad-password-guessing-lab", true, true},
		{"ordinary agent, spray scenario", "ad-password-spray-lab", false, false},
		{"ordinary agent, guessing scenario", "ad-password-guessing-lab", false, false},
		{"lab agent, unrelated scenario", "ad-ntds-access-attempt", true, false},
		{"ordinary agent, unrelated scenario", "ad-ntds-access-attempt", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := labExceptionFor(c.scenario, c.lab); got != c.want {
				t.Fatalf("labExceptionFor(%q, %v) = %v, want %v", c.scenario, c.lab, got, c.want)
			}
		})
	}
}

// A scenario's own LabException value must never reach the agent: the wire value
// always equals the server's decision.
func TestLabExemptPolicy_WireValueFollowsDecision(t *testing.T) {
	carried := &scenario.LivePolicy{LabException: true, MaxSprayAttempts: 3}
	if p := labExemptPolicy(carried, false); p == nil || p.LabException {
		t.Fatalf("scenario-carried exemption leaked through a non-exempt dispatch: %+v", p)
	}
	if p := labExemptPolicy(carried, true); p == nil || !p.LabException || p.MaxSprayAttempts != 3 {
		t.Fatalf("exempt dispatch lost the exemption or the other policy fields: %+v", p)
	}
	if p := labExemptPolicy(nil, false); p != nil {
		t.Fatalf("nil policy, not exempt: want nil, got %+v", p)
	}
	if p := labExemptPolicy(nil, true); p == nil || !p.LabException {
		t.Fatalf("nil policy, exempt: want an exempt policy, got %+v", p)
	}
	// The base must not be mutated: callers keep sc.LivePolicy unchanged.
	if carried.LabException != true {
		t.Fatal("labExemptPolicy mutated its input")
	}
}
