package adgate

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestProvenanceZeroValueIsNotSynthetic(t *testing.T) {
	// What a caller gets without the constructor must fail closed.
	d := Decide(Request{Class: scenario.ClassNonDestructive, Env: Provenance{}, Auth: Authorization{Authorized: true}})
	if d.Allowed || d.Reason != ReasonDeniedNotSynthetic {
		t.Fatalf("zero-value provenance must deny not_synthetic, got %+v", d)
	}
}

func TestDecide_AllowsSyntheticAuthorizedKnownClass(t *testing.T) {
	d := Decide(Request{Class: scenario.ClassNonDestructive, Env: SyntheticProvenance(), Auth: Authorization{Authorized: true}})
	if !d.Allowed || d.Reason != ReasonAllowedSyntheticAuthorized {
		t.Fatalf("expected allow, got %+v", d)
	}
}

func TestDecide_DeniesLiveEnvironment(t *testing.T) {
	d := Decide(Request{Class: scenario.ClassNonDestructive, Env: LiveADProvenance(), Auth: Authorization{Authorized: true}})
	if d.Allowed || d.Reason != ReasonDeniedNotSynthetic {
		t.Fatalf("expected deny not_synthetic for live env, got %+v", d)
	}
}

func TestDecide_DeniesUnknownClass(t *testing.T) {
	for _, c := range []scenario.ExecutionClass{"", scenario.ExecutionClass("bogus")} {
		d := Decide(Request{Class: c, Env: SyntheticProvenance(), Auth: Authorization{Authorized: true}})
		if d.Allowed || d.Reason != ReasonDeniedUnknownClass {
			t.Fatalf("class %q must deny unknown_classification, got %+v", c, d)
		}
	}
}

func TestDecide_DeniesMissingAuthorization(t *testing.T) {
	d := Decide(Request{Class: scenario.ClassNonDestructive, Env: SyntheticProvenance(), Auth: Authorization{Authorized: false}})
	if d.Allowed || d.Reason != ReasonDeniedMissingAuth {
		t.Fatalf("expected deny missing_authorization, got %+v", d)
	}
}

func TestDecide_DestructiveNeedsExplicitApproval(t *testing.T) {
	base := Request{Class: scenario.ClassDestructive, Env: SyntheticProvenance(), Auth: Authorization{Authorized: true}}
	if d := Decide(base); d.Allowed || d.Reason != ReasonDeniedDestructiveNotApproved {
		t.Fatalf("destructive without approval must deny, got %+v", d)
	}
	base.Auth.DestructiveApproved = true
	if d := Decide(base); !d.Allowed || d.Reason != ReasonAllowedSyntheticAuthorized {
		t.Fatalf("destructive with approval (synthetic+authorized) must allow, got %+v", d)
	}
}

func TestDecide_RuleOrderFirstFailingWins(t *testing.T) {
	// Live env AND unknown class: environment rule is first, so not_synthetic.
	d := Decide(Request{Class: "", Env: LiveADProvenance(), Auth: Authorization{}})
	if d.Reason != ReasonDeniedNotSynthetic {
		t.Fatalf("expected first-failing rule (not_synthetic), got %+v", d)
	}
}
