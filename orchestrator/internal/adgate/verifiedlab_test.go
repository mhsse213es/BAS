package adgate

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestDecide_VerifiedLabAuthorizedAllows(t *testing.T) {
	d := Decide(Request{
		Class: scenario.ClassPotentiallyDestructive,
		Env:   VerifiedControlledLabProvenance("run-1", "target-1"),
		Auth:  Authorization{Authorized: true},
	})
	if !d.Allowed || d.Reason != ReasonAllowedControlledLabAuthorized {
		t.Fatalf("verified-lab + authorized must allow with lab reason, got %+v", d)
	}
}

func TestDecide_VerifiedLabRequiresAuthorization(t *testing.T) {
	d := Decide(Request{
		Class: scenario.ClassPotentiallyDestructive,
		Env:   VerifiedControlledLabProvenance("run-1", "target-1"),
		Auth:  Authorization{Authorized: false},
	})
	if d.Allowed || d.Reason != ReasonDeniedMissingAuth {
		t.Fatalf("verified isolation alone must NOT allow; needs auth, got %+v", d)
	}
}

func TestDecide_LiveAndUnknownStillDeny(t *testing.T) {
	for _, env := range []Provenance{LiveADProvenance(), {}} {
		d := Decide(Request{Class: scenario.ClassPotentiallyDestructive, Env: env, Auth: Authorization{Authorized: true}})
		if d.Allowed || d.Reason != ReasonDeniedNotSynthetic {
			t.Fatalf("live/unknown env must still deny not-synthetic, got %+v", d)
		}
	}
}

func TestDecide_VerifiedLabDestructiveNeedsApproval(t *testing.T) {
	base := Request{Class: scenario.ClassDestructive, Env: VerifiedControlledLabProvenance("r", "t"), Auth: Authorization{Authorized: true}}
	if d := Decide(base); d.Allowed || d.Reason != ReasonDeniedDestructiveNotApproved {
		t.Fatalf("destructive verified-lab without approval must deny, got %+v", d)
	}
	base.Auth.DestructiveApproved = true
	if d := Decide(base); !d.Allowed {
		t.Fatalf("destructive verified-lab WITH approval must allow, got %+v", d)
	}
}

func TestVerifiedLabProvenance_BoundToRunAndTarget(t *testing.T) {
	p := VerifiedControlledLabProvenance("run-A", "target-A")
	if !p.BoundTo("run-A", "target-A") {
		t.Fatal("provenance must report bound to its own run+target")
	}
	if p.BoundTo("run-B", "target-B") || p.BoundTo("run-A", "target-B") || p.BoundTo("run-B", "target-A") {
		t.Fatal("provenance must NOT report bound to a different run/target")
	}
	if SyntheticProvenance().BoundTo("run-A", "target-A") {
		t.Fatal("non-lab provenance must never report bound")
	}
}
