package adrehearse

import (
	"testing"

	"github.com/audspect/bas/internal/adcompose"
	"github.com/audspect/bas/internal/adcoverage"
	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adlab"
	"github.com/audspect/bas/internal/adprimitive"
)

func step(id string, rc adprimitive.RiskClass) adcompose.ComposedStep {
	return adcompose.ComposedStep{
		Primitive:  adprimitive.Primitive{ID: id, RiskClass: rc},
		Capability: adcoverage.StepRef{Scenario: id + ".yaml", StepName: "step-" + id},
		RiskClass:  rc,
	}
}

func chain(prov adgate.Provenance, composable bool, steps ...adcompose.ComposedStep) adcompose.ComposedChain {
	return adcompose.ComposedChain{
		Lab:        adlab.Lab{Attestation: prov},
		Steps:      steps,
		Composable: composable,
	}
}

func authed() adgate.Authorization { return adgate.Authorization{Authorized: true} }

func TestRehearse_AuthorizedSyntheticAllowsAndPlans(t *testing.T) {
	c := chain(adgate.SyntheticProvenance(), true, step("p1", adprimitive.RiskNonDestructive), step("p2", adprimitive.RiskPotentiallyDestructive))
	r := Rehearse(c, authed())
	if !r.Allowed || !r.Decision.Allowed {
		t.Fatalf("expected allow, got %+v", r)
	}
	if len(r.Plan) != 2 || r.Plan[0].Primitive.ID != "p1" || r.Plan[1].Primitive.ID != "p2" {
		t.Fatalf("plan must preserve order + provenance, got %+v", r.Plan)
	}
	if r.Plan[0].Capability.Scenario != "p1.yaml" {
		t.Fatalf("plan must carry capability provenance, got %+v", r.Plan[0])
	}
}

func TestRehearse_UnverifiedEnvironmentDeniedNoPlan(t *testing.T) {
	r := Rehearse(chain(adgate.Provenance{}, true, step("p1", adprimitive.RiskNonDestructive)), authed())
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedNotSynthetic {
		t.Fatalf("zero-value provenance must deny not_synthetic with no plan, got %+v", r)
	}
}

func TestRehearse_LiveEnvironmentDeniedNoPlan(t *testing.T) {
	r := Rehearse(chain(adgate.LiveADProvenance(), true, step("p1", adprimitive.RiskNonDestructive)), authed())
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedNotSynthetic {
		t.Fatalf("live env must deny not_synthetic with no plan, got %+v", r)
	}
}

func TestRehearse_UnauthorizedDeniedNoPlan(t *testing.T) {
	r := Rehearse(chain(adgate.SyntheticProvenance(), true, step("p1", adprimitive.RiskNonDestructive)), adgate.Authorization{Authorized: false})
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedMissingAuth {
		t.Fatalf("unauthorized must deny missing_authorization with no plan, got %+v", r)
	}
}

func TestRehearse_DestructiveNeedsApproval(t *testing.T) {
	c := chain(adgate.SyntheticProvenance(), true, step("p1", adprimitive.RiskNonDestructive), step("p2", adprimitive.RiskDestructive))
	if r := Rehearse(c, authed()); r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedDestructiveNotApproved {
		t.Fatalf("destructive step without approval must deny with no plan, got %+v", r)
	}
	if r := Rehearse(c, adgate.Authorization{Authorized: true, DestructiveApproved: true}); !r.Allowed || len(r.Plan) != 2 {
		t.Fatalf("destructive with approval must allow + plan, got %+v", r)
	}
}

func TestRehearse_UnknownClassFailsClosed(t *testing.T) {
	r := Rehearse(chain(adgate.SyntheticProvenance(), true, step("p1", adprimitive.RiskClass("bogus"))), authed())
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedUnknownClass {
		t.Fatalf("bogus step class must deny unknown_classification, got %+v", r)
	}
}

func TestRehearse_NonComposableFailsClosedBeforeGate(t *testing.T) {
	r := Rehearse(chain(adgate.SyntheticProvenance(), false, step("p1", adprimitive.RiskNonDestructive)), authed())
	if r.Allowed || r.Plan != nil || r.Note == "" {
		t.Fatalf("non-composable chain must fail closed with a note and no plan, got %+v", r)
	}
}

func TestRehearse_EmptyChainIsUnknownClassDeny(t *testing.T) {
	r := Rehearse(chain(adgate.SyntheticProvenance(), true), authed())
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedUnknownClass {
		t.Fatalf("empty composable chain must deny unknown_classification, got %+v", r)
	}
}
