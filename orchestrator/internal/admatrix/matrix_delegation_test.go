package admatrix

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adprimitive"
)

var controlledAccount = []adprimitive.Capability{{Kind: adprimitive.CapControlledAccount}}
var ticket = adprimitive.Capability{Kind: adprimitive.CapTicket}

func TestSimulate_UnconstrainedDelegationReachableWhenPrincipalControlled(t *testing.T) {
	env := adenv.Environment{Delegation: adenv.Delegation{Unconstrained: []string{"WEB01$"}}}
	if res := Simulate(adprimitive.DelegationCatalog, env, "WEB01$", controlledAccount, ticket); !res.Reachable {
		t.Fatalf("unconstrained delegation must be reachable when the attacker controls the principal: %+v", res)
	}
	if res := Simulate(adprimitive.DelegationCatalog, env, "nobody", controlledAccount, ticket); res.Reachable {
		t.Fatalf("unconstrained delegation must NOT be reachable without controlling a delegation principal: %+v", res)
	}
}

func TestSimulate_ConstrainedDelegationReachableWhenPrincipalControlled(t *testing.T) {
	env := adenv.Environment{Delegation: adenv.Delegation{
		Constrained: []adenv.ConstrainedDelegation{{Principal: "svc-web", Targets: []string{"cifs/dc01"}, ProtocolTransition: true}},
	}}
	if res := Simulate(adprimitive.DelegationCatalog, env, "svc-web", controlledAccount, ticket); !res.Reachable {
		t.Fatalf("constrained delegation must be reachable when the attacker controls the principal: %+v", res)
	}
	if res := Simulate(adprimitive.DelegationCatalog, env, "nobody", controlledAccount, ticket); res.Reachable {
		t.Fatalf("constrained delegation must NOT be reachable without controlling a delegation principal: %+v", res)
	}
}

func TestDelegationEntries_GroundedAndHonest(t *testing.T) {
	if len(DelegationEntries()) != len(adprimitive.DelegationCatalog) {
		t.Fatalf("DelegationEntries must cover every delegation catalog primitive")
	}
	for _, e := range DelegationEntries() {
		if e.CurrentValidation != LevelModelSimulated {
			t.Fatalf("entry %q must stay model-simulated (no execution/telemetry evidence exists)", e.PrimitiveID)
		}
		if e.RequiredEnvToExecute == EnvSyntheticModel {
			t.Fatalf("entry %q cannot truly execute in a synthetic model; it needs a real DC", e.PrimitiveID)
		}
		if len(e.EvidenceRequirements) == 0 || len(e.Cleanup) == 0 || len(e.TelemetrySources) == 0 {
			t.Fatalf("entry %q must state evidence, cleanup, and telemetry", e.PrimitiveID)
		}
	}
}
