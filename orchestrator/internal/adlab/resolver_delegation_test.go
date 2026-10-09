package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
)

func TestResolve_UnconstrainedDelegationRequiresControlOfThePrincipal(t *testing.T) {
	env := adenv.Environment{Delegation: adenv.Delegation{Unconstrained: []string{"WEB01$"}}}
	// attacker controls WEB01$ -> reachable
	if !NewEnvResolver(env, "WEB01$").Resolve("controls_unconstrained_delegation_principal") {
		t.Fatal("must resolve when the attacker controls the unconstrained-delegation principal")
	}
	// attacker controls something else -> not reachable
	if NewEnvResolver(env, "someone-else").Resolve("controls_unconstrained_delegation_principal") {
		t.Fatal("must NOT resolve when the attacker does not control any unconstrained-delegation principal")
	}
	// nothing configured -> not reachable
	if NewEnvResolver(adenv.Environment{}, "WEB01$").Resolve("controls_unconstrained_delegation_principal") {
		t.Fatal("must NOT resolve with no unconstrained delegation configured")
	}
}

func TestResolve_ConstrainedDelegationRequiresControlOfThePrincipal(t *testing.T) {
	env := adenv.Environment{Delegation: adenv.Delegation{
		Constrained: []adenv.ConstrainedDelegation{{Principal: "svc-web", Targets: []string{"cifs/dc01"}, ProtocolTransition: true}},
	}}
	if !NewEnvResolver(env, "svc-web").Resolve("controls_constrained_delegation_principal") {
		t.Fatal("must resolve when the attacker controls the constrained-delegation principal")
	}
	if NewEnvResolver(env, "someone-else").Resolve("controls_constrained_delegation_principal") {
		t.Fatal("must NOT resolve when the attacker controls no constrained-delegation principal")
	}
}
