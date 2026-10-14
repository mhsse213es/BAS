package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
)

func TestResolve_WritableLinkedGPO(t *testing.T) {
	// attacker can edit a GPO that is linked to an OU -> reachable
	env := adenv.Environment{Policy: adenv.Policy{GPOs: []adenv.GPO{
		{Name: "WS Policy", WritePrincipals: []string{"helpdesk"}, LinkedOUs: []string{"OU=Workstations"}},
	}}}
	if !NewEnvResolver(env, "helpdesk").Resolve("controls_writable_linked_gpo") {
		t.Fatal("must resolve when the attacker can edit a linked GPO")
	}
	// writable but unlinked -> no scope -> not reachable
	unlinked := adenv.Environment{Policy: adenv.Policy{GPOs: []adenv.GPO{
		{Name: "Orphan", WritePrincipals: []string{"helpdesk"}},
	}}}
	if NewEnvResolver(unlinked, "helpdesk").Resolve("controls_writable_linked_gpo") {
		t.Fatal("must NOT resolve for a writable but unlinked GPO (no affected scope)")
	}
	// linked but attacker cannot edit -> not reachable
	noWrite := adenv.Environment{Policy: adenv.Policy{GPOs: []adenv.GPO{
		{Name: "WS Policy", WritePrincipals: []string{"admins"}, LinkedOUs: []string{"OU=Workstations"}},
	}}}
	if NewEnvResolver(noWrite, "helpdesk").Resolve("controls_writable_linked_gpo") {
		t.Fatal("must NOT resolve when the attacker cannot edit the GPO")
	}
}
