package adlabhyperv

import "testing"

func TestLookupTopology_ClientPairHasTwoClientVMs(t *testing.T) {
	topo, ok := LookupTopology("client-pair")
	if !ok {
		t.Fatal("client-pair topology not found")
	}
	if topo.Switch != "audspect-lab-private" {
		t.Fatalf("switch = %q, want audspect-lab-private (same isolated switch, no new switch)", topo.Switch)
	}
	if len(topo.VMs) != 2 {
		t.Fatalf("len(VMs) = %d, want 2", len(topo.VMs))
	}
	for _, vm := range topo.VMs {
		if vm.Role != RoleClient {
			t.Fatalf("VM %s role = %q, want client", vm.Name, vm.Role)
		}
		if vm.BaseCheckpoint == "" {
			t.Fatalf("VM %s has no BaseCheckpoint", vm.Name)
		}
	}
	if topo.VMs[0].Name == topo.VMs[1].Name {
		t.Fatal("the two client VMs must have distinct names")
	}
}

func TestLookupTopology_DCOnlyUnchanged(t *testing.T) {
	// Regression lock: adding client-pair must not perturb dc-only.
	topo, ok := LookupTopology("dc-only")
	if !ok {
		t.Fatal("dc-only topology missing")
	}
	if len(topo.VMs) != 1 || topo.VMs[0].Name != "dc01" || topo.VMs[0].Role != RoleDC {
		t.Fatalf("dc-only topology changed: %+v", topo)
	}
	if topo.Attacker.Principal != `LAB\attacker` || topo.Attacker.Rights != "AllExtendedRights@domain-root" {
		t.Fatalf("dc-only Attacker changed: %+v", topo.Attacker)
	}
}
