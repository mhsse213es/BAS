package adlabhyperv

import "testing"

func TestLookupTopology_ClientToDCHasClientAndDC(t *testing.T) {
	topo, ok := LookupTopology("client-to-dc")
	if !ok {
		t.Fatal("client-to-dc topology not found")
	}
	if topo.Switch != "audspect-lab-private" {
		t.Fatalf("switch = %q, want audspect-lab-private", topo.Switch)
	}
	if len(topo.VMs) != 2 {
		t.Fatalf("len(VMs) = %d, want 2 (one client, one DC)", len(topo.VMs))
	}
	var hasClient, hasDC bool
	for _, vm := range topo.VMs {
		switch vm.Role {
		case RoleClient:
			hasClient = true
		case RoleDC:
			hasDC = true
		}
		if vm.BaseCheckpoint == "" {
			t.Fatalf("VM %s has no BaseCheckpoint", vm.Name)
		}
	}
	if !hasClient || !hasDC {
		t.Fatalf("client-to-dc must have one client VM and one DC VM, got %+v", topo.VMs)
	}
}

func TestLookupTopology_ClientPairAndDCOnlyStillUnchanged(t *testing.T) {
	// Regression lock: adding client-to-dc must not perturb the other two topologies.
	cp, ok := LookupTopology("client-pair")
	if !ok || len(cp.VMs) != 2 {
		t.Fatalf("client-pair changed: ok=%v %+v", ok, cp)
	}
	dc, ok := LookupTopology("dc-only")
	if !ok || len(dc.VMs) != 1 || dc.VMs[0].Name != "dc01" {
		t.Fatalf("dc-only changed: ok=%v %+v", ok, dc)
	}
}
