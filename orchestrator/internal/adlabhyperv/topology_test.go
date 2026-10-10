package adlabhyperv

import "testing"

func TestLookupTopology_DCOnlyIsASingleIsolatedDC(t *testing.T) {
	topo, ok := LookupTopology("dc-only")
	if !ok {
		t.Fatal("dc-only topology must exist")
	}
	if topo.Switch == "" {
		t.Error("topology must name a dedicated private virtual switch")
	}
	if len(topo.VMs) != 1 || topo.VMs[0].Role != RoleDC {
		t.Fatalf("dc-only must be exactly one DC VM, got %+v", topo.VMs)
	}
	if topo.VMs[0].BaseCheckpoint == "" || topo.VMs[0].MemoryMB <= 0 || topo.VMs[0].VCPU <= 0 {
		t.Errorf("DC VM must carry a base checkpoint and positive resource profile: %+v", topo.VMs[0])
	}
	if topo.Attacker.Principal == "" || topo.Attacker.Rights == "" {
		t.Error("topology must name the controlled attacker identity and its granted right")
	}
}

func TestLookupTopology_UnknownNameIsNotFound(t *testing.T) {
	if _, ok := LookupTopology("does-not-exist"); ok {
		t.Fatal("unknown topology name must return ok=false, not a zero-value topology")
	}
}
