package adchain

import (
	"reflect"
	"testing"
	"time"

	"github.com/audspect/bas/internal/adprimitive"
)

func chainCatalog() []adprimitive.Primitive {
	return []adprimitive.Primitive{
		{
			ID:             "step-a",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapKerberoastableTargetKnown}},
		},
		{
			ID:             "step-b",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapKerberoastableTargetKnown}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapServiceAccountCredential}},
		},
		{
			// Unreachable from CapDomainUser alone -- requires a capability
			// nothing in this catalog ever produces.
			ID:             "step-unreachable",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapDomainCredentialMaterial}},
		},
	}
}

func TestReachable_FollowsMultiStepChain(t *testing.T) {
	got := Reachable(chainCatalog(), []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, MapResolver{})
	want := map[adprimitive.Capability]bool{
		{Kind: adprimitive.CapDomainUser}:                true,
		{Kind: adprimitive.CapKerberoastableTargetKnown}: true,
		{Kind: adprimitive.CapServiceAccountCredential}:  true,
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d reachable capabilities, got %d: %+v", len(want), len(got), got)
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected reachable capability %+v", c)
		}
	}
}

func TestReachable_TerminatesOnCyclicCatalog(t *testing.T) {
	cyclic := []adprimitive.Primitive{
		{
			ID:             "cycle-a",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapGroupMember}},
		},
		{
			ID:             "cycle-b",
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapGroupMember}}},
			Postconditions: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, // already held -- would loop forever without a fixpoint check
		},
	}
	done := make(chan []adprimitive.Capability, 1)
	go func() {
		done <- Reachable(cyclic, []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, MapResolver{})
	}()
	select {
	case got := <-done:
		if len(got) != 2 {
			t.Errorf("expected 2 reachable capabilities (DomainUser, GroupMember), got %d: %+v", len(got), got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Reachable did not terminate on a cyclic catalog")
	}
}

func TestPlan_ReturnsOrderedPathToTarget(t *testing.T) {
	path, ok := Plan(chainCatalog(), []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, adprimitive.Capability{Kind: adprimitive.CapServiceAccountCredential}, MapResolver{})
	if !ok {
		t.Fatal("expected target to be reachable")
	}
	var ids []string
	for _, p := range path {
		ids = append(ids, p.ID)
	}
	if !reflect.DeepEqual(ids, []string{"step-a", "step-b"}) {
		t.Fatalf("expected ordered path [step-a step-b], got %v", ids)
	}
}

func TestPlan_UnreachableTargetReturnsFalse(t *testing.T) {
	_, ok := Plan(chainCatalog(), []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial}, MapResolver{})
	if ok {
		t.Fatal("expected target to be unreachable (step-unreachable requires CapLocalAdmin, never produced)")
	}
}
