package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adprimitive"
)

// A minimal lab: attacker's group holds GenericAll -> CapControlledAccount
// reachable via acl-genericall-takeover.
func minimalACLLab() Lab {
	return Lab{
		Name:     "harness-min",
		Attacker: "attacker",
		Env: adenv.Environment{
			Identity: adenv.Identity{Groups: []adenv.Group{
				{Name: "Helpdesk", Members: []string{"attacker"}},
			}},
			Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{
				{Principal: "Helpdesk", Target: "svc-admin", Right: adenv.ACLGenericAll},
			}},
		},
	}
}

func TestValidate_ReportsReachableWithExpectedPath(t *testing.T) {
	c := Case{
		Lab:       minimalACLLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}},
		Expectations: []Expectation{{
			Target:        adprimitive.Capability{Kind: adprimitive.CapControlledAccount},
			WantReachable: true,
			WantPathIDs:   []string{"acl-genericall-takeover"},
		}},
	}
	if fails := Validate(c); len(fails) != 0 {
		t.Fatalf("expected no failures, got %+v", fails)
	}
}

func TestValidate_ReportsFailureOnWrongExpectation(t *testing.T) {
	// Assert UNreachable when it is in fact reachable -> one Failure.
	c := Case{
		Lab:       minimalACLLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}},
		Expectations: []Expectation{{
			Target:        adprimitive.Capability{Kind: adprimitive.CapControlledAccount},
			WantReachable: false,
		}},
	}
	fails := Validate(c)
	if len(fails) != 1 {
		t.Fatalf("expected exactly 1 failure, got %d: %+v", len(fails), fails)
	}
}

func TestValidate_PathMismatchIsAFailure(t *testing.T) {
	c := Case{
		Lab:       minimalACLLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}},
		Expectations: []Expectation{{
			Target:        adprimitive.Capability{Kind: adprimitive.CapControlledAccount},
			WantReachable: true,
			WantPathIDs:   []string{"some-other-primitive"}, // wrong
		}},
	}
	if fails := Validate(c); len(fails) != 1 {
		t.Fatalf("expected 1 failure for path mismatch, got %+v", fails)
	}
}
