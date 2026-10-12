package adlab

import (
	"testing"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adprimitive"
)

// SyntheticProvider satisfies Provider.
var _ Provider = SyntheticProvider{}

func controlledAccount() adprimitive.Capability {
	return adprimitive.Capability{Kind: adprimitive.CapControlledAccount}
}
func domainUserHeld() []adprimitive.Capability {
	return []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}
}

func TestSyntheticProvider_ReturnsAllBuiltInLabsNoError(t *testing.T) {
	labs, err := SyntheticProvider{}.Labs()
	if err != nil {
		t.Fatalf("synthetic provider must not error: %v", err)
	}
	if len(labs) != 4 {
		t.Fatalf("expected 4 built-in labs, got %d", len(labs))
	}
	seen := map[string]bool{}
	for _, l := range labs {
		if seen[l.Name] {
			t.Fatalf("duplicate lab name %q", l.Name)
		}
		seen[l.Name] = true
	}
}

func TestLab_ACLGenericAllTakeoverReachable(t *testing.T) {
	c := Case{
		Lab:       aclGenericAllTakeoverLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: domainUserHeld(),
		Expectations: []Expectation{{
			Target:        controlledAccount(),
			WantReachable: true,
			WantPathIDs:   []string{"acl-genericall-takeover"},
		}},
	}
	if fails := Validate(c); len(fails) != 0 {
		t.Fatalf("expected clean validation, got %+v", fails)
	}
}

func TestLab_ADCSESC1EnrollmentGatePositiveAndNegative(t *testing.T) {
	pos := Case{
		Lab:       adcsESC1EnrollableLab(),
		Catalog:   adprimitive.ADCSCatalog,
		StartHeld: domainUserHeld(),
		Expectations: []Expectation{{
			Target:        controlledAccount(),
			WantReachable: true,
			WantPathIDs:   []string{"adcs-esc1"},
		}},
	}
	if fails := Validate(pos); len(fails) != 0 {
		t.Fatalf("positive ESC1 lab should validate clean, got %+v", fails)
	}

	neg := Case{
		Lab:       adcsESC1NotEnrollableLab(),
		Catalog:   adprimitive.ADCSCatalog,
		StartHeld: domainUserHeld(),
		Expectations: []Expectation{{
			Target:        controlledAccount(),
			WantReachable: false, // same vulnerable template, attacker can't enroll
		}},
	}
	if fails := Validate(neg); len(fails) != 0 {
		t.Fatalf("negative ESC1 lab should validate clean (target unreachable), got %+v", fails)
	}
}

func TestLab_NoFootholdSafeUnreachable(t *testing.T) {
	c := Case{
		Lab:       noFootholdSafeLab(),
		Catalog:   adprimitive.ACLAbuseCatalog,
		StartHeld: domainUserHeld(),
		Expectations: []Expectation{{
			Target:        controlledAccount(),
			WantReachable: false,
		}},
	}
	if fails := Validate(c); len(fails) != 0 {
		t.Fatalf("safe lab should validate clean (target unreachable), got %+v", fails)
	}
}

// Integration: the ACL takeover lab also validates against the FULL catalog,
// confirming the resolver doesn't spuriously enable unrelated primitives.
func TestLab_FullCatalogIntegration(t *testing.T) {
	lab := aclGenericAllTakeoverLab()
	resolver := NewEnvResolver(lab.Env, lab.Attacker)
	full := append(append([]adprimitive.Primitive{}, adprimitive.ACLAbuseCatalog...), adprimitive.ADCSCatalog...)
	_, ok := adchain.Plan(full, domainUserHeld(), controlledAccount(), resolver)
	if !ok {
		t.Fatal("expected CapControlledAccount reachable under the full catalog")
	}
}
