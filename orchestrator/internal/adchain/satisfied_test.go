package adchain

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
)

func TestSatisfied_RequiresEveryHeldCapabilityPresent(t *testing.T) {
	p := adprimitive.Primitive{
		Prerequisites: adprimitive.Prerequisites{
			Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}},
		},
	}
	if satisfied(p, nil, MapResolver{}) {
		t.Error("expected false: required capability not held")
	}
	if !satisfied(p, []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}, MapResolver{}) {
		t.Error("expected true: required capability held")
	}
}

func TestSatisfied_TargetScopedCapabilityDoesNotMatchHostAgnosticHeld(t *testing.T) {
	p := adprimitive.Primitive{
		Prerequisites: adprimitive.Prerequisites{
			Capabilities: []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin, Target: "SERVER01"}},
		},
	}
	held := []adprimitive.Capability{{Kind: adprimitive.CapLocalAdmin}} // no Target
	if satisfied(p, held, MapResolver{}) {
		t.Error("expected false: held capability has no Target, prerequisite requires Target=SERVER01")
	}
}

func TestSatisfied_EmptyConditionsIsVacuouslyTrue(t *testing.T) {
	p := adprimitive.Primitive{} // no Capabilities, no Conditions
	if !satisfied(p, nil, MapResolver{}) {
		t.Error("expected true: no requirements at all")
	}
}

func TestSatisfied_ConditionsResolvedViaResolver(t *testing.T) {
	p := adprimitive.Primitive{
		Prerequisites: adprimitive.Prerequisites{
			Conditions: map[string]bool{"acl_right_held:GenericAll": true},
		},
	}
	if satisfied(p, nil, MapResolver{}) {
		t.Error("expected false: resolver has no entry, defaults to false")
	}
	resolver := MapResolver{"acl_right_held:GenericAll": true}
	if !satisfied(p, nil, resolver) {
		t.Error("expected true: resolver confirms the condition")
	}
}

func TestSatisfied_AConditionRequiredFalseMustNotBeResolvedTrue(t *testing.T) {
	// Prerequisites.Conditions maps key -> required boolean value; a
	// primitive could in principle require a condition to be FALSE.
	p := adprimitive.Primitive{
		Prerequisites: adprimitive.Prerequisites{
			Conditions: map[string]bool{"manager_approval_required": false},
		},
	}
	resolver := MapResolver{"manager_approval_required": true}
	if satisfied(p, nil, resolver) {
		t.Error("expected false: condition requires false, resolver says true")
	}
	resolver2 := MapResolver{"manager_approval_required": false}
	if !satisfied(p, nil, resolver2) {
		t.Error("expected true: condition requires false, resolver agrees")
	}
}
