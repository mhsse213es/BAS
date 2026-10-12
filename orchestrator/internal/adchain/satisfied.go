package adchain

import (
	"slices"

	"github.com/audspect/bas/internal/adprimitive"
)

// satisfied reports whether p's Prerequisites are met: every required
// Capability is present in held (by exact Kind+Target equality), and
// every Conditions entry resolves to the required boolean value.
// Prerequisites.DomainJoined/Privileges are not evaluated here -- no
// caller-supplied attacker-context input exists yet for this phase.
func satisfied(p adprimitive.Primitive, held []adprimitive.Capability, resolver ConditionResolver) bool {
	for _, want := range p.Prerequisites.Capabilities {
		if !containsCapability(held, want) {
			return false
		}
	}
	for key, want := range p.Prerequisites.Conditions {
		if resolver.Resolve(key) != want {
			return false
		}
	}
	return true
}

func containsCapability(held []adprimitive.Capability, want adprimitive.Capability) bool {
	return slices.Contains(held, want)
}
