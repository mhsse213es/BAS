package adchain

import "github.com/audspect/bas/internal/adprimitive"

// Reachable computes the full closure of capabilities reachable from
// held by repeatedly applying any primitive in catalog whose
// Prerequisites become satisfied, until a pass adds nothing new (a
// fixpoint) -- which also bounds the loop on a catalog containing a
// cycle, since a cycle stops producing anything new once every capability
// it can reach is already held.
func Reachable(catalog []adprimitive.Primitive, held []adprimitive.Capability, resolver ConditionResolver) []adprimitive.Capability {
	for {
		added := false
		for _, p := range catalog {
			if !satisfied(p, held, resolver) {
				continue
			}
			for _, post := range p.Postconditions {
				if !containsCapability(held, post) {
					held = append(held, post)
					added = true
				}
			}
		}
		if !added {
			return held
		}
	}
}

// Plan searches for one ordered sequence of primitives from catalog
// that, applied in order starting from held, produces target. Returns
// ok=false if target is never reachable under catalog/held/resolver.
func Plan(catalog []adprimitive.Primitive, held []adprimitive.Capability, target adprimitive.Capability, resolver ConditionResolver) ([]adprimitive.Primitive, bool) {
	var path []adprimitive.Primitive
	if containsCapability(held, target) {
		return path, true
	}
	for {
		applied := false
		for _, p := range catalog {
			if !satisfied(p, held, resolver) {
				continue
			}
			newCapability := false
			for _, post := range p.Postconditions {
				if !containsCapability(held, post) {
					held = append(held, post)
					newCapability = true
				}
			}
			if !newCapability {
				continue
			}
			path = append(path, p)
			applied = true
			if containsCapability(p.Postconditions, target) {
				return path, true
			}
		}
		if !applied {
			return nil, false
		}
	}
}
