package adchain

import "github.com/audspect/bas/internal/adprimitive"

// riskWeight maps a primitive's RiskClass to a numeric cost. An
// unrecognized or empty class scores the maximum (fail-closed, mirroring
// scenario/execclass.go's unclassified=destructive default): an
// unclassified primitive must never look cheaper than a known-destructive
// one.
func riskWeight(c adprimitive.RiskClass) int {
	switch c {
	case adprimitive.RiskNonDestructive:
		return 1
	case adprimitive.RiskPotentiallyDestructive:
		return 3
	case adprimitive.RiskDestructive:
		return 9
	default:
		return 9
	}
}

// PathRisk is the summed risk weight of every primitive in path. An empty
// path has zero risk.
func PathRisk(path []adprimitive.Primitive) int {
	total := 0
	for _, p := range path {
		total += riskWeight(p.RiskClass)
	}
	return total
}

// PlanExcluding is Plan, but it never applies a primitive whose ID is in
// excluded -- the adaptive re-route primitive: when a primitive is
// blocked (failed, too risky, already detected), re-plan around it.
// Returns ok=false if the target is unreachable without the excluded
// primitives.
func PlanExcluding(catalog []adprimitive.Primitive, held []adprimitive.Capability, target adprimitive.Capability, resolver ConditionResolver, excluded map[string]bool) ([]adprimitive.Primitive, bool) {
	var path []adprimitive.Primitive
	if containsCapability(held, target) {
		return path, true
	}
	for {
		applied := false
		for _, p := range catalog {
			if excluded[p.ID] {
				continue
			}
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
