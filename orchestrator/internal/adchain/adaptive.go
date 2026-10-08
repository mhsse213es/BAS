package adchain

import (
	"sort"

	"github.com/audspect/bas/internal/adprimitive"
)

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

// RankedPlan is one candidate plan to a target, with its total PathRisk.
type RankedPlan struct {
	Steps []adprimitive.Primitive
	Risk  int
}

// RankedPlans returns candidate plans from held to target, lowest-risk
// first. It computes the primary plan, then one alternative per primitive
// in it (re-routing around that primitive via PlanExcluding), dedups
// identical plans, and sorts ascending by PathRisk with a deterministic
// tie-break on the plans' primitive-ID sequences. Empty if the target is
// unreachable at all.
func RankedPlans(catalog []adprimitive.Primitive, held []adprimitive.Capability, target adprimitive.Capability, resolver ConditionResolver) []RankedPlan {
	primary, ok := Plan(catalog, held, target, resolver)
	if !ok {
		return nil
	}

	candidates := [][]adprimitive.Primitive{primary}
	for _, step := range primary {
		if alt, ok := PlanExcluding(catalog, held, target, resolver, map[string]bool{step.ID: true}); ok {
			candidates = append(candidates, alt)
		}
	}

	seen := map[string]bool{}
	var out []RankedPlan
	for _, c := range candidates {
		key := planKey(c)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RankedPlan{Steps: c, Risk: PathRisk(c)})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk < out[j].Risk
		}
		return planKey(out[i].Steps) < planKey(out[j].Steps)
	})
	return out
}

func planKey(path []adprimitive.Primitive) string {
	s := ""
	for _, p := range path {
		s += p.ID + "\x00"
	}
	return s
}
