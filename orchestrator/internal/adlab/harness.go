package adlab

import (
	"slices"
	"strings"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adprimitive"
)

// Expectation is one target capability and what the planner should do with
// it for a given lab. WantPathIDs is checked only when WantReachable.
type Expectation struct {
	Target        adprimitive.Capability
	WantReachable bool
	WantPathIDs   []string
}

// Case pairs a lab with the in-scope primitive catalog, the attacker's
// starting capabilities, and the expectations to assert.
type Case struct {
	Lab          Lab
	Catalog      []adprimitive.Primitive
	StartHeld    []adprimitive.Capability
	Expectations []Expectation
}

// Failure is one expectation that did not hold. Empty slice from Validate
// means every expectation passed.
type Failure struct {
	Target adprimitive.Capability
	Reason string
}

// Validate runs the full Fixture -> Environment -> EnvResolver -> Plan ->
// Expected chain for every expectation in c.
func Validate(c Case) []Failure {
	resolver := NewEnvResolver(c.Lab.Env, c.Lab.Attacker)
	var fails []Failure
	for _, exp := range c.Expectations {
		path, ok := adchain.Plan(c.Catalog, c.StartHeld, exp.Target, resolver)
		if ok != exp.WantReachable {
			fails = append(fails, Failure{
				Target: exp.Target,
				Reason: reachabilityReason(exp.WantReachable),
			})
			continue
		}
		if exp.WantReachable {
			gotIDs := primitiveIDs(path)
			if !slices.Equal(gotIDs, exp.WantPathIDs) {
				fails = append(fails, Failure{
					Target: exp.Target,
					Reason: "path mismatch: want " + joinIDs(exp.WantPathIDs) + ", got " + joinIDs(gotIDs),
				})
			}
		}
	}
	return fails
}

func reachabilityReason(want bool) string {
	if want {
		return "expected target reachable, but planner found no path"
	}
	return "expected target unreachable, but planner found a path"
}

func primitiveIDs(path []adprimitive.Primitive) []string {
	ids := make([]string, 0, len(path))
	for _, p := range path {
		ids = append(ids, p.ID)
	}
	return ids
}

func joinIDs(ids []string) string {
	if len(ids) == 0 {
		return "[]"
	}
	return "[" + strings.Join(ids, " ") + "]"
}
