// Package adrehearse is the AD executable-content D-sim milestone: a pure-Go
// rehearsal in which the plan-producing API is itself the control boundary.
// Rehearse gates a composed chain through adgate.Decide and yields an ordered,
// provenance-preserving hypothetical plan ONLY on allow. It executes nothing
// and is NOT the runtime enforcement control -- proving the real orchestrator
// has no bypass is sub-project D-runtime, separate from this package.
package adrehearse

import (
	"github.com/audspect/bas/internal/adcompose"
	"github.com/audspect/bas/internal/adcoverage"
	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// PlannedStep is one step of the hypothetical plan, preserving provenance.
type PlannedStep struct {
	Primitive  adprimitive.Primitive
	Capability adcoverage.StepRef
	RiskClass  adprimitive.RiskClass
}

// Rehearsal is the outcome. Plan is non-nil ONLY when Allowed, and Rehearse is
// the only producer of a Plan.
type Rehearsal struct {
	Allowed  bool
	Decision adgate.Decision
	Plan     []PlannedStep
	Note     string
}

// Rehearse gates chain through adgate.Decide and produces the hypothetical plan
// only on allow. Pure and total; executes nothing.
func Rehearse(chain adcompose.ComposedChain, auth adgate.Authorization) Rehearsal {
	if !chain.Composable {
		return Rehearsal{Allowed: false, Note: "chain not composable"}
	}
	decision := adgate.Decide(adgate.Request{
		Class: chainClass(chain.Steps),
		Env:   chain.Lab.Attestation,
		Auth:  auth,
	})
	r := Rehearsal{Allowed: decision.Allowed, Decision: decision}
	if decision.Allowed {
		r.Plan = buildPlan(chain.Steps)
	}
	return r
}

// buildPlan is unexported: Rehearse is the sole producer of a Plan, and it only
// calls this after a successful gate decision.
func buildPlan(steps []adcompose.ComposedStep) []PlannedStep {
	plan := make([]PlannedStep, 0, len(steps))
	for _, s := range steps {
		plan = append(plan, PlannedStep{Primitive: s.Primitive, Capability: s.Capability, RiskClass: s.RiskClass})
	}
	return plan
}

// chainClass returns the most-restrictive step RiskClass as an ExecutionClass.
// Any unrecognized/empty step class, or an empty chain, yields "" (unknown), so
// the gate fails closed on unknown_classification.
func chainClass(steps []adcompose.ComposedStep) scenario.ExecutionClass {
	if len(steps) == 0 {
		return ""
	}
	rank := map[adprimitive.RiskClass]int{
		adprimitive.RiskNonDestructive:         1,
		adprimitive.RiskPotentiallyDestructive: 2,
		adprimitive.RiskDestructive:            3,
	}
	worst := adprimitive.RiskNonDestructive
	for _, s := range steps {
		r, ok := rank[s.RiskClass]
		if !ok {
			return "" // unknown/empty class -> fail closed
		}
		if r > rank[worst] {
			worst = s.RiskClass
		}
	}
	return scenario.ExecutionClass(worst)
}
