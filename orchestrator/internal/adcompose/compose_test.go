package adcompose

import (
	"testing"

	"github.com/audspect/bas/internal/adcoverage"
	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adlab"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// --- fixtures -------------------------------------------------------------

func capCtl() adprimitive.Capability {
	return adprimitive.Capability{Kind: adprimitive.CapControlledAccount}
}
func capUser() adprimitive.Capability { return adprimitive.Capability{Kind: adprimitive.CapDomainUser} }

// pA: no prereqs, grants CapControlledAccount; mapped to one step.
func pA() adprimitive.Primitive {
	return adprimitive.Primitive{ID: "pA", TechniqueID: "T1", RiskClass: adprimitive.RiskNonDestructive,
		Postconditions: []adprimitive.Capability{capCtl()}}
}

// pB: requires CapControlledAccount (pA's postcondition); mapped to one step.
func pB() adprimitive.Primitive {
	return adprimitive.Primitive{ID: "pB", TechniqueID: "T2", RiskClass: adprimitive.RiskPotentiallyDestructive,
		Prerequisites: adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{capCtl()}}}
}

// pCond: requires condition acl_right_held:GenericAll == true; mapped.
func pCond() adprimitive.Primitive {
	return adprimitive.Primitive{ID: "pCond", TechniqueID: "T3", RiskClass: adprimitive.RiskNonDestructive,
		Prerequisites: adprimitive.Prerequisites{Conditions: map[string]bool{"acl_right_held:GenericAll": true}}}
}

func coverage(entries ...adprimitive.Primitive) adcoverage.Report {
	var rep adcoverage.Report
	for _, p := range entries {
		rep.Covered = append(rep.Covered, adcoverage.PrimitiveCoverage{
			Primitive: p,
			Steps:     []adcoverage.StepRef{{Scenario: p.ID + ".yaml", StepName: "step-" + p.ID, Framework: "custom", TechniqueID: p.TechniqueID}},
		})
	}
	return rep
}

// lab whose attacker directly holds GenericAll (so acl_right_held:GenericAll resolves true).
func labWithGenericAll() adlab.Lab {
	return adlab.Lab{Attacker: "attacker", Env: adenv.Environment{
		Authorization: adenv.Authorization{ACLs: []adenv.ACLEntry{{Principal: "attacker", Target: "v", Right: adenv.ACLGenericAll}}},
	}}
}

func emptyLab() adlab.Lab { return adlab.Lab{Attacker: "attacker"} }

// --- tests ----------------------------------------------------------------

func TestCompose_FullyComposable(t *testing.T) {
	c := Compose([]adprimitive.Primitive{pA(), pB()}, []adprimitive.Capability{capUser()}, coverage(pA(), pB()), emptyLab())
	if !c.Composable {
		t.Fatalf("expected composable, got problems: %+v", c.Steps)
	}
	if len(c.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(c.Steps))
	}
	for _, s := range c.Steps {
		if len(s.Problems) != 0 {
			t.Errorf("step %s unexpected problems %+v", s.Primitive.ID, s.Problems)
		}
		if s.Capability.Scenario == "" || s.RiskClass == "" || s.Primitive.ID == "" {
			t.Errorf("step %s missing a link (cap=%+v risk=%q)", s.Primitive.ID, s.Capability, s.RiskClass)
		}
	}
}

func TestCompose_UnmappedPrimitiveSurfaced(t *testing.T) {
	gap := adprimitive.Primitive{ID: "gap", RiskClass: adprimitive.RiskNonDestructive}
	c := Compose([]adprimitive.Primitive{gap}, nil, coverage() /* empty */, emptyLab())
	if c.Composable || len(c.Steps) != 1 {
		t.Fatalf("expected 1 step, not composable, got %+v", c)
	}
	if !hasProblem(c.Steps[0], ProblemUnmapped) || c.Steps[0].Capability.Scenario != "" {
		t.Fatalf("expected unmapped with zero capability, got %+v", c.Steps[0])
	}
}

func TestCompose_UnmetPrerequisite(t *testing.T) {
	// pB requires CapControlledAccount; no pA ahead of it and empty held.
	c := Compose([]adprimitive.Primitive{pB()}, nil, coverage(pB()), emptyLab())
	if c.Composable || !hasProblem(c.Steps[0], ProblemUnmetPrerequisite) {
		t.Fatalf("expected unmet prerequisite, got %+v", c.Steps[0])
	}
}

func TestCompose_PrereqSatisfiedByEarlierPostcondition(t *testing.T) {
	// pA grants CapControlledAccount, so pB's prereq is met -> no unmet-prereq.
	c := Compose([]adprimitive.Primitive{pA(), pB()}, nil, coverage(pA(), pB()), emptyLab())
	for _, s := range c.Steps {
		if hasProblem(s, ProblemUnmetPrerequisite) {
			t.Fatalf("step %s should not be unmet (pA provides it): %+v", s.Primitive.ID, s.Problems)
		}
	}
}

func TestCompose_UnresolvedConditionAndSatisfiedCondition(t *testing.T) {
	neg := Compose([]adprimitive.Primitive{pCond()}, nil, coverage(pCond()), emptyLab())
	if neg.Composable || !hasProblem(neg.Steps[0], ProblemUnresolvedCondition) {
		t.Fatalf("empty lab must flag unresolved condition, got %+v", neg.Steps[0])
	}
	pos := Compose([]adprimitive.Primitive{pCond()}, nil, coverage(pCond()), labWithGenericAll())
	if !pos.Composable {
		t.Fatalf("lab holding GenericAll must satisfy the condition, got %+v", pos.Steps[0])
	}
}

func TestCompose_AmbiguousMappingDeterministic(t *testing.T) {
	rep := adcoverage.Report{Covered: []adcoverage.PrimitiveCoverage{{
		Primitive: pA(),
		Steps: []adcoverage.StepRef{
			{Scenario: "z.yaml", StepName: "b", Framework: "art"},
			{Scenario: "a.yaml", StepName: "a", Framework: "custom"},
		},
	}}}
	c := Compose([]adprimitive.Primitive{pA()}, nil, rep, emptyLab())
	if !hasProblem(c.Steps[0], ProblemAmbiguousMapping) {
		t.Fatalf("expected ambiguous_mapping, got %+v", c.Steps[0])
	}
	if c.Steps[0].Capability.Scenario != "a.yaml" { // lexicographically-first wins, stably
		t.Fatalf("expected first-by-stable-sort (a.yaml), got %q", c.Steps[0].Capability.Scenario)
	}
}

func TestCompose_AuthorizationSeparation(t *testing.T) {
	c := Compose([]adprimitive.Primitive{pA()}, nil, coverage(pA()), labWithGenericAll())
	if !c.Composable {
		t.Fatalf("precondition: expected composable chain, got %+v", c.Steps)
	}
	// Composable is NOT permission. Permission comes only from a separate
	// adgate.Decide call, which adcompose never makes.
	d := adgate.Decide(adgate.Request{
		Class: scenario.ExecutionClass(c.Steps[0].RiskClass),
		Env:   adgate.SyntheticProvenance(), // D would read this from lab.Attestation
		Auth:  adgate.Authorization{Authorized: true},
	})
	if !d.Allowed {
		t.Fatalf("separate gate decision should allow here, got %+v", d)
	}
}

func hasProblem(s ComposedStep, k ProblemKind) bool {
	for _, p := range s.Problems {
		if p.Kind == k {
			return true
		}
	}
	return false
}
