// Package adcompose is AD executable-content sub-project C: it composes an
// ordered chain of AD primitives into a traceable, metadata-only chain by
// linking each primitive to the existing capability A mapped it to. It
// authors nothing, executes nothing, and never implies permission to run --
// adgate remains the only execution decision point (wired by sub-project D).
// Depends one-way on adprimitive, adcoverage, adlab.
package adcompose

import (
	"fmt"
	"slices"
	"sort"

	"github.com/audspect/bas/internal/adcoverage"
	"github.com/audspect/bas/internal/adlab"
	"github.com/audspect/bas/internal/adprimitive"
)

type ProblemKind string

const (
	ProblemUnmapped            ProblemKind = "unmapped"
	ProblemUnmetPrerequisite   ProblemKind = "unmet_prerequisite"
	ProblemUnresolvedCondition ProblemKind = "unresolved_condition"
	ProblemAmbiguousMapping    ProblemKind = "ambiguous_mapping"
)

// Problem annotates a composed step; it never removes it.
type Problem struct {
	Kind   ProblemKind
	Detail string
}

// ComposedStep links one source primitive to its chosen mapped capability and
// its primitive-level classification. Capability is the zero value when the
// primitive is unmapped. RiskClass is metadata, never permission.
type ComposedStep struct {
	Primitive  adprimitive.Primitive
	Capability adcoverage.StepRef
	RiskClass  adprimitive.RiskClass
	Problems   []Problem
}

// ComposedChain is the ordered composition for one target synthetic lab. It
// has no authorized/runnable field by construction.
type ComposedChain struct {
	Lab        adlab.Lab
	Steps      []ComposedStep
	Composable bool
}

// Compose links each primitive in chain to its mapped capability and records
// composition problems deterministically. Pure and total.
func Compose(chain []adprimitive.Primitive, held []adprimitive.Capability, cov adcoverage.Report, lab adlab.Lab) ComposedChain {
	resolver := adlab.NewEnvResolver(lab.Env, lab.Attacker)

	lookup := make(map[string][]adcoverage.StepRef, len(cov.Covered))
	for _, pc := range cov.Covered {
		lookup[pc.Primitive.ID] = pc.Steps
	}

	running := append([]adprimitive.Capability(nil), held...)
	out := ComposedChain{Lab: lab, Composable: true}

	for _, p := range chain {
		step := ComposedStep{Primitive: p, RiskClass: p.RiskClass}

		refs := append([]adcoverage.StepRef(nil), lookup[p.ID]...)
		if len(refs) == 0 {
			step.Problems = append(step.Problems, Problem{Kind: ProblemUnmapped, Detail: p.ID})
		} else {
			sort.Slice(refs, func(i, j int) bool {
				if refs[i].Scenario != refs[j].Scenario {
					return refs[i].Scenario < refs[j].Scenario
				}
				return refs[i].StepName < refs[j].StepName
			})
			step.Capability = refs[0]
			if len(refs) > 1 {
				step.Problems = append(step.Problems, Problem{Kind: ProblemAmbiguousMapping, Detail: fmt.Sprintf("%d candidate mappings", len(refs))})
			}
		}

		for _, want := range p.Prerequisites.Capabilities {
			if !slices.Contains(running, want) {
				step.Problems = append(step.Problems, Problem{Kind: ProblemUnmetPrerequisite, Detail: string(want.Kind)})
			}
		}

		condKeys := make([]string, 0, len(p.Prerequisites.Conditions))
		for k := range p.Prerequisites.Conditions {
			condKeys = append(condKeys, k)
		}
		sort.Strings(condKeys)
		for _, key := range condKeys {
			if resolver.Resolve(key) != p.Prerequisites.Conditions[key] {
				step.Problems = append(step.Problems, Problem{Kind: ProblemUnresolvedCondition, Detail: key})
			}
		}

		if len(step.Problems) > 0 {
			out.Composable = false
		}
		running = append(running, p.Postconditions...)
		out.Steps = append(out.Steps, step)
	}
	return out
}
