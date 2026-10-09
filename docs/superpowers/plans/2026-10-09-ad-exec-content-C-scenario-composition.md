# AD Executable-Content Sub-Project C — Scenario Composition — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `orchestrator/internal/adcompose`: a pure, total `Compose(chain, held, cov, lab) ComposedChain` that links an ordered primitive chain to A's coverage mapping, producing a traceable, metadata-only composed chain and surfacing composition problems deterministically. Composition never implies execution permission.

**Architecture:** One pure function over `adprimitive` primitives + `adcoverage.Report` + an `adlab.Lab`. Each primitive becomes a `ComposedStep` linked to its source primitive, its chosen mapped capability (`adcoverage.StepRef`), and its primitive-level `RiskClass`; problems (unmapped, unmet-prerequisite, unresolved-condition, ambiguous-mapping) are recorded, never dropped. Mirrors `adchain.satisfied` for prereq/condition checks. Imports neither `adgate` nor `scenario`.

**Tech Stack:** Go (stdlib `sort`/`fmt` only). No DB, no containers, no network, no execution.

**Spec:** `docs/superpowers/specs/2026-10-09-ad-exec-content-C-scenario-composition-design.md`

## Global Constraints

- Go stdlib only; no new third-party dependencies. `go 1.26.6`, module `github.com/audspect/bas`.
- `adcompose` depends one-way on `adprimitive`, `adcoverage`, `adlab`. It imports **neither `adgate` nor `scenario`** (v1 classification = primitive `RiskClass`). Nothing imports it back.
- No new raw commands/payloads/exploits; no agent/dispatch/orchestrator/execution changes; no `adgate` policy changes.
- **Composition never implies permission:** `ComposedChain` has no authorized/runnable field and the package never sets `scenario.Scenario.Executable` or calls `adgate.Decide`.
- Prerequisite/condition semantics mirror `adchain.satisfied` exactly: required `Capability` present in the running held set by exact Kind+Target equality; `Conditions` entry satisfies `resolver.Resolve(key) == want`; `DomainJoined`/`Privileges` not evaluated.
- `Compose` is pure and total: no error return, no panic. Problems + `Composable=false` report trouble; they are never Go errors.
- Deterministic output: ambiguous mappings resolved by stable `(Scenario, StepName)` sort; condition problems emitted in sorted-key order.

## Review Focus

- **Gap primitive is surfaced, not dropped:** a primitive absent from `cov.Covered` yields exactly one `ComposedStep` with `Problem{unmapped}` and a zero `Capability`, `Composable=false` — never silently omitted. → Task 1, Step 1.
- **Prerequisite accumulation across the chain:** a later primitive's required capability satisfied only by an earlier primitive's postcondition must NOT be flagged unmet; the same requirement with no provider must be. → Task 1, Step 1.
- **Condition direction matches the lab:** a `Conditions{key:true}` entry is satisfied only when `resolver.Resolve(key)==true` for the given lab; the negative lab flags `unresolved_condition`. → Task 1, Step 1.
- **Ambiguity is deterministic:** a primitive mapped to two `StepRef`s always chooses the lexicographically-first `(Scenario, StepName)` and records `ambiguous_mapping`, identically across runs. → Task 1, Step 1.
- **Authorization separation is structural:** `ComposedChain` exposes no runnable/authorized field; a fully-composable chain is still not permission — only a separate `adgate.Decide` call yields allow. → Task 1, Step 1.

---

### Task 1: The `adcompose` composition function

**Files:**
- Create: `orchestrator/internal/adcompose/compose.go`
- Test: `orchestrator/internal/adcompose/compose_test.go`

**Interfaces:**
- Consumes: `adprimitive.{Primitive,Capability,Prerequisites,RiskClass,CapabilityKind,Cap* consts}`, `adcoverage.{StepRef,PrimitiveCoverage,Report}`, `adlab.{Lab,NewEnvResolver}`, `adenv.{Environment,Identity,Group,Authorization,ACLEntry,ACLGenericAll}`.
- Produces: `type ProblemKind`, `type Problem`, `type ComposedStep`, `type ComposedChain`, `func Compose(chain []adprimitive.Primitive, held []adprimitive.Capability, cov adcoverage.Report, lab adlab.Lab) ComposedChain`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adcompose/compose_test.go
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

func capCtl() adprimitive.Capability { return adprimitive.Capability{Kind: adprimitive.CapControlledAccount} }
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adcompose/...`
Expected: FAIL — `undefined: Compose` / `undefined: ComposedStep` / etc.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adcompose/compose.go

// Package adcompose is AD executable-content sub-project C: it composes an
// ordered chain of AD primitives into a traceable, metadata-only chain by
// linking each primitive to the existing capability A mapped it to. It
// authors nothing, executes nothing, and never implies permission to run --
// adgate remains the only execution decision point (wired by sub-project D).
// Depends one-way on adprimitive, adcoverage, adlab.
package adcompose

import (
	"fmt"
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
			if !containsCapability(running, want) {
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

func containsCapability(held []adprimitive.Capability, want adprimitive.Capability) bool {
	for _, h := range held {
		if h == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adcompose/... -v`
Expected: PASS — all tests.

- [ ] **Step 5: Run gofmt, go vet, and the full build**

Run: `cd orchestrator && gofmt -l internal/adcompose/ && go vet ./internal/adcompose/... && go build ./...`
Expected: gofmt/vet print nothing; build succeeds.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adcompose/compose.go orchestrator/internal/adcompose/compose_test.go
git commit -m "$(cat <<'EOF'
feat(adcompose): add primitive-chain scenario composition (sub-project C)

Compose links an ordered primitive chain to A's coverage mapping into a
traceable, metadata-only ComposedChain: each step carries its source
primitive, chosen mapped capability, and primitive RiskClass, plus
deterministic problems (unmapped, unmet-prerequisite, unresolved-
condition, ambiguous-mapping) mirroring adchain.satisfied. Pure/total;
imports neither adgate nor scenario; never implies execution permission
(adgate stays the only decision point, wired by D). No new payloads.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing "Inline Over Subagents" preference and their "start" authorization — already decided, not asking.** Single task; no inter-task interfaces. Proceeding via `superpowers:executing-plans`, final self-review at the end (subagent reviewer dispatch has been hitting hard `[cyber]` blocks on AD-framed prompts this session).
