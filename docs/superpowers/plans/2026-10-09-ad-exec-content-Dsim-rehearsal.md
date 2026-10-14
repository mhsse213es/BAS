# AD Executable-Content — D-sim (Enforcement Rehearsal) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task (execution method already decided — native/inline, no subagent dispatch). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `orchestrator/internal/adrehearse`: a pure `Rehearse(chain, auth) Rehearsal` whose plan-producing API is itself the control boundary — it gates via `adgate.Decide` and yields an ordered, provenance-preserving hypothetical plan only on allow, executing nothing.

**Architecture:** One pure function over an `adcompose.ComposedChain`. Fail-closed if the chain is non-composable; compute the chain's most-restrictive `RiskClass` (unknown/empty → deny); call `adgate.Decide` with the lab's origin `Attestation` as the environment and the explicit `Authorization`; build the `Plan` only when the decision allows. The plan-builder is unexported, so `Rehearse` is the sole producer of a plan.

**Tech Stack:** Go (stdlib only). No DB, no containers, no network, no execution.

**Spec:** `docs/superpowers/specs/2026-10-09-ad-exec-content-Dsim-rehearsal-design.md`

## Global Constraints

- Go stdlib only; no new third-party dependencies. `go 1.26.6`, module `github.com/audspect/bas`.
- `adrehearse` deps (one-way): `adcompose`, `adlab`, `adgate`, `adprimitive`, `adcoverage`, `scenario`. Imports no dispatch/agent/orchestrator code. Nothing imports it back.
- No change to `adgate`, `adcompose`, `scenario`, or any existing package.
- `Rehearse` is pure and total: no error return, no panic, no side effects, no execution.
- The gate is the structural boundary: the plan-builder is unexported; `Rehearse` is the only exported producer of a `Plan`, and it always calls `adgate.Decide` first.
- Fail-closed: non-composable chain, denied decision, or unknown/empty classification all yield `Allowed=false` and a nil `Plan`.
- Classification is fail-safe: the chain's class is the most-restrictive step `RiskClass`; any unrecognized/empty step class, or an empty chain, makes the class unknown (`""`) → gate denies `unknown_classification`.

## Review Focus

- **No plan without a successful gate decision:** every denied/refused path leaves `Plan == nil`; a plan exists only when `Decision.Allowed`. → Task 1, Step 1.
- **Non-composable fails closed before the gate:** `Composable:false` → `Allowed:false`, `Note` set, no plan; the gate is not consulted and its absence is never read as permission. → Task 1, Step 1.
- **Most-restrictive classification is fail-safe:** a chain mixing non-destructive and destructive steps gates as destructive (needs `DestructiveApproved`); a chain with any empty/bogus step class gates as unknown (deny). → Task 1, Step 1.
- **Environment provenance comes from the lab stamp:** a synthetic `Attestation` allows; zero-value and `LiveAD` deny `not_synthetic`. → Task 1, Step 1.
- **Plan preserves order + provenance:** `Plan` is in `Steps` order and each `PlannedStep` carries the same `Primitive.ID` and `Capability`. → Task 1, Step 1.

---

### Task 1: The `adrehearse` rehearsal function

**Files:**
- Create: `orchestrator/internal/adrehearse/rehearse.go`
- Test: `orchestrator/internal/adrehearse/rehearse_test.go`

**Interfaces:**
- Consumes: `adcompose.{ComposedChain,ComposedStep}`, `adlab.Lab`, `adgate.{Decide,Request,Decision,Authorization,Provenance,SyntheticProvenance,LiveADProvenance,Reason consts}`, `adprimitive.{Primitive,RiskClass,Risk* consts}`, `adcoverage.StepRef`, `scenario.ExecutionClass`.
- Produces: `type PlannedStep`, `type Rehearsal`, `func Rehearse(chain adcompose.ComposedChain, auth adgate.Authorization) Rehearsal`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/adrehearse/rehearse_test.go
package adrehearse

import (
	"testing"

	"github.com/audspect/bas/internal/adcompose"
	"github.com/audspect/bas/internal/adcoverage"
	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adlab"
	"github.com/audspect/bas/internal/adprimitive"
)

func step(id string, rc adprimitive.RiskClass) adcompose.ComposedStep {
	return adcompose.ComposedStep{
		Primitive:  adprimitive.Primitive{ID: id, RiskClass: rc},
		Capability: adcoverage.StepRef{Scenario: id + ".yaml", StepName: "step-" + id},
		RiskClass:  rc,
	}
}

func chain(prov adgate.Provenance, composable bool, steps ...adcompose.ComposedStep) adcompose.ComposedChain {
	return adcompose.ComposedChain{
		Lab:        adlab.Lab{Attestation: prov},
		Steps:      steps,
		Composable: composable,
	}
}

func authed() adgate.Authorization { return adgate.Authorization{Authorized: true} }

func TestRehearse_AuthorizedSyntheticAllowsAndPlans(t *testing.T) {
	c := chain(adgate.SyntheticProvenance(), true, step("p1", adprimitive.RiskNonDestructive), step("p2", adprimitive.RiskPotentiallyDestructive))
	r := Rehearse(c, authed())
	if !r.Allowed || !r.Decision.Allowed {
		t.Fatalf("expected allow, got %+v", r)
	}
	if len(r.Plan) != 2 || r.Plan[0].Primitive.ID != "p1" || r.Plan[1].Primitive.ID != "p2" {
		t.Fatalf("plan must preserve order + provenance, got %+v", r.Plan)
	}
	if r.Plan[0].Capability.Scenario != "p1.yaml" {
		t.Fatalf("plan must carry capability provenance, got %+v", r.Plan[0])
	}
}

func TestRehearse_UnverifiedEnvironmentDeniedNoPlan(t *testing.T) {
	r := Rehearse(chain(adgate.Provenance{}, true, step("p1", adprimitive.RiskNonDestructive)), authed())
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedNotSynthetic {
		t.Fatalf("zero-value provenance must deny not_synthetic with no plan, got %+v", r)
	}
}

func TestRehearse_LiveEnvironmentDeniedNoPlan(t *testing.T) {
	r := Rehearse(chain(adgate.LiveADProvenance(), true, step("p1", adprimitive.RiskNonDestructive)), authed())
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedNotSynthetic {
		t.Fatalf("live env must deny not_synthetic with no plan, got %+v", r)
	}
}

func TestRehearse_UnauthorizedDeniedNoPlan(t *testing.T) {
	r := Rehearse(chain(adgate.SyntheticProvenance(), true, step("p1", adprimitive.RiskNonDestructive)), adgate.Authorization{Authorized: false})
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedMissingAuth {
		t.Fatalf("unauthorized must deny missing_authorization with no plan, got %+v", r)
	}
}

func TestRehearse_DestructiveNeedsApproval(t *testing.T) {
	c := chain(adgate.SyntheticProvenance(), true, step("p1", adprimitive.RiskNonDestructive), step("p2", adprimitive.RiskDestructive))
	if r := Rehearse(c, authed()); r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedDestructiveNotApproved {
		t.Fatalf("destructive step without approval must deny with no plan, got %+v", r)
	}
	if r := Rehearse(c, adgate.Authorization{Authorized: true, DestructiveApproved: true}); !r.Allowed || len(r.Plan) != 2 {
		t.Fatalf("destructive with approval must allow + plan, got %+v", r)
	}
}

func TestRehearse_UnknownClassFailsClosed(t *testing.T) {
	r := Rehearse(chain(adgate.SyntheticProvenance(), true, step("p1", adprimitive.RiskClass("bogus"))), authed())
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedUnknownClass {
		t.Fatalf("bogus step class must deny unknown_classification, got %+v", r)
	}
}

func TestRehearse_NonComposableFailsClosedBeforeGate(t *testing.T) {
	r := Rehearse(chain(adgate.SyntheticProvenance(), false, step("p1", adprimitive.RiskNonDestructive)), authed())
	if r.Allowed || r.Plan != nil || r.Note == "" {
		t.Fatalf("non-composable chain must fail closed with a note and no plan, got %+v", r)
	}
}

func TestRehearse_EmptyChainIsUnknownClassDeny(t *testing.T) {
	r := Rehearse(chain(adgate.SyntheticProvenance(), true), authed())
	if r.Allowed || r.Plan != nil || r.Decision.Reason != adgate.ReasonDeniedUnknownClass {
		t.Fatalf("empty composable chain must deny unknown_classification, got %+v", r)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/adrehearse/...`
Expected: FAIL — `undefined: Rehearse` / `undefined: PlannedStep` / `undefined: Rehearsal`.

- [ ] **Step 3: Write the minimal implementation**

```go
// orchestrator/internal/adrehearse/rehearse.go

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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/adrehearse/... -v`
Expected: PASS — all tests.

- [ ] **Step 5: Run gofmt, go vet, and the full build**

Run: `cd orchestrator && gofmt -l internal/adrehearse/ && go vet ./internal/adrehearse/... && go build ./...`
Expected: gofmt/vet print nothing; build succeeds.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/adrehearse/rehearse.go orchestrator/internal/adrehearse/rehearse_test.go
git commit -m "$(cat <<'EOF'
feat(adrehearse): add enforcement-rehearsal (D-sim milestone)

Rehearse is the sole producer of a hypothetical execution plan and gates
first via adgate.Decide (chain's most-restrictive RiskClass as Class,
lab Attestation as Env, explicit Authorization); the plan is built only
on allow by an unexported builder, so there is no in-package path to a
plan that skips the decision. Non-composable chains and unknown/empty
classifications fail closed; nothing is executed. This is the rehearsal
for D-runtime, not runtime enforcement -- it proves the designed control
flow only, never that the real orchestrator has no bypass.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Execution Handoff

**Execution method: Native (inline, this session), per the user's standing "Inline Over Subagents" preference and explicit D-sim go-ahead — already decided.** Single task; no inter-task interfaces. Proceeding via `superpowers:executing-plans`, final self-review at the end (subagent reviewer dispatch has been hitting hard `[cyber]` blocks on AD-framed prompts this session).
