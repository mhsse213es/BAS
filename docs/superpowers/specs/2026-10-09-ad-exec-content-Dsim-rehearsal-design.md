# AD Executable-Content — D-sim (Enforcement Rehearsal) — Design Spec

**Status:** Draft for review
**Date:** 2026-10-09
**Parent initiative:** AD Mastery — "Executable AD content". D-sim is a **separate validation milestone**, the rehearsal for sub-project D-runtime. It is NOT sub-project D.

## Where this sits, and what it is not

A (`adcoverage`), B (`adgate`), C (`adcompose`) are complete. D-sim proves the
**designed** control flow: that a hypothetical execution plan can be produced
**only** through a successful `adgate` decision, against the synthetic M06 lab,
with nothing executed. D-sim is the rehearsal.

**D-sim explicitly does NOT, and cannot, prove** that Audspect's real
orchestrator has no alternate route that bypasses `adgate`. That is
**D-runtime** (the real sub-project D), a separate project with its own scope
and runtime-path tests. D-sim passing never means production is protected, and
this spec makes no such claim.

## Purpose

Provide a pure-Go rehearsal in which the plan-producing API itself is the
control boundary: it calls `adgate.Decide` and yields an ordered,
provenance-preserving hypothetical plan only on allow. This catches
control-flow design errors before any runtime integration.

## Scope

### In scope

- A new `orchestrator/internal/adrehearse` package (pure Go, no DB, no network,
  no agent, no execution).
- `Rehearse(chain adcompose.ComposedChain, auth adgate.Authorization) Rehearsal`
  — gate-first; the only producer of a hypothetical plan.

### Out of scope / boundaries

- No real command, network action, or agent dispatch; the package imports no
  dispatch/agent/orchestrator code.
- No change to `adgate` policy or authorization semantics, and no change to
  `adcompose`, `scenario`, or any other existing package.
- No wiring into the real `dispatchRun`/orchestrator path — that is D-runtime.
- No new AD primitives, payloads, or the 11 coverage gaps (E).
- No claim that simulated enforcement protects production.

## Trust/authorization recap (already satisfied upstream)

Authorization is already an explicit input to the policy contract
(`adgate.Authorization{Authorized, DestructiveApproved}`), passed explicitly to
`Rehearse`. Synthetic environment status alone does not grant permission:
`adgate` rule 3 still requires `Authorized`, and rule 4 requires
`DestructiveApproved` for a destructive-class action. D-sim needs no `adgate`
change.

## Architecture

New package `orchestrator/internal/adrehearse`, one-way deps on `adcompose`,
`adlab` (for `ComposedChain.Lab`), `adgate`, `adprimitive`, `adcoverage`, and
`scenario` (for the `ExecutionClass` the gate consumes). Nothing imports it back.

### Types and API

```go
// PlannedStep is one step of the hypothetical plan, preserving the source
// primitive and the mapped capability (provenance). Ordered within Plan.
type PlannedStep struct {
    Primitive  adprimitive.Primitive
    Capability adcoverage.StepRef
    RiskClass  adprimitive.RiskClass
}

// Rehearsal is the outcome. Plan is non-nil ONLY when Allowed, and Rehearse is
// the only producer of a Plan.
type Rehearsal struct {
    Allowed  bool
    Decision adgate.Decision // the governing gate decision (zero value if refused pre-gate)
    Plan     []PlannedStep   // nil unless Allowed
    Note     string          // set on a pre-gate fail-closed refusal (e.g. non-composable chain)
}

func Rehearse(chain adcompose.ComposedChain, auth adgate.Authorization) Rehearsal
```

### Control flow (the plan-producing API IS the gate)

1. **Pre-gate fail-closed:** if `!chain.Composable`, return
   `Rehearsal{Allowed:false, Note:"chain not composable"}` — no gate call, no
   plan. A broken chain is never runnable.
2. **Classify (fail-safe):** compute the chain's **most-restrictive**
   `RiskClass` across its steps. If any step's `RiskClass` is unrecognized or
   empty, the chain class is unknown (`""`) so the gate denies
   `unknown_classification`. An empty chain is also unknown.
3. **Gate:** `decision := adgate.Decide(adgate.Request{ Class: chainClass,
   Env: chain.Lab.Attestation, Auth: auth })`. The environment provenance is the
   lab's origin stamp (synthetic for an M06 lab; Unknown/LiveAD otherwise).
4. **Produce plan only on allow:** if `decision.Allowed`, build `Plan` from
   `chain.Steps` in order, each `PlannedStep` carrying its primitive, mapped
   capability, and `RiskClass`. Otherwise `Plan` stays nil.

The plan-builder is **unexported**; `Rehearse` is the sole exported producer of
a `Plan`, and it always gates first. There is no in-package path to a plan that
skips the decision.

`Rehearse` is pure and total: no error return, no panic, no side effects.

## Error handling

No Go error path. A non-composable chain, a denied decision, and an unknown
classification are all reported via `Allowed=false` + `Decision`/`Note` with a
nil `Plan`.

## Testing

Pure `go test`, synthetic fixtures (`adcompose.ComposedChain` literals with an
`adlab.Lab` carrying an `adgate` provenance stamp). **No test executes
anything.**

- **Authorized synthetic allows + plans:** composable chain, synthetic
  `Attestation`, known class, `Authorized` → `Allowed`, `Decision.Allowed`,
  `Plan` length == steps, plan preserves order + each step's primitive/capability.
- **Unverified denied:** zero-value `Provenance` → deny
  `denied_environment_not_synthetic`, `Plan == nil`.
- **Live environment denied:** `LiveADProvenance()` → deny
  `denied_environment_not_synthetic`, no plan.
- **Unauthorized denied:** synthetic but `Authorized:false` → deny
  `denied_missing_authorization`, no plan.
- **Destructive needs approval:** synthetic, a destructive-class step,
  `Authorized` but `!DestructiveApproved` → deny
  `denied_destructive_not_approved`, no plan; with `DestructiveApproved` → allow
  + plan.
- **Unknown classification fails closed:** a step with empty/bogus `RiskClass`
  → deny `denied_unknown_classification`, no plan.
- **Non-composable fails closed:** `Composable:false` → `Allowed:false`, `Note`
  set, no plan, and the gate verdict is not treated as permission.
- **Denied produces no plan:** every deny case asserts `Plan == nil`.
- **Ordering + provenance:** a multi-step composable synthetic chain → `Plan`
  order equals `Steps` order and each `PlannedStep` carries the same
  `Primitive.ID` and `Capability`.

## Acceptance criteria (D-sim)

1. An authorized synthetic environment passes the gate and yields a plan.
2. A non-synthetic, unverified, or unauthorized environment is denied.
3. A denied decision produces no plan.
4. A plan cannot be produced without a successful gate decision (the
   plan-producing API itself requires the decision; the builder is unexported).
5. The plan preserves chain ordering and primitive/capability provenance.
6. No real command, network action, or agent dispatch occurs.
7. `go build ./...`, `go vet`, `gofmt -l` clean; no change to any existing package.

## Deferred — D-runtime (the real sub-project D, separate project)

Runtime enforcement in the actual `dispatchRun` path: dispatch integration,
no-bypass across all paths (alternate/retry/cancel-resume), fail-closed on
missing/invalid inputs, decision binding, auditability, and tests against the
real runtime path. D-sim does not touch it and makes no protection claim about
it.
