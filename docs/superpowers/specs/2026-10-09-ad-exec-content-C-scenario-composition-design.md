# AD Executable-Content Sub-Project C — Scenario Composition — Design Spec

**Status:** Draft for review
**Date:** 2026-10-09
**Parent initiative:** AD Mastery — "Executable AD content", sub-project C of a five-part decomposition (A done, B done).

## Where this sits

A provides the coverage/mapping layer (`adcoverage`); B provides the gate
decision library (`adgate`); M06 provides the synthetic lab model (`adlab`). C
composes **existing, already-mapped** AD capabilities into primitive-linked
chains targeting the synthetic M06 environment. C authors no new payloads,
executes nothing, and never authorizes execution. D wires enforcement; E
authors the 11 coverage gaps. Both are out of C's change set.

## Purpose

Define the smallest composition contract that turns an ordered chain of AD
primitives plus A's coverage mapping into a **traceable, metadata-only**
composed chain: each composed step linked to its source primitive, its mapped
existing capability, its prerequisites/postconditions, its provenance, and its
existing (primitive-level) classification. Composition is metadata; it is never
permission to execute.

## Scope

### In scope

- A new `orchestrator/internal/adcompose` package (pure Go, no DB, no network,
  no execution).
- `Compose(chain, held, cov, lab) ComposedChain` — links each primitive in a
  chain to its mapped capability and surfaces composition problems
  deterministically.
- Deterministic handling of: missing mapping, unmet prerequisite, unresolved
  condition, ambiguous (multi-)mapping.

### Out of scope / non-negotiable boundaries

- No new raw commands, payloads, or exploit implementations (that is E).
- No changes to agent dispatch, orchestrator run paths, or execution behavior.
- No changes to `adgate` policy or authorization semantics; `adcompose` does not
  import `adgate` and never calls `Decide`.
- **Composition must never imply permission to execute.** `adgate` remains the
  required decision point; D handles runtime enforcement. `ComposedChain` has no
  authorized/runnable field and never sets `scenario.Scenario.Executable`.
- Do not implement the 11 coverage gaps (E).
- Do not create a new abstraction where an existing type suffices (see Design
  decisions for why `adcompose` is warranted and `scenario.Scenario` is not
  reused).

## Verified repository facts

- `adprimitive.Primitive{ ID, Name, TechniqueID, Prerequisites, Postconditions
  []Capability, RiskClass }`; `Prerequisites{ DomainJoined, Privileges,
  Capabilities []Capability, Conditions map[string]bool }`;
  `RiskClass ∈ non_destructive|potentially_destructive|destructive`.
- `adcoverage.StepRef{ Scenario, StepName, Framework, TechniqueID }`,
  `PrimitiveCoverage{ Primitive, Steps []StepRef }`, `Report{ Covered, Gaps }`.
- `adlab.Lab{ Name, Description, Env, Attacker, Attestation adgate.Provenance }`;
  `adlab.NewEnvResolver(env, attacker)` resolves condition keys.
- Planner prerequisite semantics (`adchain.satisfied`, unexported): every
  required `Capability` present in `held` by exact Kind+Target equality; every
  `Conditions` entry satisfies `resolver.Resolve(key) == want`;
  `DomainJoined`/`Privileges` are not evaluated. **C mirrors this exactly.**
- Coverage reality: `T1558.003` maps to multiple scenario steps, so
  `spn-enumerate` and `kerberoast-tgs-request` are multi-mapped (real ambiguous
  case). `dcsync`, `adcs-esc1`–`esc4`, and the 6 ACL/RBCD primitives are gaps.

## Architecture

New package `orchestrator/internal/adcompose`, one-way deps on `adprimitive`,
`adcoverage`, `adlab`. It imports **neither `adgate` nor `scenario`** — v1 uses
the primitive-level `adprimitive.RiskClass` as the step classification, so no
`scenario` dependency and no authorization concept enter the package. Nothing
imports `adcompose` back.

### Types and API

```go
type ProblemKind string

const (
    ProblemUnmapped            ProblemKind = "unmapped"             // primitive has no mapped capability (a gap)
    ProblemUnmetPrerequisite   ProblemKind = "unmet_prerequisite"  // a required capability is not held at this point in the chain
    ProblemUnresolvedCondition ProblemKind = "unresolved_condition" // a Prerequisites.Conditions key does not resolve to its required value in the lab
    ProblemAmbiguousMapping    ProblemKind = "ambiguous_mapping"   // primitive maps to >1 capability; the first (stable-sorted) is chosen and this is surfaced
)

type Problem struct {
    Kind   ProblemKind
    Detail string // e.g. the capability kind, the condition key, or the count of candidate mappings
}

type ComposedStep struct {
    Primitive  adprimitive.Primitive // source primitive (traceability anchor)
    Capability adcoverage.StepRef    // chosen mapped capability; zero value when Unmapped
    RiskClass  adprimitive.RiskClass // the primitive's existing classification (metadata, NOT permission)
    Problems   []Problem             // empty => this step composed cleanly
}

type ComposedChain struct {
    Lab        adlab.Lab      // target synthetic lab; its Attestation is carried for D, never acted on here
    Steps      []ComposedStep // ordered, following the input chain
    Composable bool           // true iff no step has any Problem
    // By construction there is no Authorized/Runnable/Executable field.
}

func Compose(chain []adprimitive.Primitive, held []adprimitive.Capability, cov adcoverage.Report, lab adlab.Lab) ComposedChain
```

### Algorithm (deterministic, total)

1. Build `resolver := adlab.NewEnvResolver(lab.Env, lab.Attacker)` and a lookup
   `map[primitiveID][]StepRef` from `cov.Covered` (gaps contribute no entry).
2. Copy `held` into a running capability set.
3. For each primitive `p` in `chain`, in order, build a `ComposedStep{Primitive:
   p, RiskClass: p.RiskClass}`:
   - **Mapping:** `refs := lookup[p.ID]`. If `len(refs)==0` →
     `Problem{Unmapped}`, `Capability` left zero. Else sort `refs` by
     `(Scenario, StepName)`, set `Capability = refs[0]`, and if `len(refs)>1`
     add `Problem{AmbiguousMapping, Detail: count}`.
   - **Prerequisite capabilities:** for each `want` in
     `p.Prerequisites.Capabilities` not in the running held set →
     `Problem{UnmetPrerequisite, Detail: want}`.
   - **Conditions:** for each `key,want` in `p.Prerequisites.Conditions` where
     `resolver.Resolve(key) != want` → `Problem{UnresolvedCondition, Detail: key}`.
   - Append `p.Postconditions` to the running held set (the chain accumulates
     capabilities for later steps, mirroring the planner).
4. `Composable = true` iff no step has any Problem. Return the `ComposedChain`.

`Compose` is pure and total: no error return, no panic; every input yields a
`ComposedChain`.

## Design decisions

- **New package, not `scenario.Scenario`.** A composed chain must hold the
  primitive→capability→prereq/postcondition→provenance links; `scenario.Scenario`
  cannot, and its `Executable`/`LivePolicy` fields would entangle C with the
  execution boundary C must stay clear of. A separate metadata-only type keeps
  the authorization separation structural.
- **v1 classification = primitive `RiskClass`.** `ResolveExecutionClass` needs
  `(techniqueID, actionKey)` and `adcoverage.StepRef` carries no `actionKey`, so
  step-level scenario classification is not available without extra plumbing.
  v1 attaches the primitive's own `RiskClass` (already present, same three
  values). Reconciling primitive classification against a mapped step's
  resolved `ExecutionClass` (the fail-safe "take the more restrictive" rule) is
  **deferred** until `StepRef` carries classification — tracked below.
- **Ambiguous mapping is surfaced, not hidden.** When a primitive maps to
  several capabilities, C picks the first by a stable `(Scenario, StepName)`
  sort (deterministic) and records `ProblemAmbiguousMapping`, so the choice is
  visible rather than silent.
- **Problems do not drop steps.** Every primitive in the input chain yields
  exactly one `ComposedStep`; problems annotate, they never remove.

## Error handling

`Compose` has no error path. Gaps, unmet prerequisites, unresolved conditions,
and ambiguous mappings are reported as `Problem` values with `Composable=false`,
not as Go errors or panics.

## Testing

Pure `go test`, synthetic fixtures (`adlab` labs, `adprimitive` catalogs, a
hand-built `adcoverage.Report`). **No test executes an attack action.**

- **Fully composable:** a chain whose primitives are all mapped and whose
  prerequisites/conditions hold in the lab → every `ComposedStep` links
  primitive + capability + `RiskClass`, no problems, `Composable=true`.
- **Unmapped:** a gap primitive in the chain → `Problem{Unmapped}`,
  `Composable=false`, `Capability` zero.
- **Unmet prerequisite:** a primitive whose required capability is not yet held
  → `Problem{UnmetPrerequisite}`.
- **Unresolved condition:** a primitive with a `Conditions` key the lab resolver
  returns the wrong value for → `Problem{UnresolvedCondition}`.
- **Ambiguous mapping:** a primitive mapped to two `StepRef`s → first chosen by
  stable sort, `Problem{AmbiguousMapping}`, deterministic across runs.
- **Traceability:** every `ComposedStep` has a non-empty `Primitive.ID`, and a
  mapped step has a non-empty `Capability.Scenario`/`StepName`.
- **Authorization separation:** composing a fully-composable chain yields no
  authorization; the test shows that obtaining permission still requires a
  separate `adgate.Decide` call (the test imports `adgate`; `adcompose` does
  not), and `ComposedChain` exposes no runnable/authorized field.

## Acceptance criteria (release-blocking)

1. **Traceability:** every composed step verifiably links to its source
   primitive and its mapped capability, with provenance (scenario + step).
2. **Authorization separation:** composing cannot mark a chain authorized or
   runnable; `RiskClass` stays metadata; `adgate.Decide` remains the only
   execution decision point; `adcompose` imports neither `adgate` nor touches
   `scenario.Scenario.Executable`.
3. `go build ./...`, `go vet`, `gofmt -l` clean; no edits to any existing
   package.

## Deferred / tracked follow-ups (not C)

- Step-level `ExecutionClass` reconciliation (primitive `RiskClass` vs mapped
  step's resolved class, fail-safe to the more restrictive) once `StepRef`
  carries classification.
- D: wire `adgate.Decide` immediately before dispatch over a `ComposedChain`,
  with no bypass path.
- E: author the 11 coverage-gap primitives, each with its own go/no-go.
