# AD-M06 Lab Factory — Design Spec

**Status:** Draft for review
**Date:** 2026-10-08
**Phase:** AD Mastery initiative, AD-M06 (first of the deferred execution/validation layers)

## Purpose

Convert the completed AD library layer (M01–M12) from "model complete" into
"model demonstrably correct" by validating the `adenv` environment model, the
M04 ESC/ACL predicates, and the `adchain` planner **together, end-to-end,
against controlled AD environments**.

The validation chain this spec delivers is exactly:

```
Fixture → adenv.Environment → EnvResolver → adchain.Plan → Expected result
```

NOT the weaker `Fixture → manually-prepared conditions → Plan`. The point is
to exercise the environment-reading logic (the first real
`adchain.ConditionResolver`), not to hand the planner pre-chewed answers.

## Scope

### In scope (M06 v1)

- A new `orchestrator/internal/adlab` package (pure Go, no DB, no containers,
  no live AD).
- Deterministic, hand-authored synthetic AD environments (`adenv.Environment`
  values built in Go).
- The **first environment-backed `adchain.ConditionResolver`** (`EnvResolver`),
  which answers the condition keys the M04 catalogs actually emit by reading an
  `adenv.Environment` relative to a named attacker foothold.
- A validation harness (`Validate`) that runs the planner over a lab and
  asserts expected reachability and path.
- A starter set of built-in labs covering both resolver key families plus a
  negative case.
- A `Provider` seam so a future live-AD backend plugs in without reworking the
  validation layer.

### Explicitly out of scope (deferred to later phases)

- Any live/provisioned AD (Windows DCs, Samba, containers, VMs, cloud). The
  `Provider` seam exists for it; no implementation of it ships here.
- Executable AD content (real commands/steps for the primitives). That is the
  next deferred phase after M06.
- Evolving-foothold resolution (the resolver tracking the attacker's growing
  set of controlled principals mid-chain). `adchain`'s resolver contract is a
  static `Resolve(key) bool`; M06 resolves relative to a **fixed starting
  identity plus its transitive group memberships**. Richer evolving resolution
  would be a change to `adchain` itself, not M06.
- Wiring any of this into the live API/orchestrator/UI.

## Architecture

New package `orchestrator/internal/adlab`, depending one-way on `adenv`,
`adprimitive`, and `adchain` only (consistent with every `ad*` package in this
initiative; nothing existing imports it back).

### The `Lab` and the `Provider` seam

```go
// A Lab is one reproducible, controlled AD environment plus the attacker's
// starting foothold in it.
type Lab struct {
    Name        string
    Description string
    Env         adenv.Environment
    Attacker    string // principal name present in Env.Identity — the starting foothold
}

// Provider yields labs. The synthetic implementation returns deterministic
// built-in labs and always a nil error; a future live-AD backend provisions
// real environments, collects them into an adenv.Environment (via the existing
// SharpHound → attackpath → adenv.FromGraph pipeline), and returns them behind
// this same interface — hence the error return, which only the live backend
// will ever use.
type Provider interface {
    Labs() ([]Lab, error)
}
```

The seam's payoff: a future live provider needs no new data path. It provisions
real AD, runs the already-built `SharpHound → attackpath → adenv.FromGraph`
collection pipeline, and returns an `adenv.Environment` through the identical
interface. The validation layer above never knows the difference.

For v1, only `SyntheticProvider` exists (hard-coded deterministic labs).

## The `EnvResolver`

Implements `adchain.ConditionResolver`.

```go
type EnvResolver struct {
    env        adenv.Environment
    controlled map[string]bool // attacker + transitive group memberships
}

func NewEnvResolver(env adenv.Environment, attacker string) *EnvResolver
func (r *EnvResolver) Resolve(key string) bool
```

### Construction: the transitive principal set

`NewEnvResolver` computes `controlled` — the set of principals the attacker
"is": the attacker name, plus every group it belongs to, walked transitively
through `env.Identity.Groups` (groups may nest). The walk uses a visited-set so
a membership cycle (A∈B, B∈A) terminates.

If the attacker name is absent from `env.Identity`, `controlled` degrades to
just the bare attacker name — conditions then resolve `false` rather than
erroring.

### `Resolve(key)`: the two key families

The M04 catalogs emit exactly two condition-key families:

**1. `acl_right_held:<Right>`** (ForceChangePassword / GenericAll / GenericWrite
/ AddMember / AddSelf / AllExtendedRights — i.e. every ACL-abuse, RBCD, and
DCSync condition).

True iff some entry in `env.Authorization.ACLs` has `Principal ∈ controlled`
and `string(Right) == <Right>` (the suffix after the colon).

**2. ADCS template conditions.**

- `esc1_vulnerable_template` / `esc2_vulnerable_template` /
  `esc3_vulnerable_template` — true iff some template in `env.PKI.Templates`
  satisfies the corresponding already-built `adenv.IsESC1Vulnerable` /
  `IsESC2Vulnerable` / `IsESC3Vulnerable` predicate **AND** the attacker can
  enroll in it (`controlled ∩ template.EnrollmentRights ≠ ∅`).
- `esc4_template_write_access` — true iff `adenv.HasTemplateWriteAccess(t, p)`
  is true for some template `t` and some `p ∈ controlled`.

**The enrollment gate (ESC1-3):** the `adenv.IsESCnVulnerable` predicates
themselves check only template configuration, not who can enroll. The resolver
additionally requires the attacker to be able to enroll, because in a controlled
lab with a *specific* foothold, "can **this attacker** reach this ESC" is the
honest question — and it keeps the attacker identity meaningful for ADCS rather
than ignored. Cost: a fixture must grant the attacker's group enrollment rights
on the template, or ESC1-3 reads `false`.

**Unknown or malformed key** (unknown prefix, or `acl_right_held:` with an empty
suffix) → `false`. This is fail-closed, matching both the catalog's own
convention and `MapResolver`'s "no entry = false."

## The validation harness

```go
type Expectation struct {
    Target        adprimitive.Capability
    WantReachable bool
    WantPathIDs   []string // expected ordered primitive IDs; checked only when WantReachable is true
}

type Case struct {
    Lab          Lab
    Catalog      []adprimitive.Primitive  // primitives in scope for this scenario
    StartHeld    []adprimitive.Capability // attacker's starting capabilities (e.g. CapDomainUser)
    Expectations []Expectation
}

type Failure struct {
    Target adprimitive.Capability
    Reason string // human-readable mismatch description
}

// Validate builds an EnvResolver from c.Lab, runs adchain.Plan for each
// expectation, and returns one Failure per mismatch (empty slice = all passed).
func Validate(c Case) []Failure
```

For each `Expectation`: build `NewEnvResolver(c.Lab.Env, c.Lab.Attacker)`, call
`adchain.Plan(c.Catalog, c.StartHeld, exp.Target, resolver)`, and compare the
`(path, ok)` result to `exp.WantReachable` / `exp.WantPathIDs`.

### Fixture strategy

Each `Case` carries its **own scoped `Catalog`** — the subset of primitives
relevant to the scenario it validates — so the expected path is exact.
(`adchain.Plan` returns a capability-closure-with-order, not a minimal path; a
scoped catalog keeps `WantPathIDs` clean and the assertion precise.) At least
one case uses the full `adbench.All()` catalog as an integration check.

Each lab's `adenv.Environment` is hand-authored in Go — no files, no YAML — so
fixtures are reviewable in one place and cannot drift from an external artifact.

### Built-in labs for v1 (YAGNI — enough to exercise both key families + a negative)

- **`acl-genericall-takeover`** — the attacker's group holds `GenericAll` over a
  target account; `CapControlledAccount` is reachable via the
  `acl-genericall-takeover` primitive.
- **`adcs-esc1-enrollable`** — a published ESC1-vulnerable template the
  attacker's group can enroll in; the ESC1 path is reachable. A sibling case
  uses the *same* lab minus the enrollment right and asserts the target is
  **unreachable** — proving the enrollment gate works in both directions.
- **`no-foothold-safe`** — the attacker holds no abusable rights and no
  vulnerable template exists; the target is **unreachable**, proving the
  fail-closed path and the negative case.

## Testing

Pure `go test`, no containers or DB. Each built-in lab plus its expectations is
a table-driven test calling `Validate`. TDD throughout: write the failing
expectation first, then the resolver logic to satisfy it.

Dedicated edge-case tests:

- **Group-membership cycle** (A∈B, B∈A) — the transitive closure terminates.
- **Attacker absent from `env.Identity`** — conditions resolve `false`, no panic.
- **Malformed/empty condition key** — `false`.
- **Empty `env.PKI`** — all `escN_*` resolve `false`.

## Error handling

- `EnvResolver` does no I/O; `Resolve` returns a bare `bool` with no error path.
- `Validate` returns `[]Failure` (data), not `error` — a mismatch is a result,
  not a failure to run.
- `Provider.Labs()` returns `([]Lab, error)`; `SyntheticProvider` always returns
  a `nil` error. The error exists for the future live backend.

## Dependencies & boundaries

- `adlab` → `adenv`, `adprimitive`, `adchain` (one-way; nothing imports `adlab`
  back).
- No new third-party dependencies. Go stdlib + the existing `ad*` packages only.
- No change to `adenv`, `adprimitive`, or `adchain` — M06 consumes their
  existing exported surfaces (`IsESC1Vulnerable`/…, `HasTemplateWriteAccess`,
  `Plan`, `ConditionResolver`, `Environment`, the catalogs).

## Success criteria

- `adlab.Validate` runs the full `Fixture → Environment → EnvResolver → Plan →
  Expected` chain and passes for every built-in lab.
- The ESC1 enrollment-gate positive/negative pair both assert correctly.
- Edge cases (cycle, absent attacker, malformed key, empty PKI) are covered and
  pass.
- `go build ./...`, `go vet`, and `gofmt -l` are clean.
- The `Provider` seam is defined such that a future live-AD backend can
  implement it without changes to `EnvResolver` or `Validate`.
