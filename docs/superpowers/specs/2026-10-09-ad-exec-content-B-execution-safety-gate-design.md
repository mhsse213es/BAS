# AD Executable-Content Sub-Project B — Execution Safety Gate — Design Spec

**Status:** Draft for review
**Date:** 2026-10-09
**Parent initiative:** AD Mastery — "Executable AD content" (deferred execution layer), sub-project B of a five-part decomposition.

## Where this sits

"Executable AD content" is decomposed (user-approved 2026-10-08) into five
sub-projects, in dependency order: **A** capability inventory + primitive→capability
mapping (DONE) → **B** execution safety contract/gate (this spec) → **C** scenario
composition (targets the M06 synthetic lab) → **D** controlled execution + validation
(M06 lab only, never production/customer AD; gated by B) → **E** raw authoring for
genuine coverage gaps (`dcsync`, `adcs-esc1`–`esc4`, the 6 ACL/RBCD primitives; each
gap gets its own go/no-go).

B defines and tests the decision "**may this specific action run in this specific
environment right now?**" It does not execute anything and is not wired into the
orchestrator. A gate that is not wired into dispatch is **not yet an enforcement
control**: turning B's decision into enforcement is sub-project D's job and is tracked
below as a required follow-up.

## Purpose

Provide a pure-Go policy library that answers, deterministically and fail-closed,
whether an action may execute against a given environment — **distinct from
classification**. Classification (`scenario.ExecutionClass`, `ResolveExecutionClass`,
`AttachExecutionClassifications`, mirrored by `adprimitive.RiskClass`) answers *what an
action is*; the gate answers *whether this action may run in this environment now*.
Classification alone must never be read as permission to run.

## Scope

### In scope

- A new `orchestrator/internal/adgate` package (pure Go, deterministic, no network, DB,
  orchestrator, agent, or execution side effects).
- A `Provenance` value that is unforgeable by struct literal (zero value = Unknown) and
  minted only by environment producers at origin.
- A `Decide(Request) Decision` function returning Allow/Deny with a stable,
  machine-readable reason.
- Origin stamping: `adlab.Lab` carries an `adgate.Provenance`; `SyntheticProvider`
  stamps it synthetic. (Producer-side library code, not runtime wiring.)

### Out of scope

- Any wiring into the orchestrator run/dispatch path, agent, or real execution — that is
  sub-project D, where enforcement is verified end to end.
- Any new risk tiers or changes to `scenario.ExecutionClass` / `ResolveExecutionClass` /
  `AttachExecutionClassifications` / `adprimitive.RiskClass`.
- Any live-AD authorization policy. A live-AD environment denies by default in B; a
  separate explicit live-authorization policy is a future sub-project, not B.
- Cryptographic/signed attestations (see Threat model — unnecessary in-process).

## Trust model — what makes "synthetic" trustworthy

A descriptor that merely *claims* to be synthetic is not proof; a bare caller-set bool
would make the gate check only a label. Instead:

- `Provenance` has a single **unexported** field. A plain `adgate.Provenance{}` literal is
  therefore **Unknown**, and Unknown denies. A caller cannot assert "synthetic" by
  filling a struct.
- The only way to obtain a synthetic `Provenance` is `adgate.SyntheticProvenance()`,
  which environment **producers call at the environment's point of origin**. In v1 the
  sole producer is `adlab.SyntheticProvider`, which stamps each lab it builds. Consumers
  (D) read the stamped provenance and pass it to the gate; they never infer or mint it.
- The gate **consumes** provenance; it never tries to infer syntheticness from the
  environment's data, because a faithful synthetic model is deliberately
  indistinguishable from real AD (that is M06's point).
- A future live-AD producer stamps `LiveADProvenance()`, never synthetic, so real
  execution denies by default in B.

**Threat model (stated plainly):** in-process Go cannot defend against deliberately
malicious in-process code that calls `SyntheticProvenance()` on real-environment data;
no in-process mechanism short of signing can, and signing a decision that never leaves
the process is YAGNI. B's goal is to make **accidental misuse structurally impossible**
— you cannot get an Allow without a synthetic stamp minted at origin, and every
unverified, missing, or ambiguous case fails closed — not to defend against a hostile
in-process caller.

## Architecture

New package `orchestrator/internal/adgate`, depending one-way on `scenario` (for
`ExecutionClass`). It imports no lab code. `adlab` imports `adgate` to stamp its labs
(`adlab → adgate`; no cycle, since `adgate` does not import `adlab`).

Dependency spine: `scenario`/`adprimitive` classification → `adgate` decision → (D)
dispatch integration + enforcement → controlled execution + validation.

### Types and API

```go
// Provenance records where an environment came from. Unforgeable by struct
// literal: the zero value is Unknown, which denies.
type Provenance struct { kind provenanceKind } // kind unexported

type provenanceKind int // unexported; zero value = unknown

// Minted only by environment producers at the environment's origin.
func SyntheticProvenance() Provenance
func LiveADProvenance() Provenance

// Authorization is the operator consent / policy context the caller supplies.
// Operator consent is legitimately a caller assertion; it is the environment
// provenance (above) that carries unforgeable evidence.
type Authorization struct {
    Authorized          bool // operator consented to this controlled run
    DestructiveApproved bool // extra consent required for a destructive-class action
}

type Request struct {
    Class scenario.ExecutionClass // consumed, never re-derived
    Env   Provenance
    Auth  Authorization
}

type Reason string

const (
    ReasonAllowedSyntheticAuthorized Reason = "allowed_synthetic_authorized"
    ReasonDeniedNotSynthetic         Reason = "denied_environment_not_synthetic"
    ReasonDeniedUnknownClass         Reason = "denied_unknown_classification"
    ReasonDeniedMissingAuth          Reason = "denied_missing_authorization"
    ReasonDeniedDestructiveNotApproved Reason = "denied_destructive_not_approved"
)

type Decision struct {
    Allowed bool
    Reason  Reason
}

func Decide(req Request) Decision
```

### Decision rules

Fail-closed; evaluated in order; the first failing rule wins; deterministic:

1. `Env` is not synthetic (Unknown zero value, or LiveAD) → deny `ReasonDeniedNotSynthetic`.
2. `Class` is not one of the three known tiers (`non_destructive`,
   `potentially_destructive`, `destructive`) — including empty/unclassified → deny
   `ReasonDeniedUnknownClass`.
3. `!Auth.Authorized` → deny `ReasonDeniedMissingAuth`.
4. `Class == ClassDestructive && !Auth.DestructiveApproved` → deny
   `ReasonDeniedDestructiveNotApproved`.
5. otherwise → allow `ReasonAllowedSyntheticAuthorized`.

Rules 2 and 4 consume the existing `scenario.ExecutionClass` constants; no tiers are
added and no classification is recomputed.

### Origin stamping

`adlab.Lab` gains a field `Attestation adgate.Provenance`. The four
`SyntheticProvider` labs are each constructed with
`Attestation: adgate.SyntheticProvenance()`. Nothing else in `adlab` changes; the field
is additive and the `Validate` harness is unaffected.

## Error handling

`Decide` is pure and total: every `Request` yields a `Decision`; there is no error
return and no panic path. Unrecognized or zero-valued inputs resolve to a deny with the
matching reason. `SyntheticProvenance`/`LiveADProvenance` are infallible constructors.

## Testing

Pure `go test`, no DB, no containers, deterministic.

- **positive:** synthetic provenance + known class + `Authorized` → allow
  `ReasonAllowedSyntheticAuthorized`.
- **live environment:** `LiveADProvenance()` → deny `ReasonDeniedNotSynthetic`.
- **unverified:** zero-value `Provenance{}` → deny `ReasonDeniedNotSynthetic`.
- **unknown class:** empty `ExecutionClass`, and a bogus value → deny
  `ReasonDeniedUnknownClass`.
- **missing authorization:** `Authorized == false` (synthetic, known class) → deny
  `ReasonDeniedMissingAuth`.
- **destructive without approval:** `ClassDestructive`, `Authorized`, `!DestructiveApproved`
  → deny `ReasonDeniedDestructiveNotApproved`; and with `DestructiveApproved` → allow.
- **rule order:** a request failing multiple rules returns the first (e.g. live + unknown
  class returns `not_synthetic`).
- **fail-closed by construction:** the zero-value `Provenance{}` is Unknown (not synthetic).
- **origin stamping end-to-end:** each `SyntheticProvider` lab's `Attestation` flows
  through `Decide` (known class + authorized) to allow.

## Required follow-up (tracked, not part of B)

B is a decision library, **not an enforcement control**. Sub-project D must:

- call `Decide` immediately before dispatch, so classification is never treated as
  permission; and
- ensure there is no path to construct and run an action that bypasses the gate.

Until D lands that integration and verifies it end to end, B provides the contract only.

## Success criteria

- `Decide` implements the fail-closed rule order exactly, deterministically, with stable
  reasons.
- A synthetic `Provenance` is obtainable only via `SyntheticProvenance()`; the zero value
  denies.
- `adlab` synthetic labs are stamped and flow through `Decide` to allow.
- `go build ./...`, `go vet`, `gofmt -l` clean; no change to classification code or tiers.
