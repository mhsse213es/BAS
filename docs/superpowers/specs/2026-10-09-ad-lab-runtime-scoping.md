# AD Controlled Lab-Runtime — Scoping Document

**Date:** 2026-10-09
**Status:** Scoping (requirements + contracts + boundaries). **Not** a design spec,
**not** an implementation plan, **no** code. Awaiting review before a full DCSync-lab
design spec is written.
**Decision locked (user, 2026-10-09):** separate lab-runtime; `adlab` remains the
environment model + `Provider` seam; **DCSync lab first**, ADCS lab second;
**D-runtime stays deferred** until a real target + trustworthy provenance +
isolation + evidence path exist.

## 1. Purpose

Define the dependency that unblocks E2 (executable-content authoring) and,
eventually, D-runtime: a **controlled lab-runtime** that can stand up a real,
isolated AD environment, prove it is isolated, run a validated primitive against
it, observe the postcondition, and tear it down — binding verifiable provenance to
the specific run. This document fixes the *contracts and boundaries*; the DCSync
lab's design and plan come after review.

## 2. Responsibility split (locked architecture — fork ii)

| Component | Owns | Does NOT own |
|---|---|---|
| `adlab` (existing, pure Go) | environment **model** (`adenv.Environment`), synthetic fixtures, expected conditions, planning/validation cases (`Validate`), the `Provider` seam | provisioning, real targets, credentials, isolation, lifecycle, execution evidence |
| **lab-runtime (new)** | provisioning, target handle(s), isolation verification, credential/secret handling, lifecycle (reset/teardown), execution-evidence capture, minting run-bound provenance | planning/reachability semantics; the gate decision itself |
| `adgate` (existing) | decides whether *this action* is permitted in *this verified environment* (fail-closed) | provisioning; evidence; dispatch |
| orchestrator (later, D-runtime) | enforces the gate decision at the real dispatch boundary | — (unchanged in this scope) |

Rationale: `Lab` today is a *model*, not a running machine. Mixing agents,
credentials, teardown, and evidence into it would entangle deterministic planning
with infrastructure lifecycle. Keeping them separate preserves the pure-Go model's
testability and lets a live backend appear without changing planning semantics.

**Narrowness constraint:** build only what the *first DCSync lab* needs. No generic
lab-management platform, no broad provisioning framework, no multi-backend
abstraction before the first lab exists.

## 3. Lab-runtime minimum lifecycle contract

The runtime exposes a **narrow** lifecycle (contract shape, not an implementation):

1. **Provision** → bring up the controlled environment for a named lab; return an
   opaque target handle. Idempotent per lab identity where feasible.
2. **Verify isolation** → independently confirm the target cannot reach production
   (network/tenancy). Returns a definite verified / not-verified result. **A
   not-verified or uncertain result MUST block everything downstream.**
3. **Expose target identity** → the real principal(s)/host(s) the run will use,
   mapped to the `adlab` model's `Attacker`/`Env` so planning and execution refer
   to the same entities.
4. **Collect evidence** → capture observable proof that a primitive achieved (or did
   not achieve) its postcondition — distinct from planner reachability.
5. **Reset / teardown** → return the environment to a known baseline between runs and
   destroy it after; teardown must run even on failure paths.

Each stage has an explicit **fail-closed** outcome (see §6). The contract is
consumed by the validation harness and, later, by D-runtime; it is **not** wired
into `dispatchRun` in this scope.

## 4. Provenance: established and bound, never copied

The crux. Today every synthetic lab carries `Attestation = adgate.SyntheticProvenance()`
— a stamp on a *model*. A real target must NOT simply reuse that stamp.

Requirements for real-target provenance:

- **Verification-derived:** provenance is minted **only after** Provision +
  Verify-isolation + Expose-identity all succeed. It encodes *what was verified*
  (this target, isolated, identity confirmed), not a constant.
- **Run-bound:** bound to the specific run (correlation id) and the specific target
  handle — not reusable across runs or targets.
- **Unforgeable at origin:** minted solely by the lab-runtime (mirroring `adgate`'s
  existing unexported-origin pattern), so no caller can fabricate "verified lab."
- **Distinct gate class:** `adgate` currently treats `SyntheticProvenance()` → allow
  and `LiveADProvenance()` → deny. A DC-backed controlled lab is *real yet
  controlled* — it fits neither. This scope **requires an `adgate` extension**: a
  provenance origin for "verified controlled lab," which the gate allows **only**
  when the verification evidence is present, and which fails closed to deny
  otherwise. (Design of that origin is part of the DCSync-lab design spec, not here.)

## 5. Authorization, secrets, failure behavior

- **Authorization binding:** the operator authorization that reaches `adgate`
  (`Authorization{Authorized, DestructiveApproved}`) must be bound to *this* run +
  target (who approved *this* execution against *this* lab), not an ambient flag.
- **Secret handling:** lab credentials/handles are runtime-only, never logged, never
  embedded in the model, never committed. (Consistent with existing
  deployment-secret handling.)
- **Failure behavior (fail-closed, non-negotiable):** any of — provision failed,
  isolation unverified/uncertain, identity unconfirmed, provenance unminted,
  authorization absent — **prevents execution**. Uncertainty is treated as denial.

## 6. Smallest DCSync lab — infrastructure & validation requirements

Infrastructure (requirements only — **no attack commands authored or run here**):

- **One Domain Controller** in an isolated network/tenancy.
- **A controlled attacker identity** granted the specific rights the `dcsync`
  primitive's prerequisites describe (the DS-Replication extended rights, modeled in
  `adlab` as `acl_right_held:AllExtendedRights` on the domain object).
- **Isolation** from any production AD (verifiable per §3.2).
- **Reset** to a clean directory state between runs; **teardown** after.

Validation requirements (what "validated" means for DCSync):

- `adlab.Validate` already proves **planning reachability** (the planner finds the
  `dcsync` path given the modeled rights). The *new* thing the lab-runtime proves is
  **execution evidence**: the primitive, when run, actually produced its
  postcondition (`CapDomainCredentialMaterial` — replication occurred) on the real
  DC, observed via evidence capture (§3.4) — and that a *negative* control (identity
  lacking the rights) does **not** produce it.
- DCSync is **already reusable** (stock ART atomics); this lab is therefore
  **validation of execution+evidence**, not new content authoring. It is the vehicle
  that proves the lab-runtime contract end to end.

## 7. Smallest adgate-enforcement integration seam (identify only; do not wire)

- Identify the **single** point where a future caller would ask `adgate.Decide`
  immediately before dispatching a primitive to the lab target, consuming the §4
  run-bound provenance + §5 authorization.
- This scope **only names** that seam and the data it needs; it does **not** modify
  `dispatchRun`, run modes, or execution behavior (D-runtime readiness criteria,
  still deferred).

## 8. Explicit exclusions (this scope)

- No code. No provisioning framework. No generic/multi-backend lab platform.
- No changes to `adlab` planning semantics, `dispatchRun`, or run modes.
- No ADCS lab (second milestone, reuses this contract).
- **No E2 per-gap contracts** — prereqs/postconditions/telemetry/risk/acceptance for
  the 8 missing primitives are a *separate* track, not mixed into lab provisioning.
- No attack payloads or executable attack content.

## 9. Open questions for review

1. **Provisioning substrate for the DCSync DC** — out of scope to *decide* here, but
   the design spec will need a direction (e.g., disposable VM vs. container-based DC
   vs. an existing isolated lab network). Any preference to record now?
2. **Evidence mechanism** — reuse the orchestrator's existing telemetry/observation
   path, or a lab-local observation captured by the runtime? (Affects the evidence
   contract's shape.)
3. **Where the lab-runtime lives** — a new `internal/adlabrt` package (Go, mirroring
   the `ad*` family) vs. an out-of-process provisioner the runtime drives. Lean:
   a thin Go package owning the contract, delegating actual provisioning to whatever
   substrate (1) picks.

## 10. Next steps (gated on review of this document)

1. On approval, write the **DCSync lab-runtime design spec** (the §3 contract as a
   concrete narrow Go interface, the §4 provenance origin + `adgate` extension, the
   §6 lab + evidence model) → self-review → your review → implementation plan.
2. **In parallel and separate:** safe E2 per-gap contracts (no payloads).
3. D-runtime remains deferred until this contract is real and testable for bypasses.
