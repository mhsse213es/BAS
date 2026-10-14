# P5 — AD Lab Substrate (Real Hyper-V Adapter) Design Spec

**Date:** 2026-10-10
**Status:** Design spec for review. The **lab-independent** parts (adapter contract,
lab-topology catalog, isolation/evidence requirements, resource profiles, runbook,
readiness criteria) are specified for implementation now. The **real adapter
implementation and its end-to-end validation against a live DC are lab-gated** and
remain deferred until dedicated hardware + operator authorization exist.
**Predecessors:** [`2026-10-09-ad-lab-runtime-scoping.md`](2026-10-09-ad-lab-runtime-scoping.md)
(locked architecture; open question #1 = substrate), and
[`2026-10-09-dcsync-lab-runtime-design.md`](2026-10-09-dcsync-lab-runtime-design.md)
(Phase A fake `adlabrt`, now implemented). This spec is that doc's **Phase B**.

## 1. Decisions carried in (locked by user, 2026-10-10)

- **Substrate:** local **Hyper-V on dedicated hardware** (not the dev host). Initial
  target: one **self-contained Windows Server Domain Controller VM**.
- **Interface stays provider-neutral:** cloud (or another hypervisor) can be added
  later as a second `Substrate` implementation **without redesigning `adlabrt`**.
- **Topology grows on demand:** DC-only first; add a **domain-joined Windows client**
  when an agent-based scenario needs it; add **AD CS** when validating certificate
  (ESC) scenarios.
- **No cloud spending** for now. **Do not assume the dev host can run the lab** — the
  spec documents minimum resource requirements and isolation checks so an operator
  can stand it up on separate hardware.
- Unchanged from predecessors: `adlabrt` owns provisioning/isolation/provenance/
  evidence/teardown; `adgate` owns the decision; **`dispatchRun` is not touched**;
  D-runtime (real-execution enforcement at the dispatch boundary) stays deferred.

## 2. What already exists (do not rebuild)

`adlabrt` (Phase A, implemented + tested) already provides the full lifecycle against
a **fake** `Substrate`:

```
type Substrate interface {
    Provision(ctx, LabSpec) (Target, error)
    VerifyIsolation(ctx, Target) (IsolationResult, error)
    Execute(ctx, Target, ValidationCase) (Observation, error)
    Teardown(ctx, Target) error
}
```

`Runtime.Validate()` already: provisions → verifies isolation (fail-closed) → mints
run-bound `adgate.VerifiedControlledLabProvenance(runID, targetID)` **only after**
isolation is verified → `adgate.Decide` (verified-lab env **AND** authorization) →
executes → interprets → **guarantees teardown on success/error/panic** on a
cancellation-detached, time-bounded context. Terminal states: `validated`,
`provision_failed`, `isolation_unverified`, `gate_denied`, `execution_errored`,
`evidence_inconclusive`, `not_validated`.

**Consequence:** P5 adds a **second `Substrate` implementation** (real, Hyper-V-backed)
plus the operator-facing env/runbook. It does **not** change the `Substrate` interface,
`Runtime`, `adgate`, or any lifecycle semantics. If a genuine gap forces an interface
change, that is a flagged amendment to this spec, not a silent edit.

## 3. Architecture

```
operator runbook  ──┐
                    ▼
            adlabrt.Runtime.Validate   (unchanged)
                    │  Substrate seam (unchanged, provider-neutral)
         ┌──────────┴───────────┐
         ▼                      ▼
  fakeSubstrate (tests)   hypervSubstrate (NEW, lab-gated)
                                │ drives Hyper-V on dedicated host
                                ▼
                   lab-topology catalog (declarative)
```

- **New package:** `internal/adlabhyperv` (name provisional) implementing
  `adlabrt.Substrate`. Keeps the Hyper-V/PowerShell/WMI specifics out of `adlabrt`,
  preserving its pure-Go testability. A future `internal/adlabcloud` is a sibling.
- **Lab-topology catalog:** `LabSpec.Name` is the only field the interface carries, so
  the adapter resolves `Name` → a **declarative topology definition** it owns (roles,
  base image, network, resource profile, expected attacker identity/rights). This is
  how the narrow interface stays provider-neutral: topology detail lives in the
  adapter's catalog, not in the seam.

## 4. The Hyper-V adapter contract (per `Substrate` method)

Each method's concrete obligations on a real DC. All operations target an **isolated
private virtual switch**; none may touch the host's own network or domain.

- **`Provision(ctx, spec)`** → resolve `spec.Name` to a topology; create/clone the VMs
  from a prepared, offline **base checkpoint** (sysprepped Windows Server already
  promoted to a DC for DC-only labs); attach them **only** to a dedicated **private**
  (host-internal, non-external) virtual switch; start them; wait for the DC to reach a
  ready directory state (bounded by a provision timeout); return `Target{ID}` encoding
  the VM set + a fresh per-run checkpoint name. Idempotent per `spec.Name` where
  feasible (reuse a pooled base, never a dirty one). Any failure → return error →
  `Runtime` yields `provision_failed` and still tears down.
- **`VerifyIsolation(ctx, target)`** → **independently** prove the target cannot reach
  anything outside the lab (see §5). Populate `IsolationResult.Method` with the exact
  checks run and `Detail` with results. Return `Verified:false` on any failure **or
  uncertainty** — the runtime already fails closed and mints no provenance.
- **`Execute(ctx, target, vc)`** → run the already-reusable validation case's primitive
  against the target (via the lab's own controlled attacker identity), observe whether
  the postcondition occurred, return `Observation{PostconditionObserved, Complete,
  Detail}`. `Complete:false` for any inconclusive observation. **No new attack content
  is authored here** — execution uses existing reusable content; this adapter is the
  substrate, not a payload author.
- **`Teardown(ctx, target)`** → revert to the clean base checkpoint and delete the
  per-run VMs/checkpoints; must be **idempotent** and safe to call on a half-provisioned
  target; must leave no running lab VM and no attached run artifacts. Runs on the
  runtime's independent, time-bounded context even under cancellation/panic.

## 5. Isolation verification (the crux — concrete for Hyper-V)

"Verified isolated" for a Hyper-V DC lab means **all** of the following pass; any
failure or inability to determine → `Verified:false` (fail-closed), recorded in
`Method`/`Detail`:

1. **Private switch only:** every lab VM's network adapter is bound to the dedicated
   **private** virtual switch (no External or Internal-with-host-routing switch, no
   additional adapters). Verified by querying the VM/adapter configuration, not by
   assuming the provisioning intent held.
2. **No external route — positive negative-control probe:** from inside the lab (or via
   an isolation probe the adapter controls), confirm the DC **cannot** reach (a) the
   host's management network/gateway, (b) the internet, and (c) any non-lab host. A
   reachable result → not isolated. This is an **active probe**, not a config
   inference.
3. **No production-AD contact:** confirm the lab DC's domain is the lab's own
   throwaway domain and it has **no trust path** to any real/production directory.
4. **Distinct identity space:** lab credentials/SIDs are the lab's own; they are never
   the host's or any production principal.

`VerifyIsolation` records which of these ran and their outcomes in `Method` so the
evidence trail shows *how* isolation was established, not merely that a boolean was
set. (The design intentionally treats an adapter that cannot run probe #2 as
**not verified** — a config-only check is insufficient.)

## 6. Negative control (mandatory, before any "validated" is trusted)

Per the DCSync design spec, a lab run is only trustworthy if the harness can also
**fail** correctly. For each capability under validation the runbook MUST execute, in
the same lab, a **negative control**: the same primitive run by an identity *lacking*
the required rights, which MUST yield `not_validated` (postcondition NOT observed). A
positive `validated` result is only accepted when its paired negative control came back
`not_validated` in the same lab build. This is a runbook + acceptance requirement; it
needs **no** interface change (it is a second `ValidationCase`).

## 7. Lab topologies (grow on demand)

| Milestone | VMs | Adds | Validates |
|---|---|---|---|
| **M1 DC-only** | 1 × Windows Server DC | the baseline | directory-side primitives (DCSync, ACL/RBCD/delegation/trust/GPO exposure + abuse where DC-local) |
| **M2 + client** | + 1 × domain-joined Windows client (runs the Audspect agent) | agent-based execution path | agent-dispatched scenarios against the domain |
| **M3 + AD CS** | + AD CS role (on the DC or a dedicated CA VM) | certificate services | ESC1–4/6/8 certificate scenarios |

Each milestone is a distinct catalog topology keyed by `LabSpec.Name`. M2/M3 are added
only when a scenario actually requires them — no speculative build-out.

## 8. Minimum resource requirements (dedicated host; NOT the dev host)

Indicative minimums for the operator's separate Hyper-V host (final numbers confirmed
during M1 bring-up):

| Topology | vCPU | RAM | Disk (thin/base + per-run) | Notes |
|---|---|---|---|---|
| M1 DC-only | 2 | 4–8 GB | ~40 GB base + per-run checkpoint delta | Windows Server Core preferred to cut footprint |
| M2 + client | +2 | +4 GB | +40 GB | client can be Core or minimal GUI |
| M3 + AD CS | +0–2 | +2–4 GB | +10 GB | CA may co-locate on the DC for M3-minimal |

Host must have Hyper-V enabled, a dedicated **private** virtual switch, and enough
headroom to hold a pooled clean base checkpoint plus one live run. **The current dev
host (~7.8 GB RAM, build/Docker duties) is explicitly out of scope as a lab host.**

## 9. Evidence (lab-local first; telemetry is a P6 boundary)

The adapter returns `Observation`; the runtime already records lab-local `Evidence`
(run/lab/target/case, postcondition observed, complete, timing). P5 keeps evidence
**lab-local**. Shipping that evidence to a SIEM/EDR and asserting *detection* is **P6**
and is explicitly **not** in this spec. The `Evidence` struct's "telemetry adapter is a
future boundary" note is where P6 attaches.

## 10. Readiness criteria — gate before building the real adapter

The real `adlabhyperv` adapter is implemented only when **all** hold (mirrors the
deferred D-runtime criteria):

1. Dedicated Hyper-V host available and operator-authorized for this use.
2. A prepared, offline, sysprepped Windows Server base image/checkpoint (DC-promoted
   for M1), licensed appropriately.
3. The isolation checks of §5 are automatable on that host (esp. the §5.2 active
   negative-control network probe).
4. Secret handling path confirmed: lab credentials are runtime-only, never logged,
   never committed (consistent with existing deployment-secret handling).
5. Operator authorization flow for `adgate.Authorization{Authorized, DestructiveApproved}`
   is bound to *this* run + target (not an ambient flag).

Until all five hold, P5 ships only the lab-independent artifacts (§11) and the adapter
stays a documented, tested-against-fake contract.

## 11. What is implementable NOW (lab-independent)

1. **`adlabhyperv` package skeleton + lab-topology catalog types** (declarative
   topology/resource/identity definitions for M1), implementing `adlabrt.Substrate`
   with the real Hyper-V calls behind a thin **command seam** that is itself faked in
   tests — so the adapter's *resolution/validation/ordering logic* (topology lookup,
   isolation-check sequencing, fail-closed aggregation, teardown idempotency) is unit
   tested without a hypervisor.
2. **Isolation-check policy as data + a pure evaluator** (§5 as a checklist the adapter
   runs and aggregates fail-closed), fully unit-testable with fake probe results.
3. **The operator runbook** (setup / validate / negative-control / evidence / teardown),
   as a doc under `docs/`.
4. **Resource-profile + readiness-criteria doc** (this spec's §8/§10, extracted as an
   operator checklist).

The actual Hyper-V command execution and the live end-to-end run are **lab-gated**
(§10) and excluded here.

## 12. Testing strategy

- **Now (lab-independent, TDD):** the `adlabhyperv` resolution/isolation-aggregation/
  teardown-idempotency logic against a **fake command seam**; the isolation evaluator's
  fail-closed behavior on every probe-failure/uncertain combination; the topology
  catalog's M1 definition; contract tests that the adapter satisfies `adlabrt.Substrate`
  and drives `Runtime.Validate` to each terminal state using faked Hyper-V results.
- **Lab-gated (deferred):** real provisioning, the §5 live isolation probes, and a full
  positive+negative DCSync validation against a real DC on dedicated hardware.

## 13. Exclusions

- No cloud, no cloud spend, no second provider implementation in this milestone.
- No changes to `adlabrt.Substrate`/`Runtime`, `adgate`, `adlab` planning, or
  `dispatchRun`/run modes.
- No running the lab on the dev host.
- No new attack/payload content (execution reuses existing reusable content).
- No detection/telemetry assertion (that is P6).
- No generic multi-backend lab-management platform — only what M1 needs, provider-neutral
  by keeping topology in the adapter catalog behind the unchanged seam.

## 14. Next steps (gated on review)

1. On approval of this spec → `writing-plans` for the **lab-independent** slice (§11):
   `adlabhyperv` skeleton + topology catalog + isolation evaluator + runbook, all TDD
   against fakes.
2. The real Hyper-V execution + live validation remain deferred until §10 readiness
   criteria hold.
3. P6 (detection validation) attaches at the §9 evidence boundary, separately.
