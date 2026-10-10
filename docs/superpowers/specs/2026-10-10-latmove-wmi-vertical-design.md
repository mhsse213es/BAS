# Lateral-Movement Validation — Vertical 1: WMI Remote Process Creation — Design Spec

**Date:** 2026-10-10
**Status:** Approved for planning (user scoped and approved the design; proceeding to spec→plan→implement without an intermediate gate).
**Builds on:** `adlabhyperv` (lab substrate/topology), `adprimitive.RiskClass` (type only). Deliberately does **not** build on `admatrix` or `controlval` in this slice (see section 1).

## 1. Scope

The first lateral-movement validation vertical: prove that WMI remote process creation
(T1047) genuinely achieves cross-machine code execution between two domain-joined client
machines. This slice is **execution-validation only** — it establishes whether the
technique's postcondition is genuinely observed on the destination. It does **not** yet
test rights-gating (an authorized vs. unauthorized identity) — that is a follow-on slice,
"Vertical 1b", layered on afterward exactly as DCSync's control-efficacy layer followed its
own execution/content work.

**Sequencing (locked, user-approved):**
1. **Vertical 1 (this slice):** client→client, WMI remote process creation, execution
   validation only. Lab-independent, fake-backed.
2. **Vertical 1b (not built now):** rights-gating control-efficacy layer on top of Vertical
   1, reusing `controlval` the way `adefficacy` reused it for DCSync (authorized identity
   succeeds, unprivileged identity denied, same-build pairing).
3. **Vertical 1c (not built now):** client→`dc01` topology variant, reusing the existing DC
   from the DCSync lab — no new VM.
4. **Family expansion (not built now):** remote service creation (PsExec-style), scheduled
   task (remote), WinRM, RDP — added one technique at a time after Vertical 1 proves the
   pattern.

### Why not reuse `admatrix` or `controlval` here

`admatrix`'s five axes are scoped to AD-object-abuse capabilities (Kerberoasting, ACL,
DCSync, etc.) — WMI remote process creation is an OS-level execution technique, not a
directory-object action, and forcing it into `admatrix` would miscategorize it. Generalizing
`admatrix`'s execution-validation axis into a shared package (as `controlval` was
generalized from the AD-specific case) is a larger refactor than one vertical justifies —
YAGNI. This slice is self-contained; a third consumer, if one appears, is the trigger to
generalize, not this one.

### Non-goals (this slice)

- No real `ExecutionObserver` (no live WMI call, no real log reads). Only a fake ships.
- No live wiring into any execution/reporting path.
- No rights-gating / control-efficacy layer (Vertical 1b).
- No client→`dc01` topology (Vertical 1c).
- No other techniques (remote service creation, scheduled task, WinRM, RDP).

## 2. Evidence model

Three evidence items, with a strict hierarchy that mirrors — and tightens — the DCSync
DRSUAPI-primary/4662-corroboration discipline, per the project's standing rule: **verify
postconditions, not command-success.**

- **Primary (sole determinant): the destination-side marker readback.** The attempt writes
  a **unique, per-attempt token** and the harness independently reads it back from the
  destination. This is the only thing that establishes `Executed`. A call that *reports*
  success is not sufficient on its own — only a genuinely observed postcondition is.
- **Secondary — the WMI call's own immediate outcome** (`succeeded` / `access_denied` /
  `errored` / `unknown`). Diagnostic only: it never independently establishes `Executed`,
  but an `access_denied` call result, combined with a marker that was *not* found, lets the
  harness report a meaningful `AccessDenied` instead of a bare `Indeterminate`.
- **Corroboration only — parent-process chain (`WmiPrvSE.exe`) and the WMI-Activity
  operational log.** Supporting detail; never outcome-determining, exactly as 4662 was for
  DCSync.

### Classification rule — `ClassifyAttempt(obs Observation) AttemptResult`

Pure function, no side effects:

| Condition | Result |
|---|---|
| marker check not correlated to this attempt | `Indeterminate` (can't trust an uncorrelated check) |
| marker found | `Executed` (postcondition genuinely observed) |
| marker absent AND call outcome = `access_denied` | `AccessDenied` (absence corroborated by a denial signal) |
| marker absent AND no corroborating denial signal | `Indeterminate` (ambiguous — never a false negative *or* false positive) |

No path promotes a call-reported success, or a present corroboration signal alone, to
`Executed`. No path manufactures `AccessDenied` from corroboration alone.

## 3. Package layout

```
internal/latmove    new, self-contained. Imports adprimitive (RiskClass TYPE only — no AD
                    catalog content) + stdlib. No dependency on admatrix or controlval in
                    this slice.
internal/adlabhyperv  gains ONE additive topology catalog entry ("client-pair"); no
                    changes to the Topology/VMSpec/AttackerIdentity struct shapes.
```

- `technique.go`: `Technique{ID, Name, MitreID, RiskClass}`, `WMIRemoteProcessCreation() Technique`.
- `observation.go`: `AttemptKey{RunID, Source, Destination, Technique string; Window TimeWindow}`,
  `CallOutcome`, `MarkerCheck{Correlated, Found bool}`, `Corroboration{ParentProcessObserved bool;
  ParentProcessName string; WMIActivityLogged bool}`, `Observation{Key, Call, Marker,
  Corroboration, Detail}`, `AttemptResult` (`Executed`/`AccessDenied`/`Indeterminate`),
  `ClassifyAttempt(obs Observation) AttemptResult`.
- `observer.go`: `ExecutionObserver` interface (`Observe(ctx, key) (Observation, error)`),
  `FakeObserver` (the only implementation that ships).

## 4. Lab topology extension

`adlabhyperv`'s catalog gains a new topology, additive only:

```go
"client-pair": {
    Name:   "client-pair",
    Switch: "audspect-lab-private",
    VMs: []VMSpec{
        {Name: "ws01", Role: RoleClient, BaseCheckpoint: "ws01-base-clean", VCPU: 2, MemoryMB: 4096, DiskGB: 40},
        {Name: "ws02", Role: RoleClient, BaseCheckpoint: "ws02-base-clean", VCPU: 2, MemoryMB: 4096, DiskGB: 40},
    },
    // Attacker is intentionally zero-value: this slice is execution-validation only.
    // Rights-gating (Vertical 1b) assigns identities when it is built.
},
```

Resource profile matches the runbook's already-documented client-VM figures (~2 vCPU/4GB/
40GB), same private switch as `dc-only` — no new switch, no change to isolation checks.
`AttackerIdentity` is left at its zero value for this entry; it is documented as
intentionally unused until Vertical 1b, not an oversight.

## 5. Lab-gated boundary & readiness

Real execution requires: the `client-pair` topology stood up (two client VMs, domain-joined
to `lab.local`, on `audspect-lab-private`); isolation re-verified for the new VMs (same four
checks, same fail-closed rule); a real `ExecutionObserver` that performs the WMI call,
writes/reads the per-attempt marker, and reads the destination's own event log for the
corroboration signals; operator authorization bound to the run. Until then: `latmove` is
fake-backed only; no live wiring.

## 6. Definition of done (this slice)

- `ClassifyAttempt` truth table fully tested, including both ambiguous-but-not-wrong paths
  (uncorrelated marker; absent marker with no denial signal) landing on `Indeterminate`
  rather than a guessed verdict in either direction.
- `FakeObserver` proves the seam (same caveat as `adefficacy`'s fake: it proves the seam
  works, not that a real observer correlates correctly).
- `client-pair` topology addition is additive-only; `dc-only` and its tests are unaffected.
- No real observer, no live wiring, no rights-gating.

## 7. Testing

- `technique_test.go`: `WMIRemoteProcessCreation()` returns stable `ID`/`MitreID`.
- `observation_test.go`: full `ClassifyAttempt` truth table (4 rows above) plus a case
  proving corroboration fields never flip the result on their own (e.g. `ParentProcessObserved:
  true` with an uncorrelated marker is still `Indeterminate`).
- `observer_test.go`: `FakeObserver` returns canned observations by key, an uncaptured key
  returns an indeterminate/uncorrelated observation (never fabricates), a configured error
  propagates, compile-time `ExecutionObserver` interface check.
- `adlabhyperv` topology test: `LookupTopology("client-pair")` returns the two-VM topology;
  `LookupTopology("dc-only")` is unchanged (regression lock).
