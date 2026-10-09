# DCSync Lab-Runtime — Design Spec

**Date:** 2026-10-09
**Status:** Design spec. Awaiting review before an implementation plan. No code yet.
**Precursor:** `2026-10-09-ad-lab-runtime-scoping.md` (scoping, reviewed; decisions locked below).
**Scope:** DCSync **execution-and-evidence validation** — proving the controlled
lab-runtime contract end to end for an *already-reusable* capability. **Not** new
payload authoring. `dispatchRun` is untouched; D-runtime stays deferred.

## 1. Decisions carried in (locked)

| Decision | Direction |
|---|---|
| Provisioning | Disposable VM + **verified** isolated network (tech not committed until isolation demonstrated) |
| Evidence | Lab-local collection first; defined telemetry-adapter boundary for later |
| Runtime home | `internal/adlabrt`, in-process, narrow interface, substrate-specific adapter |
| Provenance | Verification-derived, bound to lab target **and** run |
| Failure policy | Fail closed on uncertain isolation, provenance, authorization, **or** evidence |
| Dispatcher | `dispatchRun` untouched |
| Scope | DCSync execution+evidence validation, not new payload authoring |

**Critical requirement:** *authorization to execute* is kept distinct from *evidence
that the environment is controlled*. Verification establishes that a lab is isolated;
it must **not** silently permit every action within it. `adgate` evaluates **both**
the verified environment provenance **and** the action-specific authorization —
neither alone allows.

## 2. Phase split

- **Phase A (buildable now — pure Go + fake substrate):** the `internal/adlabrt`
  contract, the `Runtime` lifecycle orchestration, fail-closed semantics, the
  `adgate` "verified controlled lab" provenance origin + run-binding, and the
  evidence model — all exercised against an in-process **fake substrate**. No real
  VM, no real DC, no real DCSync command.
- **Phase B (deferred — needs real infra + a demonstrated isolation property):** the
  concrete disposable-VM substrate adapter, real DC provisioning, the real isolation
  probe, and driving the real (already-reusable) DCSync ART atomic. Gated on
  demonstrating the substrate's isolation before committing the provisioning tech.

This spec specifies both; the implementation plan that follows covers **Phase A
only**. Phase B gets its own plan once isolation is demonstrable.

## 3. Architecture & responsibilities

```
adlab (unchanged)          internal/adlabrt (new)              adgate (extended)
  Env model, Provider,       Runtime: lifecycle orchestration    Decide(Request) with a new
  Validate (planning only)   Substrate adapter (iface)           "verified controlled lab"
                             Evidence model + collection          provenance origin; still
                             mints run-bound provenance           requires BOTH env+auth
```

- `adlab` stays the deterministic environment **model** and planning validator.
- `adlabrt` owns **lifecycle**: provision → verify-isolation → expose-identity →
  (gate) → execute a validation case → collect evidence → reset/teardown. It talks to
  infrastructure only through a **`Substrate` adapter**, so no hypervisor command or
  credential is embedded across the codebase.
- `adgate` gains one new allowable provenance origin (below); its decision inputs
  (env provenance + action authorization) are unchanged in shape.

## 4. The `adlabrt` contract (narrow interfaces — design shapes, not implementation)

```go
// Substrate is the only seam to real infrastructure. The fake implements it for
// Phase A; the disposable-VM adapter implements it for Phase B. Nothing above this
// line knows about hypervisors or credentials.
type Substrate interface {
    Provision(ctx, LabSpec) (Target, error)          // bring up a disposable DC+identity
    VerifyIsolation(ctx, Target) (IsolationResult, error) // INDEPENDENT check; see §7
    Execute(ctx, Target, ValidationCase) (RawObservation, error) // run the (reusable) atomic
    Teardown(ctx, Target) error                       // destroy; must be callable any time
}

type Target struct { ID string; /* opaque handle; identities exposed via accessor */ }
type IsolationResult struct { Verified bool; Method string; Detail string }

// Runtime orchestrates the lifecycle and is the ONLY minter of lab provenance.
type Runtime struct { /* holds a Substrate + a clock + an evidence sink */ }

func (r *Runtime) Validate(ctx, Request) Result
```

- `Runtime.Validate` is the single entry point: it runs the full lifecycle for one
  authorized validation case and returns a `Result` (outcome + `Evidence`),
  guaranteeing teardown on every path.
- `Request` carries: the lab spec/name, the `ValidationCase` (which `adlab` case +
  expected postcondition), and the **action authorization** (operator-supplied,
  per-run) — kept separate from anything the runtime derives.

## 5. Provenance (the `adgate` extension)

- `adgate` gains a provenance origin **`VerifiedControlledLabProvenance`**, minted by
  a constructor that lives only where the `Runtime` can call it (unexported-origin
  pattern, mirroring `SyntheticProvenance`/`LiveADProvenance`) so no caller can
  fabricate "verified lab."
- The `Runtime` mints it **only after** `Provision` + `VerifyIsolation(Verified==true)`
  + identity exposure succeed. It is **run-bound**: tied to the run correlation id and
  the `Target.ID`; a provenance minted for run/target A is not valid for B.
- `adgate.Decide` treats this origin as allowable like `SyntheticProvenance` for the
  environment dimension — **but the decision still requires the separate
  `Authorization` to be present/sufficient.** Verified isolation alone never allows an
  action (the critical requirement): env-provenance says *where*, authorization says
  *whether this action*.
- Any failure to mint (isolation not verified/uncertain) → no provenance → gate
  denies → no execution.

## 6. Authorization & secrets

- **Authorization** (`adgate.Authorization{Authorized, DestructiveApproved}`) is
  supplied per validation case by the operator and bound to this run+target; it is an
  independent `Decide` input, never derived from isolation verification.
- **Secrets** (lab credentials, substrate handles) live only inside the `Substrate`
  adapter and `Target`; never logged, never in the `adlab` model, never committed.
  The `Target` exposes identity *references*, not raw credentials, upward.

## 7. Threat boundaries

- **Isolation is adversarial, verified independently.** `VerifyIsolation` must not
  trust the substrate's self-report; it performs an independent check that production
  AD is unreachable from the target (e.g., an active negative-reachability probe) and
  returns `Verified=false` if the check cannot be performed. Unverifiable ⇒ not
  isolated ⇒ fail closed.
- **Provenance is unforgeable at origin** (only the `Runtime` mints it) and
  **run-bound** (cannot be replayed to authorize another run/target).
- **Evidence is runtime-collected, not self-reported** by the executed action, so a
  misbehaving target cannot fake a postcondition.
- **Blast radius:** a disposable DC per run, on an isolated network with no route to
  production, destroyed after — the attack cannot escape the lab or persist.

## 8. Failure recovery & cleanup guarantees

- **Teardown always runs** — on success, on any error, on panic (deferred), and on
  context cancellation. A `Provision` with no matching `Teardown` is a defect.
- **Teardown failure is surfaced loudly** (leaked lab resources are a risk), returned
  in `Result` and logged, not swallowed.
- **Cleanup model:** disposable-per-run — each `Validate` gets a fresh target and
  destroys it; "reset" is reprovision, which sidesteps dirty-state concerns. (Pooled
  targets with reset are a possible later optimization, out of scope.)
- **Fail-closed outcomes**, each a distinct `Result` status: provision-failed,
  isolation-unverified, provenance-unminted, authorization-denied, execution-errored,
  evidence-inconclusive. Any of these ⇒ **not validated**; none is reported as success.

## 9. Evidence model (lab-local first; adapter boundary for telemetry later)

`Evidence` captured by the `Runtime` records, at minimum:

- **lab instance + target** involved (ids);
- the **authorized validation case** requested;
- the **observed outcome** and relevant **timestamps**;
- whether the **expected postcondition** (`CapDomainCredentialMaterial` — replication
  actually occurred) **was observed**;
- whether collection was **complete or inconclusive** (inconclusive ⇒ fail closed).

A successful dispatch is **never** taken as proof of outcome — the postcondition is
observed, not assumed. The evidence sink is behind an interface with a defined
adapter boundary so the orchestrator's telemetry path can be plugged in later without
changing the runtime.

## 10. `adgate`-enforcement seam (identify only — do NOT wire)

The single point where a future caller asks `adgate.Decide` immediately before
`Substrate.Execute`, consuming the §5 run-bound provenance + §6 authorization, is
named here. In this spec the `Runtime` itself calls `Decide` before `Execute`
(self-contained; the lab-runtime *is* the control boundary for lab execution). The
orchestrator's `dispatchRun` is **not** touched; wiring the gate into the real
product dispatch path remains D-runtime, deferred.

## 11. Testable acceptance criteria (Phase A, fake substrate)

1. **Happy path:** fake provisions + isolation verified + authorized → gate allows →
   execute → evidence shows postcondition observed → teardown ran → `Result=validated`.
2. **Isolation unverified/uncertain:** no execution, **no provenance minted**, gate
   not satisfied, teardown ran, `Result=isolation-unverified`.
3. **Environment verified but action NOT authorized:** gate **denies** (proves
   authorization is distinct from environment-controlled provenance) → no execute.
4. **Verified + authorized but evidence inconclusive:** `Result=evidence-inconclusive`
   (fail closed), not success.
5. **Negative control (real distinction from planning):** identity lacking
   DS-Replication rights → postcondition **not** observed → `Result=not-validated`,
   even though `adlab.Validate` reachability would differ — proving execution evidence
   ≠ planner reachability.
6. **Provenance run-binding:** provenance minted for run/target A does not satisfy the
   gate for run/target B.
7. **Teardown on every path:** execution error and injected panic both still invoke
   teardown exactly once.
8. **Both-inputs rule:** neither verified-lab provenance alone nor authorization alone
   yields allow; only both together.

(Phase B adds, later: real isolation-probe correctness, real DC provisioning/teardown,
and the real DCSync atomic producing the observed postcondition.)

## 12. Exclusions

- No real VM/substrate implementation in Phase A (deferred to Phase B, gated on an
  isolation demonstration). No hypervisor tech committed by this spec.
- No new attack payloads; DCSync uses the existing reusable ART atomic, driven via the
  `Substrate.Execute` seam in Phase B.
- No changes to `adlab` planning semantics, `dispatchRun`, or run modes.
- No E2 per-gap contracts (separate track).
- No generic provisioning framework.

## 13. Next steps (gated on review)

1. On approval → implementation plan for **Phase A** (`internal/adlabrt` + `adgate`
   provenance extension + evidence model + fake substrate + the §11 acceptance tests),
   TDD, inline.
2. Phase B (real disposable-VM substrate + isolation demonstration + real DCSync
   execution) → its own spec + plan, later.
3. Separate track: safe E2 per-gap contracts (no payloads).
4. D-runtime remains deferred.
