# Control-Efficacy Validation — Design Spec

**Date:** 2026-10-10
**Status:** Approved for planning (design locked in brainstorming; user authorized spec→plan without an intermediate gate).
**Scope note:** Lab-independent slice only. Fake-backed, contract-tested, provider-neutral. Real provider adapters (Silverfort first) are deferred and lab-gated.

## 1. Goal & scope

Give Audspect a **product-neutral control-efficacy validation layer**: for an attack
attempt that was *already executed* by some other part of the system, record what a
**deployed security control** did about it — allowed, blocked, MFA-challenged, terminated,
quarantined, or unknown — and grade that **observed** response against a **per-case
expected outcome**. The verdict is always a comparison of observed-vs-expected, never the
outcome alone.

"Control" is deliberately broad: some controls block, some challenge authentication, some
terminate sessions, some quarantine assets, and some only detect-and-alert without
preventing. Silverfort is the first real provider; the core model couples to no vendor and
to no AD-specific code.

### Non-goals (this slice)

- No real provider adapter (no Silverfort/Entra/Okta/GoTrust/BigID client). Only a fake.
- No wiring into `dispatchRun` or the `adlabrt` production execution path.
- No live population of the new capability-state axis (requires real observations).
- No standalone policy engine. Expectation is declared per validation case.
- No expansion to a second vendor until the provider-neutral contract is proven sound.

## 2. Context — where it fits

The AD capability model (`internal/admatrix`) carries **five independent axes** per
capability: `Modeled → ContentAvailability → ScenarioComposed → ExecutionValidation →
DetectionValidation`. There is **no axis for "was the attack prevented by a deployed
control."** `DetectionValidation` (via `internal/addetect → internal/detectverify`, keyed
on MITRE TechniqueID) answers *"did the SIEM/EDR **see** it?"* — a different question from
*"did the control **block/challenge/terminate** it?"*.

This design adds **control efficacy as a sixth, independent sibling axis**. It mirrors the
`addetect → detectverify` split: a generic, vendor- and AD-agnostic core, consumed by a
thin AD bridge. The sixth axis never modifies or collapses the five existing axes.

## 3. Package layout & dependency direction

```
internal/controlval      generic core — imports stdlib only.
                         NO adprimitive, NO admatrix, NO vendor packages.
internal/adcontrolval    AD bridge — imports controlval + adprimitive + admatrix. One-way.
internal/admatrix        gains ONE additive sibling field + ONE additive summary count.
                         Imports nothing new (the axis type is admatrix-local).
```

`controlval` never gains AD-awareness or vendor-awareness. `adcontrolval` is the only
AD-aware piece. `admatrix` does not import `controlval`.

## 4. Core model (`internal/controlval`)

Types are design-level; the plan refines exact signatures.

```go
type Outcome string

const (
    OutcomeAllowed       Outcome = "allowed"
    OutcomeBlocked       Outcome = "blocked"
    OutcomeMFAChallenged Outcome = "mfa_challenged"
    OutcomeTerminated    Outcome = "terminated"
    OutcomeQuarantined   Outcome = "quarantined"
    OutcomeUnknown       Outcome = "unknown"
)

// EvidenceKind separates a directly observed response from an inferred one.
// Recorded on every observation; it is NOT automatically trustworthy.
type EvidenceKind string

const (
    EvidenceObserved EvidenceKind = "observed" // the control itself reported the response
    EvidenceInferred EvidenceKind = "inferred" // derived from side effects / attack-side postcondition
)

// Confidence is the correlation + evidence-quality grade. SEPARATE from
// EvidenceKind: an observed outcome can still be low-confidence.
type Confidence string

const (
    ConfidenceHigh   Confidence = "high"
    ConfidenceMedium Confidence = "medium"
    ConfidenceLow    Confidence = "low"
    ConfidenceNone   Confidence = "none"
)

type TimeWindow struct {
    Start time.Time
    End   time.Time
}

// CorrelationKey ties the four evidence streams (attempt, execution/postcondition,
// control response, detection) together WITHOUT requiring all four to exist.
type CorrelationKey struct {
    RunID  string
    Target string
    Action string // opaque action id; the AD bridge maps primitive.ID -> Action
    Window TimeWindow
}

// Observation is ONE record from the control-response evidence stream.
type Observation struct {
    Key          CorrelationKey
    Provider     string // "silverfort" | "fake" | ...
    Outcome      Outcome
    EvidenceKind EvidenceKind
    Confidence   Confidence
    Source       string // "silverfort-api" | "siem-query" | "agent-postcondition" | ...
    ObservedAt   time.Time
    Detail       string
}

// Expectation is declared per validation case. It does NOT verify policy; it
// identifies the policy the expectation derives from.
type Expectation struct {
    Expected       Outcome
    PolicyBasis    string     // identifies the governing policy
    PolicyVerified bool       // false when the policy was merely SUPPLIED as test input,
                              // not independently verified against the live control config
    MinConfidence  Confidence // required floor for a determinate verdict
}

// Verdict reuses the existing scoring taxonomy (project_scoring_verdicts).
type Verdict string

const (
    VerdictPass    Verdict = "PASS"
    VerdictFail    Verdict = "FAIL"
    VerdictError   Verdict = "ERROR"
    VerdictSkipped Verdict = "SKIPPED"
)

type Validation struct {
    Key         CorrelationKey
    Expectation Expectation
    Observation *Observation // nil = control-response stream explicitly MISSING
    Verdict     Verdict
    Reason      string // control-specific, directional
}
```

`PolicyVerified` defaults false. The rationale (`PolicyBasis`) identifies the policy basis;
it must never imply a policy was verified when it was only supplied as test input.

## 5. Evaluation rules — `Evaluate(exp Expectation, obs *Observation, opErr error) Validation`

`Evaluate` is pure over its inputs and reads **nothing** from the execution or detection
streams.

| Condition | Verdict | Reason |
|---|---|---|
| `opErr != nil` | `ERROR` | provider/validation operation failed technically |
| `obs == nil` | `SKIPPED` | control response not recorded (stream missing) |
| `obs.Outcome == OutcomeUnknown` | `SKIPPED` | outcome unknown |
| confidence below `exp.MinConfidence` | `SKIPPED` | below required confidence threshold |
| expected ∈ {blocked, terminated, quarantined, mfa_challenged} AND `obs.EvidenceKind == inferred` | `SKIPPED` | inferred-only cannot establish prevention |
| determinate & `observed == expected` | `PASS` | observed outcome matches expectation |
| determinate & expected=prevention, observed=allowed | `FAIL` | expected prevention, observed allowed — control gap |
| determinate & expected=allowed, observed=prevention | `FAIL` | unexpected denial |
| determinate & `observed != expected` (other) | `FAIL` | observed outcome contradicts expectation |

Two **hard invariants**, each pinned by a dedicated test:

- **Invariant A — inferred never prevents.** Inferred evidence must never independently
  establish successful prevention. When the expectation is a prevention outcome and the only
  evidence is inferred, the verdict is `SKIPPED`, never `PASS`.
- **Invariant B — missing stays missing.** A missing stream (nil observation) yields
  `SKIPPED` and is never fabricated from another stream. The evaluator never reads the
  execution or detection streams to fill a missing control observation.

"Sufficiently reliable" = observed (or an allowed-expectation inferred result) at or above
`MinConfidence`, with a determinate (non-unknown) outcome.

## 6. Provider seam + fake

```go
// Provider observes a DEPLOYED security control's response to an already-executed
// attack attempt. It does NOT execute the attack (execution is a separate evidence
// stream). When it cannot correlate a response it returns an Outcome=unknown
// observation (NOT an error); error is reserved for a technical failure of the
// observation operation itself.
type Provider interface {
    Name() string
    Observe(ctx context.Context, key CorrelationKey) (Observation, error)
}
```

Only `FakeProvider` ships now: canned observations per `Action`, with settable
`Outcome`/`EvidenceKind`/`Confidence`/`Source`, plus a settable error, so tests can drive
every row of the truth table and both invariants. A real adapter is a named, deferred
follow-up behind this seam.

## 7. Provider roster (all deferred, lab/tenant-gated)

The contract is proven with the fake. Real adapters are added **one at a time, only after
the contract is sound**, each behind the `Provider` seam. Recorded here so the roster is
explicit; none is built in this slice.

| Provider | Control types validated | Observation source (EvidenceKind=observed) | Gate |
|---|---|---|---|
| **Silverfort** (first) | Universal MFA, Auth Firewall, ITDR (PtH/PtT/Kerberoasting/DCSync), NHI virtual fencing, vaultless PAM | Silverfort API / SIEM enforcement decisions | AD lab or client env with Silverfort inline |
| **Microsoft Entra ID** | Conditional Access (grant/block/require-MFA/require-compliant-device), ID Protection risk, session revocation via CAE, PIM | Sign-in logs (per-policy CA result); Microsoft Graph `riskDetections`/`riskySignIns`/`riskyUsers`; diagnostic-settings export to SIEM | Entra tenant (P1/P2) + Graph access |
| **Okta** | Adaptive MFA risk (force-MFA/block/allow), ThreatInsight IP block, Identity Threat Protection session signals | System Log API `/api/v1/logs` (`user.risk.detect`, ITP session events); ThreatInsight | Okta org (OIE) + API token |
| **GoTrustID** | Passwordless/FIDO2 MFA enforcement | Integration logs (RADIUS/SAML/OIDC adapter) | Env with GoTrust inline |
| **BigID** (data controls only) | Access revocation, DLP/exfil block on classified data | BigID Action Center / audit trail; DLP decision logs | Env with BigID + classified canary data |

Note the independence point for IdPs: Entra/Okta risk detections are a **detection** signal;
a Conditional-Access block / session revocation is a **control** response. They are recorded
as separate streams under the same `CorrelationKey` and never substituted for one another.

## 8. AD bridge (`internal/adcontrolval`) + the sixth axis

The bridge:

- Maps `adprimitive.Primitive.ID → controlval.Action` (stable identifier mapping).
- Builds the `controlval.CorrelationKey` from caller-supplied `(runID, target, window)` plus
  the mapped action — exactly as `addetect.VerifyRequestFor` builds a detect request.
- Maps `controlval.Validation → admatrix.ControlEfficacyState`.

`admatrix.CapabilityState` gains **one additive field** (admatrix-local type — admatrix
imports nothing new):

```go
// ControlEfficacy is the sixth, INDEPENDENT axis: whether a DEPLOYED security
// control produced its expected response to this capability. Zero value =
// not evaluated. It never modifies or collapses the five existing axes, and it
// is independent of DetectionValidation.
ControlEfficacy ControlEfficacyState `json:"controlEfficacy"`

type ControlEfficacyState struct {
    Evaluated    bool   `json:"evaluated"`
    Verdict      string `json:"verdict,omitempty"`        // PASS/FAIL/ERROR/SKIPPED
    Provider     string `json:"provider,omitempty"`
    Observed     string `json:"observedOutcome,omitempty"`
    Expected     string `json:"expectedOutcome,omitempty"`
    EvidenceKind string `json:"evidenceKind,omitempty"`
    Confidence   string `json:"confidence,omitempty"`
    Reason       string `json:"reason,omitempty"`
}
```

`CapabilityStateSummary` gains **one additive count** `ControlValidated int` (count of
capabilities whose `ControlEfficacy.Verdict == PASS`). In this slice it is **0**, because
nothing populates the axis live — this is honest, not hidden.

**Live population is deferred.** `CapabilityStates()` leaves `ControlEfficacy` at its
`{Evaluated:false}` zero value. The slice ships the field, the bridge mapping, and tests —
not live data. A doc comment marks the deferred live-wiring boundary.

## 9. The independence invariant

Control efficacy and detection efficacy are computed by **different packages from different
streams** and must never cross-contaminate. Canonical case pinned by a test: an
observed, high-confidence `Blocked` control response yields control-efficacy `PASS`, while
an empty detection result for the same `CorrelationKey` yields detection failure — and
neither evaluator reads the other's input. A blocked attempt with no SIEM alert may pass
control validation and fail detection validation.

## 10. Lab-gated boundary & readiness criteria

Real control-efficacy claims require **all** of:

1. A lab or client environment with the control (Silverfort first) inline on the auth/data path.
2. A real `Provider` adapter that reads the control's enforcement decisions (API/SIEM/logs)
   and reports `EvidenceKind` and `Confidence` honestly.
3. Correlation proven against real `(runID, target, action, window)` — not assumed.
4. Operator authorization bound to the specific run/target (via the existing `adgate`
   authorization model), not an ambient flag.
5. No prevention claim derived from mocks, configuration presence, or detection telemetry alone.

Until all hold: `controlval` + `adcontrolval` exist fake-backed only; no `dispatchRun`
wiring; the axis stays not-evaluated.

## 11. Testing strategy (TDD throughout)

- **`controlval`**: full `Evaluate` truth table incl. both FAIL directions (gap and
  unexpected-denial); Invariant A (inferred-only prevention → SKIPPED); Invariant B
  (nil observation → SKIPPED, no cross-stream read); confidence floor → SKIPPED;
  `Unknown` → SKIPPED; `opErr` → ERROR; provenance (EvidenceKind) kept separate from
  Confidence; `FakeProvider.Observe` returns canned/error paths.
- **`adcontrolval`**: `primitive.ID → Action` mapping; `CorrelationKey` construction;
  `Validation → ControlEfficacyState` mapping; and an explicit assertion that the bridge
  leaves the five existing axes untouched.
- **`admatrix`**: `ControlEfficacy` defaults to not-evaluated; camelCase JSON key
  (`controlEfficacy`); existing summary counts unchanged; new `ControlValidated` count
  additive and 0 in this slice.

## 12. Review focus / risks

1. **Invariant A and B are the crown jewels** — most likely to be quietly violated by a
   convenience default (e.g. a PASS that falls through on inferred evidence, or a missing
   observation defaulted to a benign outcome). Each gets a dedicated failing-first test.
2. The additive axis must not perturb existing P7 reporting/UI, the camelCase JSON test,
   or the RBAC matrix tests.
3. `Action` identifier stability across the bridge (a rename silently breaks correlation).
4. Scope creep: resist building a real provider or a second vendor before the contract is
   proven.
5. `PolicyVerified` honesty: ensure no code path sets it true from test-supplied input.

## 13. Decisions locked (recorded)

- Product-neutral control-efficacy layer; Silverfort first provider; broad "control"
  definition (block / challenge / terminate / quarantine / detect-only).
- Five AD axes preserved; control efficacy added as an independent sixth sibling axis.
- Generic `ControlOutcome` contract with Allowed/Blocked/MFAChallenged/Terminated/
  Quarantined/Unknown; observed-vs-inferred distinction preserved.
- Attack execution, execution/postcondition, control response, and SIEM/EDR detection are
  four independent evidence streams, correlated by `(runID, target, action, window)`, none
  required to co-exist, none manufacturing another's result.
- Provider-neutral interface + fake-backed seam first (Hyper-V approach: model, contract,
  tests, fake).
- Real Silverfort efficacy gated on an actual lab/client env.
- Evidence provenance explicit; Unknown/ambiguous/inferred-only/low-confidence never
  promotes to Blocked or PASS.
- Outcome alone never determines pass/fail; every case carries an expected outcome plus a
  policy-derived rationale, with `PolicyVerified` honestly false for test-supplied policy.
- AD coupling via bridge-and-surface; bridge must not modify/collapse the five axes.
- Expectation per validation case; no standalone policy engine yet.
- Verdicts reuse PASS/FAIL/ERROR/SKIPPED with explicit control-specific reasons.
