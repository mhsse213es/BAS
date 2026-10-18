# DLP-ENF (Enforcement Consistency) Design

## Intent and why

DLP Mastery's third and final locked evaluation dimension. Per the boundary table established during DLP-POL/DLP-CLS brainstorming: DLP-ENF answers "did the control take the expected enforcement action?" — distinct from DLP-POL (is the policy configuration correct?), DLP-CLS (did the classification outcome match ground truth?), and Telemetry (is the evidence complete and trustworthy?).

Unlike DLP-POL and DLP-CLS, **DLP-ENF does not start from zero.** `internal/reporting/dlp.go` already is a live, scenario-integrated enforcement-outcome evaluator: `dlpComparator` compares the DLP outcome catalog (Allow/Block/Warn/Justify/Audit/Quarantine/Encrypt/Redact, `internal/scenario/outcome_catalog.go`) against one of three primitive local observations (`OperationSucceeded`/`OperationBlocked`/`OperationUnknown`), sourced from either sink-receipt evidence (authoritative) or a step's self-reported `DLP_OBSERVATION` marker (secondary), with an explicit `MissingEvidence` state and `limitationsFor` prose that never overclaims. This is confirmed correct and in production; this design does not touch it.

A repository audit (`dlp.txt`'s DLP-ENF concern list against the live evaluator) found 4 real gaps:

| Concern (dlp.txt) | Exists today? |
|---|---|
| Allow/audit/warn/block/quarantine/encrypt outcome comparison | Yes — `dlp.go`, unchanged by this design |
| Authorized vs. unauthorized destinations | Partially — scenario-level targeting, not a structured evidence field |
| **User override permissions, reasons and audit records** | **No** — no field anywhere carries an override/justification record |
| **Online vs. offline endpoints and delayed policy synchronization** | **No** — `StepEvidence`/`models.SimulationResult` carry no connectivity or policy-sync-timestamp field. (Note: `internal/dlppolicy/rulebaseline.go` already measures a *related but distinct* question — whether a rule's own *configuration* is stale, via `ConfigChangedAt`/`LastSyncedAt`/`MaxPropagationDelay`. DLP-ENF's question is whether *enforcement behavior* holds up under offline/stale conditions, not whether the configuration itself is stale. This design borrows `rulebaseline.go`'s pattern for the sync-lag calculation, never its domain model.) |
| **Differences between browser/native app/sync client/API-based operations** | **No** — no structured channel-type field exists; channel is implicit in which scenario step ran |
| **Failure handling when classification/policy services are unavailable** (fail open / fail closed / defer / indeterminate) | **No**, and the live engine has no mechanism to put a classification/policy service into a down state during a run — confirmed by audit (no `ServiceUnavailable`-type fault injection anywhere in `internal/scenario`/`internal/agent`) |

The user's locked architectural decision (2026-10-18), given directly, not re-derived here:

> Don't build a second general-purpose enforcement evaluator. `internal/reporting/dlp.go` remains the authoritative enforcement-outcome evaluator. The missing capabilities should extend that foundation where possible; any separate evaluator must have a narrowly defined responsibility, justified only by testing a decision model the live engine cannot currently exercise, and must not duplicate the normal comparator.

This design is the direct application of that decision, split into two pieces of work:

**A. Extend the live evidence pipeline** (3 of the 4 gaps) — add structured fields for channel type, override/justification, and endpoint connectivity/policy-sync-lag to the existing `DLPEvidence`/`StepEvidence`/`VerificationResult` chain, sourced from `models.SimulationResult`. No new comparator; `dlpComparator`'s Allow/Block logic is untouched. These three gaps are all things a live scenario run *can* observe today or with a small, additive field — they ride the existing scenario-integrated path.

**B. A narrowly-scoped, independent evaluator for the one gap the live engine cannot exercise** — service-unavailable failure-mode behavior (fail open / fail closed / defer / indeterminate). This is a new standalone package, `internal/dlpresilience`, fixture-only, with its own `Expectation`/`Evidence`/`Verify` quartet — borrowing the architectural discipline `dlppolicy`/`dlpclassify` already established, never their domain model, and never reusing `dlpComparator` or `DLPCLSOutcome`. Its name deliberately avoids "enforce"/"enf" to prevent it from being mistaken for a second general enforcement evaluator — it tests exactly one decision model (the configured fail-open/fail-closed/defer contract) and nothing else.

## Goals

1. Add a `Channel` dimension (browser / native-app / sync-client / API — an open string, not a closed enum, same discipline as `dlpclassify.SensitivityClass`) to the evidence chain, so enforcement comparisons are reportable per-channel.
2. Add an override/justification evidence record: whether an override occurred, who/what authorized it, the stated reason, and whether an audit record exists for it — all as observed facts, never inferred from a bare "operation succeeded."
3. Add endpoint connectivity + policy-sync evidence: online/offline state, effective policy version, last successful sync time — so an enforcement comparison can be qualified by ("this endpoint was offline / its policy was N hours stale when this was observed") rather than silently assumed current.
4. Build `internal/dlpresilience`: a fixture-only evaluator for the service-unavailable failure-mode contract — given a declared expected failure mode (fail-open/fail-closed/defer/indeterminate-is-acceptable) and synthetic evidence of what actually happened when the classification/policy service was unavailable, produce a verdict. Never claims to have actually taken a real service down.
5. Preserve every existing evidence-sufficiency rule from `dlp.go` (`limitationsFor`, `MissingEvidence`, skip handling) unweakened — new dimensions add qualification, they never let a weaker signal masquerade as a stronger one.
6. Keep DLP-ENF's boundary with DLP-POL (`rulebaseline.go`'s configuration-staleness check) and DLP-CLS strict: this design never infers an enforcement verdict from a policy-configuration verdict or a classification verdict, and vice versa.

## Non-goals

- Rebuilding or replacing `dlpComparator`/`dlpVerifier`'s Allow/Block logic. Unchanged.
- Actually taking a real classification/policy service offline in a live scenario run. Out of scope — `internal/dlpresilience` evaluates a declared contract against evidence, fixture or (later, out of scope for this slice) externally supplied; it never orchestrates a real outage.
- Wiring new scenario YAML step types, new agent protocol fields, or new UI/report surfaces for any of this. This design fixes the Go-level type/evidence contracts only — the same "contracts first, wiring later" boundary DLP-POL/DLP-CLS both used. `ExpectationRow`/report JSON already don't surface `ExpectedOutcome`/`ObservedOutcome`/`Comparison` today (per `detection_validation.go`'s own comment); this design does not change that.
- A live vendor connector for anything in this design.
- Re-deriving the user's architectural decision above — it is locked input to this design, not a proposal to re-litigate.

## Anti-goals

- Never let the new `Channel`/override/connectivity fields weaken an existing `MissingEvidence` verdict into a false `Match` — they are additive qualification, not a new path to a stronger conclusion than the underlying observation supports.
- Never hard-code "fail closed is the correct failure mode" in `dlpresilience` — the correct expectation is declared per-expectation (policy- and product-dependent), never assumed.
- Never let `dlpresilience`'s verdict be presented as proof of real-world service-outage behavior — fixture-backed evidence proves the evaluator's own correctness, never a live product's resilience, exactly the same caveat DLP-POL/DLP-CLS's specs both carry.
- Never duplicate `dlpComparator`'s comparison logic inside `dlpresilience`, and never let `dlpresilience` import `internal/reporting` or vice versa.

## Constraints

- `internal/reporting/dlp.go`'s `dlpComparator`/`dlpVerifier`/outcome-catalog registration are unchanged by this design, beyond the new evidence fields threaded through `DLPEvidence`.
- New fields on `DLPEvidence`/`StepEvidence`/`models.SimulationResult` are additive only (`omitempty` JSON tags where applicable) — no existing field renamed or removed.
- `internal/dlpresilience` has zero imports outside Go stdlib, and zero cross-import of `internal/reporting`, `internal/dlppolicy`, `internal/dlpclassify`, `internal/scenario`. It borrows the `Expectation`/`Evidence`/`EvidenceProvider`/`Verify...` shape, never a shared type.
- Any field whose value cannot be established from available evidence is left as the type's zero value / explicit "unknown" marker, never inferred (e.g., connectivity state defaults to unknown, not "online").

## Builder's call

### Part A: extend the live evidence pipeline

New fields on `DLPEvidence` (`internal/reporting/dlp.go`):

```go
type DLPEvidence struct {
    CollectionMethod string
    CorrelationID    string
    FixtureID        string
    Limitations      string

    // Channel names which operation path produced this evidence --
    // "browser" | "native-app" | "sync-client" | "api" | "" (unknown).
    // An open string, not a closed enum, mirroring
    // dlpclassify.SensitivityClass's own discipline: a future channel
    // type needs no code change to be reported.
    Channel string `json:",omitempty"`

    // Override carries an observed override/justification record, or
    // nil when no override evidence exists (never assumed absent --
    // see OverrideEvidence's own doc comment).
    Override *OverrideEvidence `json:",omitempty"`

    // Connectivity carries observed endpoint online/offline and
    // policy-sync state, or nil when unavailable.
    Connectivity *ConnectivityEvidence `json:",omitempty"`
}

// OverrideEvidence is what was actually observed about a user override
// of a DLP action -- never inferred from a bare operation success.
// Occurred == false with a non-empty Reason is invalid evidence (the
// evidence source made an error); the provider populating this is
// responsible for that invariant, not VerifyEvidence-side code added
// by this design (there is no new Verify function in Part A -- these
// fields are additive evidence only, qualifying dlpVerifier's existing
// result, never driving a new comparison).
type OverrideEvidence struct {
    Occurred       bool
    AuthorizedBy   string // user/role/service identity that approved the override; empty if Occurred is false or unknown
    Reason         string // the stated justification text, verbatim
    AuditRecordID  string // empty when no corresponding audit-trail record was found
}

// ConnectivityEvidence is what was actually observed about the
// endpoint's connectivity and policy currency at the time of the
// enforcement action -- never inferred from the action's outcome
// alone (an endpoint can enforce correctly while offline, using a
// cached policy; "it enforced correctly" is not proof it was online
// or current).
type ConnectivityEvidence struct {
    // Online is nil when connectivity state could not be established
    // (never defaulted to true or false).
    Online               *bool
    EffectivePolicyVersion string
    LastSyncedAt         time.Time // zero value = unknown, never "now"
}
```

`evidenceByTechnique` (`detection_validation.go`) populates `Channel`/`Override`/`Connectivity` from new, equally additive fields on `models.SimulationResult` (`internal/models/schema.go`) — exact field names and the `StepEvidence` passthrough are left to the implementing plan, following the existing `SinkTokenObserved`/`StepName` passthrough pattern in `evidenceByTechnique` exactly (same file, same function, same mirroring convention). No new Verify logic: these are qualifying facts attached to the existing `dlpVerifier` result, not a new comparison axis.

Two things to note explicitly rather than leave implicit:
- `evidenceByTechnique` already collapses multiple steps sharing a `TechniqueID`, keeping whichever step actually fired a detection (`DetectionVerdict == "detected"/"prevented"`) and silently dropping the other step's data on that dedup — pre-existing behavior, unchanged by this design. The new `Channel`/`Override`/`Connectivity` fields are subject to the same dedup as `SinkTokenObserved`/`StepName` already are; this is accepted by precedent, not a new problem this design introduces.
- These new `models.SimulationResult` fields will sit at their zero value in any real (non-fixture) scenario run until the agent protocol is separately extended to actually report channel/override/connectivity data — the same situation `CorrelationID` is already in today (see `DLPEvidence.CorrelationID`'s own doc comment). This design fixes the Go-level contract only; it does not make these dimensions live-useful by itself. `dlpVerifier.Verify`'s `Limitations` text (via `limitationsFor`) is extended with one additional case: when `Connectivity.Online != nil && !*Connectivity.Online`, append a plain-language caveat that the endpoint was offline at observation time — extending `limitationsFor`'s existing switch, never replacing its logic.

Outcome-catalog note (non-blocking, flagged for the implementer): `internal/scenario/outcome_catalog.go`'s `"dlp"` family values (`Allow/Block/Warn/Justify/Audit/Quarantine/Encrypt/Redact`) don't include `Challenge` or `Approval`/`Approve`, which `dlp.txt`'s own enforcement-action list names ("challenged, overridden" / "justify and approval actions"). Whether to add these catalog values is left to the implementing plan's own judgment — it's a one-line additive registry change with no evaluator-logic impact, not a design-level decision.

### Part B: `internal/dlpresilience` — service-unavailable failure-mode contract

```go
package dlpresilience

import "time"

// FailureMode is the declared contract for what a product should do
// when the classification or policy service it depends on becomes
// unavailable. An open string, never a closed enum with an assumed
// "correct" default -- the right mode is policy- and
// product-dependent, decided by whoever authors the expectation.
type FailureMode string

const (
    FailOpen        FailureMode = "fail-open"        // operation proceeds as if no policy applied
    FailClosed      FailureMode = "fail-closed"       // operation is blocked/denied outright
    Defer           FailureMode = "defer"             // operation is held/queued until the service returns
    IndeterminateOK FailureMode = "indeterminate-ok"  // any of the above is an accepted outcome for this expectation
)

// ServiceUnavailabilityExpectation declares what should happen for one
// dependency (classification or policy) when it is unavailable.
type ServiceUnavailabilityExpectation struct {
    ExpectationID    string
    Dependency       string      // "classification" | "policy"
    ExpectedMode     FailureMode
    Note             string
}

// ServiceUnavailabilityEvidence is one observed record of what
// actually happened while the named dependency was unavailable.
type ServiceUnavailabilityEvidence struct {
    ExpectationID    string
    Dependency       string
    ObservedMode     FailureMode // "" = outcome could not be classified into any known mode
    Timestamp        time.Time
    Source           EvidenceSource
}

type EvidenceSource string

const SourceFixture EvidenceSource = "recorded-fixture"

type ServiceUnavailabilityProvider interface {
    ServiceUnavailabilityEvidenceFor(expectationID string, window TimeWindow) ([]ServiceUnavailabilityEvidence, error)
}

type TimeWindow struct{ Start, End time.Time }

// ResilienceOutcome is this package's own independent verdict
// vocabulary -- never dlpComparator's ComparisonResult, never
// dlpclassify.DLPCLSOutcome, never dlppolicy's verdict type.
type ResilienceOutcome string

const (
    OutcomeModeMatched     ResilienceOutcome = "mode-matched"
    OutcomeModeMismatched  ResilienceOutcome = "mode-mismatched"
    OutcomeInconclusive    ResilienceOutcome = "inconclusive"
)

type ResilienceVerdict struct {
    Outcome ResilienceOutcome
    Reason  string
}

// VerifyServiceUnavailabilityExpectation compares a declared
// failure-mode contract against observed evidence. IndeterminateOK
// matches any non-empty ObservedMode -- that is its entire meaning.
func VerifyServiceUnavailabilityExpectation(exp ServiceUnavailabilityExpectation, provider ServiceUnavailabilityProvider, window TimeWindow) ResilienceVerdict
```

Verify order (first match wins):

1. `exp.ExpectedMode == ""` (no failure mode declared) → `OutcomeInconclusive`, `"expectation declares no failure mode"` — checked before evidence is even fetched, since an unset expectation can never be meaningfully compared regardless of what was observed.
2. No evidence records → `OutcomeInconclusive`, `"no service-unavailability evidence found for this expectation in the window"`.
3. Latest (by `Timestamp`) record's `ObservedMode == ""` → `OutcomeInconclusive`, `"observed behavior could not be classified into a known failure mode"`.
4. `exp.ExpectedMode == IndeterminateOK` → `OutcomeModeMatched` (any classified mode is accepted; no Reason).
5. `latest.ObservedMode == exp.ExpectedMode` → `OutcomeModeMatched` (no Reason).
6. Otherwise → `OutcomeModeMismatched`, `fmt.Sprintf("expected failure mode %q, observed %q", exp.ExpectedMode, latest.ObservedMode)`.

A `FixtureServiceUnavailabilityProvider` (mirroring `dlpfixture`/`dlpclassify`'s fixture-provider filtering style: by `ExpectationID` and inclusive `TimeWindow`) is the only provider in this slice's buildable scope.

## What's left to the builder

- Part A's exact new field names on `models.SimulationResult` and the `evidenceByTechnique` passthrough wiring — the `DLPEvidence` additions above are fixed; the `SimulationResult`-side names should follow that file's existing naming conventions (e.g. `Channel string`, `Override *models.OverrideRecord`, `ConnectivityState *models.ConnectivityRecord` or equivalent — exact names and whether `Override`/`ConnectivityState` are modeled as `models` types or passed through as primitive fields is an implementation judgment call, not pinned here).
- `limitationsFor`'s exact new offline-caveat sentence text.
- Whether to add `Challenge`/`Approval` to the `"dlp"` outcome catalog (flagged above, non-blocking).
- Part B's package layout (single file vs. split) and its fixture test matrix (one failing test per Verify branch, per this initiative's established TDD convention).
- Whether `internal/dlpresilience` needs its own `CompareChannelVerdicts`-style helper — not evident from the spec above; left to the plan if a real need surfaces (YAGNI otherwise).
