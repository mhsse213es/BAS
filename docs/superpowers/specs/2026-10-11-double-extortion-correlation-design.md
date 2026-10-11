# Double-Extortion Correlation Engine — Design

## Why

Sub-project #5 of the ransomware-mastery roadmap (`ransomware.txt:283-340`,
depends on #1, done): "Double-extortion correlation: sensitive-data
discovery/staging detection, correlate staging+transfer+encryption, the
IR-without-encryption case." Confirmed against live code: this is
genuinely unbuilt. `internal/rwevidence/dataprotection.go:9` already
documents the current state as "a deliberate scope-down of the full
'double-extortion validation' roadmap item... not a new
correlated-exfiltration engine" — T1567.002 (transfer) and T1486
(encryption) each independently produce a `CapabilityResult`, but nothing
correlates them, and there is no "staging" technique, capability, or
observer anywhere in the codebase.

Of the 6 ransomware scenarios, only `clop-kill-chain.yaml` scripts a
staging-shaped step at all (Stage 3, `T1560.001` — archive creation via
`Compress-Archive`) followed by a transfer-shaped step (Stage 4,
`T1567.002`). Clop has **no `T1486` step** — its 5 stages are recon
(T1083) → process termination (T1562.001) → archive staging (T1560.001) →
cloud-egress reachability (T1567.002) → log clearing (T1070.001). The
other 5 scenarios (Akira, BlackCat, LockBit, Play, RansomHub) have no
staging or transfer step at all; RansomHub's "Double-Extortion Note" is a
message string in a step name, not evidence.

## Scope

**In scope:**
1. Wire `T1560.001` (staging/archival) into `rwevidence`'s existing
   per-attempt evidence framework, reusing its `DataProtection`
   capability and `DataProtectionLookup`/`FakeDataProtectionLookup`
   machinery unchanged.
2. A new, decoupled `internal/dxcorrelate` package that correlates
   staging + transfer + encryption evidence, with explicit rules for
   missing signals, ordering, duplicates, and time windows.
3. A new raw (non-aggregated) read path, `db.RWCapabilityAttempts`,
   preserving per-attempt `action`, `created_at`, and `reason` — the
   existing `RWCapabilityCoverage` (which `rwscore` depends on) is never
   modified or entangled with this.
4. Validate the two leg types the real data model can actually produce
   (staging, transfer) end-to-end against Clop's real dispatch; validate
   the full three-leg case, and every negative case (missing,
   out-of-order, duplicated, temporally-unrelated signals), with
   synthetic evidence in `dxcorrelate`'s own unit tests.
5. `GET /api/scenarios/runs/{runId}/double-extortion-correlation` —
   computed live on every request, no new table (correlation is a
   derived interpretation of existing evidence, not a new observation).

**Out of scope, deliberately deferred:**
- Adding staging or transfer steps to Akira, BlackCat, LockBit, Play, or
  RansomHub — separate, explicitly-scoped scenario-content work.
- Any real direct-behavior observer (proof that staging/transfer/
  encryption actually completed, as opposed to a control's response to
  the attempt) — a future sub-project, once a trustworthy behavior
  signal exists to build it against.
- Persisting scenario step outcomes (pass/fail/vetoed) into
  `rw_capability_results` — a separately-scoped change if ever pursued;
  this sub-project reads only what's already persisted there today.
- A list/history endpoint or any UI for correlation results.

## A. The central evidence-model distinction

Every one of `rwevidence`'s existing capability verdicts (`Prevention`,
`Detection`, `Containment`, `DataProtection`) answers **"how did a
security control respond to this attempt"** — not **"did the underlying
behavior (staging, transfer, encryption) actually occur."** Confirmed
directly: `DataProtectionFromDLPResult` (`internal/rwevidence/dataprotection.go:20`)
maps DLP status `"Detected"`→`VerdictPass`, `"NotDetected"`→`VerdictFail` —
a control-detection fact, with no independent confirmation that the
underlying file operation (archive, exfil) completed. The richer DLP
outcome vocabulary (`Block`/`Warn`/`Audit`/`Justify`/`Quarantine`/etc.,
`internal/reporting/dlp.go`) is collapsed to this binary before it ever
reaches `rwevidence`, losing the distinction between "blocked" and
"flagged but allowed to proceed."

`dxcorrelate` keeps these two questions structurally separate and never
promotes one into the other:

```go
type ControlEfficacyStatus string
const (
    EfficacyDetected      ControlEfficacyStatus = "detected"       // control responded (Verdict=PASS)
    EfficacyNotDetected    ControlEfficacyStatus = "not_detected"   // control did not respond (Verdict=FAIL)
    EfficacyNotApplicable ControlEfficacyStatus = "not_applicable" // SKIPPED/not_applicable
    EfficacyNoEvidence    ControlEfficacyStatus = "no_evidence"    // no row, or SKIPPED/not_tested, or ERROR
)

type BehaviorStatus string
const (
    BehaviorOccurred      BehaviorStatus = "occurred"       // a genuine direct-observation signal said so
    BehaviorNotEstablished BehaviorStatus = "not_established" // the default -- no direct-observation signal exists
)
```

**`BehaviorOccurred` is never derived from `ControlEfficacyStatus`, for
any leg, under any circumstance.** Neither `Detected` nor `NotDetected`
establishes that staging, transfer, or encryption actually happened —
only a genuine direct-observation signal does, and none exists in this
codebase today. This applies uniformly to all three legs; there is no
special-cased inference for staging/transfer reusing the DLP signal. The
practical consequence, stated plainly: **against every real scenario run
today, including Clop, every leg's `Behavior` is `NotEstablished`.**
`ControlEfficacyStatus` is still computed and reported for every leg
where a row exists — it is real, useful, honestly-labeled context (it is
exactly what sub-project #1/`rwscore`'s `DataProtection` dimension already
means) — it is just never the thing that establishes a "confirmed"
correlation.

## B. T1560.001 staging evidence (mechanical addition to `rwevidence`)

Mirrors `T1567.002`'s existing shape exactly — no new observer type, no
new interface:

- New `Technique` constructor in `technique.go` (ID
  `"archive-staging-via-utility"`, `MitreID: "T1560.001"`,
  `RiskClass: adprimitive.RiskNonDestructive` — archiving is reversible,
  matching Clop's actual script, which only zips a decoy file).
- `classifyRansomwareStep`'s technique switch gains `"T1560.001"`
  alongside `"T1490", "T1486", "T1567.002"`.
- `techniqueFor("T1560.001")` returns the new constructor.
- Capability applicability, mirroring `T1567.002`'s own undecided/
  not-applicable split: `DataProtection` is evaluated (via the existing,
  unchanged `DataProtectionLookup`/`FakeDataProtectionLookup` — already
  generic over `AttemptKey.TechniqueID`, so no new Go type is needed, only
  a new captured-key entry at the dispatch call site);
  `Containment`→`notApplicable` ("archiving collected data locally has no
  lateral-reachability dimension to contain", matching `T1490`'s own
  Containment reasoning template); `Prevention`/`Recovery`/`Detection`→
  `undecidedApplicability` (left genuinely undecided, same as
  `T1567.002`'s own unresolved state — not invented here).

## C. `dxcorrelate` — the correlation engine

Pure Go, no DB or HTTP import, decoupled from `rwevidence.Capability`
entirely (its own `Leg` vocabulary — the API-layer adapter, not this
package, knows about MITRE technique IDs):

```go
type Leg string
const (
    LegStaging    Leg = "staging"
    LegTransfer   Leg = "transfer"
    LegEncryption Leg = "encryption"
)

type AttemptRow struct {
    Leg             Leg
    Action          string
    ControlEfficacy ControlEfficacyStatus
    Behavior        BehaviorStatus
    Reason          string
    CreatedAt       time.Time
}

type LegEvidence struct {
    Leg             Leg
    ControlEfficacy ControlEfficacyStatus // the single row contributing this leg's context, if any
    Behavior        BehaviorStatus
    CreatedAt       time.Time             // zero value if no row at all
    Reason          string
}

type Classification string
const (
    ClassificationThreeLegConfirmed                     Classification = "three_leg_confirmed"
    ClassificationExfiltrationConfirmedEncryptionNotEstablished Classification = "exfiltration_confirmed_encryption_not_established"
    ClassificationEncryptionConfirmedExfiltrationNotEstablished Classification = "encryption_confirmed_exfiltration_not_established"
    ClassificationPartialBehaviorEvidence               Classification = "partial_behavior_evidence"
    ClassificationInsufficientBehaviorEvidence          Classification = "insufficient_behavior_evidence"
)

type CorrelationResult struct {
    Legs           []LegEvidence // always exactly 3, fixed order: staging, transfer, encryption
    Classification Classification
    Anomaly        string // non-empty only when an ordering/window/duplicate issue downgraded the classification
}

func Correlate(rows []AttemptRow) CorrelationResult
```

**Deterministic rules** (same input rows always produce the same
`CorrelationResult`):

1. **Leg selection.** For each `Leg`, among `rows` matching it, keep only
   the **earliest** (`CreatedAt` ascending) row whose `Behavior ==
   Occurred` as that leg's qualifying evidence for classification
   purposes; if none has `Occurred`, the leg's `Behavior` is
   `NotEstablished` and its `ControlEfficacy` is taken from the earliest
   row of any kind (or `NoEvidence` if `rows` has none for that leg at
   all). A second or later `Occurred` row for the same leg does not
   change the result — `Anomaly` notes that duplicates existed, but
   duplicate *qualifying* evidence for one leg is not itself a
   disqualifying problem.
2. **Ordering.** A `ClassificationThreeLegConfirmed` or
   `ClassificationExfiltrationConfirmedEncryptionNotEstablished` or
   `ClassificationEncryptionConfirmedExfiltrationNotEstablished` requires
   every leg with `Behavior == Occurred` to appear in `CreatedAt` order
   consistent with the kill-chain narrative (staging ≤ transfer ≤
   encryption, comparing only the legs actually `Occurred`). A violation
   downgrades the result to `ClassificationPartialBehaviorEvidence` with
   `Anomaly` set to `"out-of-order evidence: <detail>"` — evidence that
   doesn't support a coherent sequence is never silently accepted as a
   confirmed one.
3. **Time window.** Two `Occurred` legs more than `MaxCorrelationWindow`
   (a `Correlate`-level constant, default 24h — generous because this is
   simulated/synthetic timing, not real attacker telemetry, and tuning a
   real threshold is explicitly deferred to the real-observer
   sub-project) apart are "temporally unrelated": treated the same as an
   ordering violation — downgrade to `PartialBehaviorEvidence`, `Anomaly`
   set accordingly.
4. **Classification** is computed from `Behavior` alone, across the 3
   legs, after rules 1-3 have been applied:
   - All 3 `Occurred`, in order, in window → `ThreeLegConfirmed`.
   - Staging+Transfer `Occurred` (in order/window), Encryption
     `NotEstablished` → `ExfiltrationConfirmedEncryptionNotEstablished`
     (the IR-without-encryption pattern).
   - Encryption `Occurred`, Staging and/or Transfer `NotEstablished` →
     `EncryptionConfirmedExfiltrationNotEstablished`.
   - Any other mix with at least one `Occurred` (including an
     ordering/window violation) → `PartialBehaviorEvidence`.
   - All 3 `NotEstablished` → `InsufficientBehaviorEvidence` — the
     outcome for every real scenario run today, Clop included, since no
     direct-observation signal exists anywhere yet (see section A).

## D. Raw per-attempt read path

`RWCapabilityCoverage` (`internal/db/rwevidence_store.go:85`) `GROUP
BY`s and `COUNT(*)`s — it discards `action`, `created_at`, `reason`, and
`provenance` entirely, and `rwscore` depends on exactly that aggregated
shape. It is never modified. A new, separate function:

```go
type RWAttemptRow struct {
    TechniqueID    string
    Action         string
    Capability     string
    Verdict        controlval.Verdict
    SkipReason     controlval.SkipReason
    Reason         string
    CreatedAt      time.Time
}

func RWCapabilityAttempts(ctx context.Context, pool *pgxpool.Pool, runID string) ([]RWAttemptRow, error)
```

`SELECT technique_id, action, capability, verdict,
COALESCE(skip_reason,''), reason, created_at FROM rw_capability_results
WHERE run_id = $1 ORDER BY created_at ASC` — no `GROUP BY`, every row
individually preserved, deterministic ordering.

## E. API-layer adapter and endpoint

The adapter (lives in `internal/api`, not in `dxcorrelate` or `internal/db`
— the one place allowed to know both MITRE technique IDs and
`dxcorrelate`'s `Leg` vocabulary) maps `RWAttemptRow` → `dxcorrelate.AttemptRow`:

- `TechniqueID == "T1560.001"`, `Capability == "data_protection"` →
  `Leg: LegStaging`.
- `TechniqueID == "T1567.002"`, `Capability == "data_protection"` →
  `Leg: LegTransfer`.
- No case produces `Leg: LegEncryption` with `Behavior: Occurred` from
  real data today — per section A, there is no accepted direct-behavior
  signal for encryption (or any leg) yet. `T1486` rows for
  `Prevention`/`Detection`/`Containment` are **not** translated into any
  `dxcorrelate.AttemptRow` at all in this sub-project — they remain pure
  control-efficacy evidence inside `rwevidence`'s own existing model,
  outside the correlation engine's input, consistent with "control
  response is not behavior occurrence" applying uniformly. A future
  direct-behavior observer sub-project adds the one adapter case that can
  ever produce `LegEncryption`/`Behavior: Occurred`.
- Every mapped row's `ControlEfficacy` comes straight from
  `Verdict`/`SkipReason` (`PASS`→`Detected`, `FAIL`→`NotDetected`,
  `SKIPPED`/`not_applicable`→`NotApplicable`, anything else→`NoEvidence`);
  `Behavior` is always `NotEstablished` for every row this sub-project's
  adapter produces (no case sets `Occurred` — only a future
  direct-behavior signal would).

`GET /api/scenarios/runs/{runId}/double-extortion-correlation` — `tierAny`
(read-only, no permission gate needed, same precedent as `GET
.../rw-score`): fetches via `RWCapabilityAttempts`, adapts, calls
`Correlate`, returns the `CorrelationResult` as camelCase JSON.

## Acceptance criteria

1. `T1560.001` is recognized by `classifyRansomwareStep`/`techniqueFor`,
   with the same capability-applicability split as `T1567.002`
   (DataProtection evaluated; Containment decided not-applicable;
   Prevention/Recovery/Detection left undecided) — pinned by tests
   mirroring `T1567.002`'s existing test shape.
2. `Correlate` with all 3 legs' `Behavior: Occurred`, in order, in window
   → `ThreeLegConfirmed` (unit test, synthetic rows — this case is not
   reachable from any current real evidence source).
3. `Correlate` with staging+transfer `Occurred`, encryption
   `NotEstablished` → `ExfiltrationConfirmedEncryptionNotEstablished` (unit
   test, synthetic rows).
4. `Correlate` with encryption `Occurred` alone →
   `EncryptionConfirmedExfiltrationNotEstablished` (unit test).
5. `Correlate` with an out-of-order `Occurred` triple (e.g. encryption's
   `CreatedAt` before staging's) → `PartialBehaviorEvidence` with a
   non-empty `Anomaly`, never a `*Confirmed*` classification.
6. `Correlate` with two `Occurred` legs more than the window apart →
   `PartialBehaviorEvidence` with a non-empty `Anomaly`.
7. `Correlate` with duplicate rows for one leg (two `Occurred` rows, same
   `Leg`, different `CreatedAt`) deterministically uses the earliest and
   still reaches the correct classification — same input always produces
   the same result.
8. `Correlate` with zero rows → `InsufficientBehaviorEvidence`, all 3
   `LegEvidence.ControlEfficacy == NoEvidence`.
9. `RWCapabilityAttempts` preserves `action`/`created_at`/`reason` per
   row (round-trip test), unlike `RWCapabilityCoverage`; `RWCapabilityCoverage`
   itself is untouched and its existing tests still pass unmodified.
10. End-to-end against Clop's real dispatch (fake-backed observers wired
    the same way sub-project #1 wired T1486/T1567.002): the endpoint
    reports `Classification: InsufficientBehaviorEvidence` (never a false
    confirmation) **and** `ControlEfficacy: NotDetected` for both
    staging and transfer legs, `ControlEfficacy: NoEvidence` for
    encryption — proving the engine surfaces honest, rich context
    without ever promoting it to an unearned "confirmed" result.
11. `GET .../double-extortion-correlation` for a run with zero relevant
    evidence (e.g. a non-ransomware scenario run) returns 200 with
    `InsufficientBehaviorEvidence` and all-`NoEvidence` legs — not an
    error; absence of relevant techniques is not a failure state.

## Review Focus

- The single easiest mistake to make while implementing this: reintroducing
  a `ControlEfficacy → Behavior` inference "just for staging/transfer,
  since sub-project #1 already accepted that signal." Section A is
  explicit that this is rejected — re-verify no code path ever sets
  `Behavior: Occurred` from a `Verdict` value for any leg.
- The ordering rule (criterion 5) is easy to skip if the implementer
  tests only the "nicely ordered" synthetic case — a reviewer should
  specifically check for a test where `Occurred` rows exist but in the
  wrong `CreatedAt` sequence.
- The time-window rule (criterion 6) is a second, easily-conflated-with-
  ordering rule — a test must exist where rows are in correct order but
  too far apart, distinct from the out-of-order test.
- Criterion 10's Clop test is the one most likely to get accidentally
  "strengthened" into asserting a confirmed classification, since that
  would read as a more satisfying test — the spec's whole point is that
  it must NOT.
