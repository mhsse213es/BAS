# WAF BAS Mastery Phase 8: Detection and Telemetry Validation — Design Spec

## 1. Scope

Per `waf.txt` lines 167-170, Phase 8 is: **"Detection and telemetry validation — Correlate test IDs with WAF events, SIEM records, alerts, response timing, and evidence loss."**

Unlike every prior phase (2-7), Phase 8 is not about whether an attack was blocked — it is about whether the **evidence pipeline itself** is trustworthy: can a test's `CorrelationKey` actually be traced through to WAF logs, SIEM records, and alerts, within an acceptable time, without silent evidence loss. The claim shape is orthogonal to any specific attack vector, so this phase does **not** cross-reference `wafcatalog` at all — it operates on bare `wafval.CorrelationKey`/`CollectionResult`/`Verdict` values, generic over whatever attack produced them.

New package: `orchestrator/internal/wafdetection`.

The five named items map 1:1 onto three evaluation shapes and five seed scenarios:

| Named item | Shape | Seed ID |
|---|---|---|
| WAF events | channel completeness | WAFDETECT-001 |
| SIEM records | channel completeness | WAFDETECT-002 |
| evidence loss (retention/archival) | channel completeness | WAFDETECT-005 |
| alerts | alert correlation | WAFDETECT-003 |
| response timing | timing SLA | WAFDETECT-004 |

## 2. Dependency

`wafdetection` depends on `internal/wafval` only (`CollectionResult`, `Coverage`, `Verdict`, `VerdictBlocked`, `VerdictDetectedButAllowed`) plus stdlib `fmt`/`time`. It does not depend on `wafcatalog`, `wafpolicygap`, `wafevasion`, `wafapiflow`, `wafbotabuse`, or `waforigin`, and none of those depend on it either. This is the first WAF-mastery phase since `wafval` itself that evaluates evidence-pipeline health rather than a specific attack claim, so no catalog cross-reference exists to validate against — there is no vector-ID mismatch guard anywhere in this package, unlike every prior phase.

## 3. Distinctness from existing phases

- **vs. `wafval`'s own `Coverage`/`EvidenceCompleteness`:** this phase does not add a new coverage concept — `EvaluateCompleteness` (§5.1) is a thin, named wrapper over `wafval.Coverage.Present()` for a specific caller-identified channel, giving each of the three named "events/records/evidence-loss" items its own scenario identity and reason text, not a new verdict-derivation rule.
- **vs. `waforigin`'s cross-node consistency (Phase 7):** that compares two *nodes'* independently-derived verdicts for the *same attack*. This phase's channel-completeness check compares nothing — it asks whether *one* channel's search for *one* correlation key found anything at all, lost or not.
- **vs. every attack-vector phase (2, 5, 6, 7):** those all answer "was this malicious request blocked." This phase never asks that question — `EvaluateAlertCorrelation` (§5.2) takes an already-computed `wafval.Verdict` as a bare input (computed elsewhere, by whatever claim-evaluation phase produced it) and asks only whether the alerting pipeline correctly reflected it, decoupling this phase entirely from how that verdict was derived.

## 4. Types

### 4.1 Channel completeness

```go
type EvidenceChannel string
const (
    ChannelWAFEventLog     EvidenceChannel = "waf_event_log"
    ChannelSIEMRecord      EvidenceChannel = "siem_record"
    ChannelAlertQueue      EvidenceChannel = "alert_queue"
    ChannelEvidenceArchive EvidenceChannel = "evidence_archive"
)

type CompletenessScenario struct {
    ID          string
    Channel     EvidenceChannel
    Description string
    Provenance  string
}
func NewCompletenessScenario(id string, channel EvidenceChannel, description string, provenance string) (CompletenessScenario, error)
```
Validation: `id` non-empty; `channel` one of the four known constants; `description` non-empty; `provenance` non-empty.

```go
type CompletenessVerdict string
const (
    EvidencePresent      CompletenessVerdict = "present"
    EvidenceLost         CompletenessVerdict = "lost"
    EvidenceInconclusive CompletenessVerdict = "inconclusive"
)
```

### 4.2 Alert correlation

```go
type AlertScenario struct {
    ID          string
    Description string
    Provenance  string
}
func NewAlertScenario(id string, description string, provenance string) (AlertScenario, error)
```
Validation: `id`/`description`/`provenance` all non-empty.

```go
type AlertVerdict string
const (
    AlertCorrect      AlertVerdict = "correct"
    AlertMissing      AlertVerdict = "missing"
    AlertSpurious     AlertVerdict = "spurious"
    AlertInconclusive AlertVerdict = "inconclusive"
)
```

### 4.3 Response timing

```go
type TimingScenario struct {
    ID          string
    SLA         time.Duration
    Description string
    Provenance  string
}
func NewTimingScenario(id string, sla time.Duration, description string, provenance string) (TimingScenario, error)
```
Validation: `id`/`description`/`provenance` non-empty; `sla` must be `> 0`.

```go
type TimingVerdict string
const (
    TimingWithinSLA    TimingVerdict = "within_sla"
    TimingSLABreached  TimingVerdict = "sla_breached"
    TimingInconclusive TimingVerdict = "inconclusive"
)
```

## 5. Evaluation

### 5.1 `EvaluateCompleteness`

```go
func EvaluateCompleteness(scenario CompletenessScenario, result wafval.CollectionResult) (CompletenessVerdict, string, error)
```
No evidence found at all (`len(result.Observations) == 0` and `result.Coverage` is zero-value) is treated the same as any other non-present coverage. Logic: if `result.Coverage.Present()` → `EvidencePresent`; else if `result.Coverage == wafval.CoverageSearchedVerifiedNone` → `EvidencePresent` is wrong here since `Present()` already returns true for `CoverageSearchedVerifiedNone` (confirmed against `wafval.Coverage.Present()`'s real definition: `CoverageFound || CoverageSearchedVerifiedNone`) — so the only two remaining `Coverage` values are `CoverageSearchIncomplete` and `CoverageSourceUnavailable`, both of which mean the channel could not establish anything either way: return `EvidenceLost, "<channel> search could not establish whether evidence exists (incomplete search or source unavailable)"`. A genuinely empty/zero-value `CollectionResult` (caller passed nothing) also falls through to `EvidenceLost` via the same `!Present()` branch — there is no separate `EvidenceInconclusive` path in this function; `EvidenceInconclusive` exists as a `CompletenessVerdict` constant for symmetry with the other two verdict enums but `EvaluateCompleteness` itself always resolves to `EvidencePresent` or `EvidenceLost` given `wafval.Coverage`'s four closed values — this is a deliberate design note, not an oversight (Task 2's acceptance test confirms both of `EvaluateCompleteness`'s two real outcomes, not a third that cannot occur).

### 5.2 `EvaluateAlertCorrelation`

```go
func alertWarranted(v wafval.Verdict) bool {
    return v == wafval.VerdictBlocked || v == wafval.VerdictDetectedButAllowed
}

func EvaluateAlertCorrelation(underlyingVerdict wafval.Verdict, alertEvidence wafval.CollectionResult) (AlertVerdict, string, error)
```
`underlyingVerdict` is the already-computed verdict of whatever claim this alert is supposed to reflect (produced elsewhere, by any attack-claim-evaluating phase — this function takes the bare `wafval.Verdict` value, never re-derives it). Logic:
- `warranted := alertWarranted(underlyingVerdict)`; `hasAlert := alertEvidence.Coverage == wafval.CoverageFound && len(alertEvidence.Observations) > 0`; `verifiedAbsent := alertEvidence.Coverage == wafval.CoverageSearchedVerifiedNone`.
- `warranted && hasAlert` → `AlertCorrect, "alert correctly generated for a detected/blocked request"`.
- `warranted && verifiedAbsent` → `AlertMissing, "request was blocked/detected but no alert was found despite a verified-complete search"`.
- `warranted && !hasAlert && !verifiedAbsent` (search incomplete/unavailable) → `AlertInconclusive, "alert-channel search was incomplete or unavailable; cannot confirm whether an alert exists"`.
- `!warranted && hasAlert` → `AlertSpurious, "an alert was generated for a request that was neither blocked nor detected"`.
- `!warranted && !hasAlert` (regardless of search completeness — nothing was expected either way) → `AlertCorrect, "no alert generated, correctly, for a request that did not warrant one"`.

### 5.3 `EvaluateResponseTiming`

```go
func EvaluateResponseTiming(scenario TimingScenario, eventObservedAt, alertObservedAt time.Time) (TimingVerdict, string, error)
```
If either timestamp is the zero `time.Time` value, or `alertObservedAt` is before `eventObservedAt` (nonsensical ordering — the alert cannot precede the event it is about), return `TimingInconclusive, "..."`. Otherwise `latency := alertObservedAt.Sub(eventObservedAt)`; `latency <= scenario.SLA` → `TimingWithinSLA`; else `TimingSLABreached`.

## 6. Seed catalog

| ID | Shape | Parameters | Story |
|---|---|---|---|
| WAFDETECT-001 | completeness | `ChannelWAFEventLog` | A test execution's `CorrelationKey` must resolve to a findable WAF-engine event-log record. |
| WAFDETECT-002 | completeness | `ChannelSIEMRecord` | The same correlation key must resolve to a findable SIEM-ingested record (an independent corroborating source). |
| WAFDETECT-003 | alert | — | A blocked or detected-but-allowed request must produce a queryable alert; an allowed-and-undetected request must not spuriously produce one. |
| WAFDETECT-004 | timing | `SLA: 5 * time.Minute` | An alert must surface within 5 minutes of the triggering event, a representative SOC response-time target. |
| WAFDETECT-005 | completeness | `ChannelEvidenceArchive` | Evidence already confirmed present at collection time must still be retrievable from long-term archival storage, not lost to log rotation or a retention-policy gap. |

## 7. Acceptance gate

1. `NewCompletenessScenario` rejects empty ID/description/provenance and an unknown `EvidenceChannel`.
2. `EvaluateCompleteness` returns `EvidencePresent` for `CoverageFound` and `CoverageSearchedVerifiedNone`; returns `EvidenceLost` for `CoverageSearchIncomplete`, `CoverageSourceUnavailable`, and the zero-value `CollectionResult`.
3. `NewAlertScenario` rejects empty ID/description/provenance.
4. `EvaluateAlertCorrelation` returns `AlertCorrect` when warranted+present or not-warranted+absent; `AlertMissing` when warranted+verified-absent; `AlertSpurious` when not-warranted+present; `AlertInconclusive` when warranted+search-incomplete.
5. `NewTimingScenario` rejects empty ID/description/provenance and `sla <= 0`.
6. `EvaluateResponseTiming` returns `TimingInconclusive` for a zero timestamp or `alertObservedAt` before `eventObservedAt`; `TimingWithinSLA` when latency `<= SLA`; `TimingSLABreached` when latency `> SLA`.
7. All 5 seed scenarios construct without error, one per row of §6's table.

## 8. Deferred (explicitly, per standing fixture-backed discipline)

- Real WAF/SIEM/alert-queue log collection — every scenario here evaluates caller-supplied `wafval.CollectionResult`/timestamp evidence, never queries a live system.
- Any dependency on `wafcatalog` or a specific attack-vector cross-reference — this phase is deliberately attack-agnostic.
- Expanding the seed catalog beyond 1 scenario per named item.
- Any new `wafval` verdict-derivation logic — `EvaluateCompleteness` only reads `wafval.Coverage.Present()`'s existing result; `EvaluateAlertCorrelation` takes an already-derived `wafval.Verdict` as a bare input and never re-derives one; `EvaluateResponseTiming` does plain `time.Duration` arithmetic.
