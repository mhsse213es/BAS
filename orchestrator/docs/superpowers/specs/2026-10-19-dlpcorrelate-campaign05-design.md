# dlpcorrelate Campaign 05 (Detection-to-Response Validation) — Design Spec

## Intent

Closes `dlp.txt` §3C's Campaign 05:

> **Detection-to-response validation.** Generate a controlled policy violation → verify the event reaches the DLP console → verify SIEM ingestion → confirm incident creation and assignment → measure acknowledgment and response. Separates preventive control efficacy from the organization's ability to detect and handle an incident.

## Why this is Campaign 01's ordered-chain shape, with different stop semantics

The 5 clauses are strictly ordered: the console event only matters once a violation was generated and enforced, SIEM ingestion only once a console event exists, and so on. That is `CorrelationChain`'s shape, reused from `chain.go`.

The stop semantics are NOT Campaign 01's. In Campaign 01, a `Match` on enforcement means the attack was stopped, so the chain halts. Campaign 05 asks whether the organization can DETECT and HANDLE the violation, so a successful prevention must not halt the chain. Downstream stages must still be verified after a block. Therefore Campaign 05 gets its own translation function, `verificationStageOutcome`, and does NOT reuse `enforcementOutcome`. Reusing it would silently halt the chain on `Match`, which is the wrong semantics here.

## Stage mapping

| # | Label | Dimension | Input | Mapping |
|---|-------|-----------|-------|---------|
| 1 | controlled policy violation enforced as expected | DLP-ENF | `EnforcementComparison` | Match → Continues; Mismatch → Failed; MissingEvidence/NotApplicable/Unknown → Inconclusive |
| 2 | event reaches DLP console | DLP-TEL | `ConsoleComparison` | Match → Continues; Mismatch → Failed; MissingEvidence/NotApplicable/Unknown → Inconclusive |
| 3 | SIEM ingestion verified | DLP-TEL | `SIEMVerdict` (`detectverify.VerdictDetected`/`VerdictNotDetected`) | Detected → Continues; NotDetected → Inconclusive; anything else → Inconclusive |
| 4 | incident creation confirmed | DLP-RESP | `TicketAttempted`, `TicketID` | not attempted → Inconclusive; attempted with empty ID → Failed; attempted with non-empty ID → Continues |
| 5 | incident assignment confirmed | DLP-RESP | none | permanently StageNotTested (see below) |
| 6 | acknowledgment and response measured | DLP-RESP | none | permanently StageNotTested (see below) |

**Why NotDetected is Inconclusive, not Failed:** `dlp.txt` §6 says an absent alert "might instead reflect delayed ingestion, a missing connector, incorrect event correlation or a genuine detection gap," and Audspect "must distinguish these possibilities before issuing a definitive finding." A SIEM-window miss is absence evidence, not a confirmed failure. The same reasoning applies to the console (MissingEvidence → Inconclusive).

**Why Failed is non-stopping:** a confirmed failure is recorded and the chain continues, as in `chain.go`. A `Mismatch` at enforcement does not make the console or ticket stages meaningless.

**Why stages 5 and 6 are permanent gaps:** `ticketing.TicketRef` carries only `TicketID` and `TicketURL`. It has no assignee field. `ticketing.Connector.GetStatus` returns a raw provider status string with no acknowledgment timestamp or response-time concept. Assignment and response time therefore cannot be evaluated without new `internal/ticketing` features. These stages are skip-filled as `StageNotTested` by `EvaluateCorrelationChain`, consistent with Campaign 01's stage 4. Consequence: `AnyNotTested` is always true for this campaign, so a clean run never reports as fully passing.

## Reuse and decoupling

- `chain.go`: `CorrelationChain`, `StageDefinition`, `StageResult`, `EvaluateCorrelationChain`, `StageOutcome` — reused unmodified.
- `detectverify.VerdictDetected`/`VerdictNotDetected` — string constants, type-only consumption.
- `reporting.ComparisonResult` — type-only consumption, same as Campaigns 01/04.
- `ticketing` is NOT imported. Ticket evidence is passed as two primitives (`TicketAttempted bool`, `TicketID string`) to keep `dlpcorrelate` free of `ticketing`'s database dependency.
- The campaign never calls `detectverify` or `ticketing` functions itself. It consumes already-computed values only.

## Goals

1. `Campaign05DetectionToResponse` — package-level `CorrelationChain` with the 6 stages above.
2. `Campaign05Evidence` — input struct: `EnforcementComparison reporting.ComparisonResult`, `EnforcementReason string`, `ConsoleComparison reporting.ComparisonResult`, `ConsoleReason string`, `SIEMVerdict string`, `TicketAttempted bool`, `TicketID string`.
3. `EvaluateCampaign05(ev Campaign05Evidence) (ChainResult, error)` — builds `reached` one stage at a time, early-returns when a stage's outcome `.stops()`, and never builds stages 5 or 6.
4. `verificationStageOutcome(reporting.ComparisonResult) StageOutcome` — the Match-continues translation, distinct from `enforcementOutcome`.

## Non-goals

- No new `internal/ticketing` features (assignee tracking, ack timestamps). Named as the gap that keeps stages 5/6 NotTested.
- No wiring into the real run or report pipeline. No new scenario YAML.
- No change to `chain.go`, `campaign01.go`, `campaign04.go`, or `detectverify`/`ticketing`.

## Anti-goals

- Must not reuse `enforcementOutcome` for stage 1. Its `Match → StageCaught` would halt the chain on a successful block, which is the wrong semantics for this campaign.
- Must not treat `NotDetected` as `StageFailed`. That would be a definitive finding from absence evidence, which §6 forbids.
- Must not fabricate assignee or response-time evidence to fill stages 5 or 6.
- Must not import `ticketing`.
