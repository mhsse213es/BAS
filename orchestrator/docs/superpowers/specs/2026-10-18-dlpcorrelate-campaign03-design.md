# dlpcorrelate Campaign 03 (Scenario Differentiation) — Design Spec

## Intent

Closes `dlp.txt` §3C's Campaign 03:

> **Email policy and exception failure.** Send synthetic sensitive content through approved internal and external recipient cases → compare normal delivery, justified override and unauthorized sharing → verify actual mail disposition and policy audit evidence. Tests recipient scoping, policy exceptions and delivery outcomes.

## Why this is a third aggregate shape, not Campaign 01's or Campaign 02's

- Campaign 01's `CorrelationChain` is an ORDERED sequence — a later stage either continues or is gated by an earlier one.
- Campaign 02's `EvaluateChannelConsistency` asks whether N independent channels AGREE with each other (the risk: one channel blocks, another doesn't, for the *same* underlying unauthorized action).
- Campaign 03 asks a different question: does the system correctly DIFFERENTIATE legitimate cases from illegitimate ones? Its 3 named cases don't share one "correct" outcome — normal delivery and a justified override are both SUPPOSED to succeed (one is ordinary business use, the other is an authorized exception), while unauthorized sharing is SUPPOSED to be blocked. A channel-consistency check would be the wrong question here ("do all 3 agree" is nonsensical when 2 are expected to succeed and 1 is expected to fail by design). What matters is whether each case matches its OWN expected direction, and specifically whether failures skew toward **over-blocking** (a legitimate case got blocked — false positive, operational friction, `dlp.txt` Campaign 06's own named concern) or **under-blocking** (the unauthorized case got through — false negative, the real risk).

This is the same underlying question Campaign 06 ("Business continuity versus data protection... measure false positives and operational friction") asks, just applied to a different, smaller named scenario set. This slice's generic core (`EvaluateScenarioDifferentiation`) is written so Campaign 06 can reuse it later as a separate, later wrapper — not built in this slice (named as a future reuse opportunity, not claimed done).

## What already exists and is reused, unmodified

- `internal/reporting/dlp.go`'s live `dlpVerifier` already produces a `reporting.ComparisonResult` (`Match`/`Mismatch`/...) per scenario step, and its `DLPEvidence.Override` field (`OverrideEvidence{Occurred, AuthorizedBy, Reason, AuditRecordID}`) already models "a justified override occurred" as real evidence, not an inferred state — this is the exact evidence shape Campaign 03's "justified override" case needs, with nothing new to build for it.
- `internal/exercise` / EmailGW Mastery's existing run/report pipeline already delivers synthetic content through internal/external recipient paths (feature-complete per the EmailGW Mastery initiative).

## Goals

1. A new, generically-named aggregate in `internal/dlpcorrelate` — `ScenarioCase`/`DifferentiationVerdict`/`ScenarioDifferentiationResult`/`EvaluateScenarioDifferentiation` — that takes N already-computed `(label, expectedToSucceed bool, reporting.ComparisonResult, reason)` cases and produces one of 5 named verdicts: differentiates correctly, over-blocks (a legitimate case failed), under-blocks (an illegitimate case got through), both at once, or no informative evidence.
2. `Campaign03EmailPolicyAndExceptionFailure(normalDelivery, justifiedOverride, unauthorizedSharing ScenarioCase) (ScenarioDifferentiationResult, error)` — the concrete worked example naming exactly the 3 cases `dlp.txt`'s own Campaign 03 text names (`normalDelivery.ExpectedToSucceed`/`justifiedOverride.ExpectedToSucceed` = true, `unauthorizedSharing.ExpectedToSucceed` = false).
3. `EvaluateScenarioDifferentiation` never calls any real evaluator itself (same decoupling discipline as `campaign01.go`/`channelconsistency.go`) — it only consumes already-computed `reporting.ComparisonResult` values.

## Non-goals

- No new scenario YAML, no wiring into the real run/report pipeline — same posture as Campaign 01/02 (evaluator built and proven against fixtures; live wiring is a separate follow-up).
- No Campaign 06 wrapper in this slice — the generic core is written to be reusable by one later, but that wrapper itself is not built here.
- No "policy audit evidence" comparison dimension beyond the existing `OverrideEvidence`/`reporting.ComparisonResult` — `dlp.txt`'s own text's "verify actual mail disposition and policy audit evidence" is closed by reusing what already exists (`DLPEvidence.Override`, `reporting.ComparisonResult`); no new audit-trail evidence source is built.

## Anti-goals

- Must not reuse `CorrelationChain`/`StageResult` (Campaign 01) or `ChannelResult`/`ConsistencyVerdict` (Campaign 02) — a reviewer should see zero shared types between the 3 aggregates beyond living in the same package.
- Must not fold "over-blocking" and "under-blocking" into one verdict — these are different findings with different severity and different remediation paths (a false positive costs productivity; a false negative is a real data-loss risk), matching the project's standing "do not collapse everything into a single pass/fail field" discipline.
- Must not infer `ExpectedToSucceed` from the comparison itself — it is caller-supplied, fixed per case, because it encodes the SCENARIO's own design intent (what SHOULD happen), not something derivable from what WAS observed.

## What's left to the builder

- Exact Go error-wrapping/validation message text.
- Exact test fixture values (case labels, reasons).
