# dlpcorrelate Campaign 02 (Channel Consistency) — Design Spec

## Intent

`dlp.txt` §3C names 6 cross-channel campaigns; Campaign 01 (ordered chain: classify → label-persist → enforce → [permanently-gapped] evidence) is already built in `internal/dlpcorrelate`. This closes Campaign 02:

> **Endpoint-to-cloud leakage.** Place a synthetic confidential file on a managed endpoint → validate local policy → attempt controlled USB, browser upload and approved-cloud transfer variants → compare enforcement and telemetry. Tests channel consistency without assuming one successful block protects every channel.

## Why Campaign 01's chain model doesn't fit

Campaign 01 is a *sequence*: each stage either lets the data keep moving or stops the chain, and a later stage's pass never erases an earlier stage's confirmed failure. Campaign 02 is explicitly NOT a sequence — its own text says "without assuming one successful block protects every channel," i.e. the 3 channel variants (USB, browser upload, approved-cloud transfer) are independently exercised and compared SIDE BY SIDE, not ordered. The finding that matters here is disagreement between channels (one blocked, another not) — a `CorrelationChain`'s single chain-stop model has no way to express that; it would force an artificial ordering onto 3 things that have none. This needs a second, genuinely different aggregate shape inside the same package.

## What already exists and is reused, unmodified

- `internal/reporting/dlp.go`'s live `dlpVerifier` already produces, per scenario step, a `VerificationResult` whose `.Comparison` field is a `reporting.ComparisonResult` (`Match`/`Mismatch`/`MissingEvidence`/...) and whose `.DLPEvidence.Channel` names the operation path (`"browser"|"native-app"|"sync-client"|"api"|""`) — this is ALREADY the per-channel enforcement signal Campaign 02 needs; nothing new has to be built to produce it.
- The existing local DLP Validation Suite (USB/clipboard/print/archive/local-staging — see `internal/dlpfixture/catalog.go`'s `scenarioValidation`/`scenarioMultichannel` entries and `internal/exercise/templates.go`'s DLP Exfiltration Purple Team Drill) already exercises a USB-channel variant against this same live verifier.
- `internal/vendors/cloudsink` (approved-cloud-transfer destinations) and `internal/vendors/webhooksink`-shaped browser-upload scenario content already exist from earlier DLP Mastery work.

## Goals

1. A new, generically-named aggregate in `internal/dlpcorrelate` — `ChannelResult`/`ChannelConsistencyResult`/`ConsistencyVerdict`/`EvaluateChannelConsistency` — that takes N already-computed `(channel, reporting.ComparisonResult, reason)` triples and produces one of 4 named verdicts: enforcement was consistently correct across all informative channels, consistently absent across all of them (a uniform gap, not a channel-specific one), inconsistent (the real risk this campaign names — some channels enforce, others don't), or there was no informative evidence at all to judge consistency by.
2. `Campaign02EndpointToCloudLeakage(usb, browserUpload, cloudTransfer ChannelResult) (ChannelConsistencyResult, error)` — the concrete worked example naming exactly the 3 channel variants `dlp.txt`'s own Campaign 02 text names, wired to `EvaluateChannelConsistency`.
3. `EvaluateChannelConsistency` never calls any real evaluator itself (same decoupling discipline as `EvaluateCampaign01`) — it only consumes already-computed `reporting.ComparisonResult` values the caller obtained from the existing live `dlpVerifier` pipeline per scenario step.

## Non-goals

- No new scenario YAML in this slice — wiring 3 real scenario steps' live verification results into `Campaign02EndpointToCloudLeakage` at run time is a separate, later integration task (same posture Campaign 01 took: the evaluator exists and is proven against fixtures; wiring it into the actual run/report pipeline is named as a follow-up, not silently claimed done here).
- No new "telemetry" comparison dimension — `dlp.txt`'s own Campaign 02 text says "compare enforcement and telemetry," but no telemetry-correlation evidence source exists in this repo yet (same honestly-named gap as Campaign 01's permanently-`StageNotTested` stage 4); this slice closes the enforcement-consistency half only, and that gap is named in `docs/dlp-mastery-qa-log.md`.
- Campaigns 03-06 remain untouched, named gaps.

## Anti-goals

- Must not force Campaign 02 through `CorrelationChain`/`EvaluateCorrelationChain` — see "Why Campaign 01's chain model doesn't fit" above. A reviewer should be able to see, by reading `channelconsistency.go`, that this is a deliberately separate aggregate, not a workaround.
- Must not silently default an all-`MissingEvidence` input to "consistent" (a false claim of safety) — it must resolve to its own distinct `InsufficientEvidence` verdict.
- Must not collapse "all channels uniformly fail to enforce" and "channels disagree with each other" into the same verdict — these are different findings with different remediation paths (a global policy gap vs. a channel-specific one), matching the project's standing "do not collapse everything into a single pass/fail field" discipline already followed in `avefficacy`/Campaign 01.

## What's left to the builder

- Exact Go error-wrapping/validation message text.
- Exact test fixture values (channel names, reasons) — any 3 distinct, readable channel-name strings matching `dlp.txt`'s own vocabulary (USB, browser upload, approved-cloud transfer).
