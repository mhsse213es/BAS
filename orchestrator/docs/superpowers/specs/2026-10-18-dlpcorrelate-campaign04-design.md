# dlpcorrelate Campaign 04 (Departing Employee Data Exposure) — Design Spec

## Intent

Closes `dlp.txt` §3C's Campaign 04:

> **Departing employee data exposure.** Use a dedicated test identity with realistic but synthetic access → access a seeded business dataset → exercise authorized export and controlled external-sharing cases → correlate identity, data, channel and alerts. Tests the combination of DLP, identity permissions and investigation—not an unsupported claim that DLP alone prevents insider risk.

## Why this reuses Campaign 01's ordered-chain shape, not Campaign 02's or 03's

Re-reading the text's own structure against Campaign 01's ("Seed synthetic customer records → classify the data → move it through a supported document workflow → attempt an unauthorized external share → verify enforcement → verify the security event and case evidence"): "use a dedicated test identity with realistic but synthetic access" is SETUP — it describes which actor runs the scenario, not an evaluated stage with its own pass/fail, exactly parallel to Campaign 01's own "Seed synthetic customer records" setup clause. The 3 actually-EVALUATED stages are: access the seeded dataset (a classification/visibility question), exercise export/external-sharing (an enforcement question), and correlate identity/data/channel/alerts (an investigation question). These are STRICTLY ORDERED — correlating alerts only makes sense after an export was attempted, which only makes sense after the dataset was accessed — so this is genuinely Campaign 01's `CorrelationChain`/`EvaluateCorrelationChain` shape, reused directly, not a new aggregate.

## What already exists and is reused, unmodified

- `internal/dlpcorrelate/chain.go`'s `CorrelationChain`/`EvaluateCorrelationChain` (Campaign 01's own core) — reused as-is, zero changes.
- `internal/dlpcorrelate/campaign01.go`'s already-defined, package-private `classificationOutcome(dlpclassify.DLPCLSOutcome) StageOutcome` and `enforcementOutcome(reporting.ComparisonResult) StageOutcome` helper functions — reused directly (same package, same translation rules apply identically: this campaign's 2 real stages ask the exact same "did classification work" / "did enforcement catch the unauthorized action" questions Campaign 01's stages 1 and 3 already ask, just against a different scenario narrative).
- `internal/dlpclassify`'s `DLPCLSVerdict`/`DLPCLSOutcome` and `internal/reporting`'s `ComparisonResult` types — same decoupled consumption as Campaign 01 (this package never calls either evaluator itself).

## No identity/access-permission evaluator exists — named as the stage-1 precondition, not fabricated as its own stage

`dlp.txt`'s own text names "identity permissions" as part of what this campaign tests. No RBAC/IAM access-boundary evaluator exists anywhere in this repo capable of verifying a synthetic identity's permission scope was correctly enforced (confirmed by repo search, 2026-10-18 — no `internal/actoridentity`/RBAC-boundary package exists for this purpose; the existing actor-identity/RBAC work in this repo concerns run attribution and platform access control, not data-access-boundary testing for a DLP insider-risk scenario). Rather than inventing a stage for this, the test identity's scope is treated as a property of how the scenario itself is authored (which synthetic account the simulation runs as) — exactly how Campaign 01 treats "seed synthetic customer records" as scenario content, not an evaluated stage. This is named here explicitly so a future reader does not mistake the absence of an identity-permission STAGE for an oversight.

## Goals

1. `Campaign04DepartingEmployeeDataExposure` — a package-level `CorrelationChain` value with 3 named stages: (1) "access seeded business dataset via scoped test identity" (Dimension `"DLP-CLS"`), (2) "exercise authorized export and controlled external-sharing cases" (Dimension `"DLP-ENF"`), (3) "correlate identity, data, channel and alerts" (Dimension `""`, permanently `StageNotTested` — the same telemetry/SIEM-correlation gap already named in `docs/dlp-mastery-qa-log.md` item 6).
2. `EvaluateCampaign04(classVerdict dlpclassify.DLPCLSVerdict, enfComparison reporting.ComparisonResult, enfReason string) (ChainResult, error)` — translates 2 already-computed verdicts using the EXISTING `classificationOutcome`/`enforcementOutcome` helpers, builds `reached` stopping early if stage 1's outcome `.stops()` (same early-return discipline `EvaluateCampaign01` already established and had to fix once), and calls `EvaluateCorrelationChain`.

## Non-goals

- No new scenario YAML, no wiring into the real run/report pipeline.
- No new identity/access-permission evaluator — explicitly named as a precondition-of-authorship, not a gap this slice closes or claims to close.
- No duplicate copy of `classificationOutcome`/`enforcementOutcome` — this slice reuses Campaign 01's existing private functions rather than redefining equivalent logic, since both campaigns ask the identical 2 translation questions.

## Anti-goals

- Must not invent a 4th "identity permission" stage with a fabricated evaluator behind it — see the dedicated section above.
- Must not duplicate `classificationOutcome`/`enforcementOutcome`'s logic under new names — reuse the existing functions directly; a reviewer should see zero new translation logic for the 2 real stages, only new STAGE LABELS and a new chain definition.

## What's left to the builder

- Exact Go error-wrapping message text (none expected beyond what `EvaluateCorrelationChain` itself already returns).
- Exact test fixture values (stage labels already fixed above).
