# EmailGW Mastery: Campaign → Stage → Expectation → Evidence Execution Design

**Date:** 2026-10-16
**Status:** Design, immediately followed by implementation of the BEC vertical slice in this same pass.

## 0. Why this document exists

EG-001 through EG-010 are individual control-validation checks (Level 3 "expectations" in the hierarchy below), not complete attack simulations. Real enterprise email attacks (business email compromise, credential phishing, malware delivery, data exfiltration) cross several controls in one coherent narrative. This document designs the execution model for **campaigns** — ordered, conditionally-gated sequences of real stages, each stage itself one (or a read of an already-collected) `emailgwefficacy.EfficacyResult` — and proves it with one real vertical slice: a Business Email Compromise (BEC) supplier-payment-fraud campaign.

**Explicit correction carried into this design, per direction:** do not assume EG-002/EG-005/EG-008/EG-010 are "real and wired" merely because they appear in the catalogue or in prior session notes. Each claim below is re-verified against the current source, not against memory of an earlier session. See §0.1.

### 0.1 Ground truth, re-verified against current source (not assumed)

| Claim | Verified how | Result |
|---|---|---|
| `ExecutiveImpersonationExpectation(true/false)` (EG-002) sets `EnvelopeFrom` for both directions | Read `internal/emailgwefficacy/scenarios.go` directly, this pass | **True** — both directions wired for real SMTP injection |
| `SupplierPaymentDiversionExpectation(true/false)` (EG-005) sets `EnvelopeFrom` for both directions | Same | **True** — both directions wired |
| `PostDeliveryThreatResponseExpectation()` (EG-008/EG-010) sets `EnvelopeFrom` | Same | **True** — wired |
| These scenarios have ever executed against a real customer M365 tenant | Read `docs/emailgw-mastery-qa-log.md` item 1b | **False.** Tenant provisioning/licensing is open, blocked on account access, not an engineering gap. Every "real" execution anywhere in this initiative (including this design's own BEC proof) is proven against `httptest`/a local SMTP test server/real Postgres — never a genuine production Defender tenant. |
| `caught=true` is the "attack is expected to be caught" direction for EG-002/EG-005 | Read each function's own doc comment | **True**, and this matters for the campaign design below: `caught=true` → `ExpectedAction=ExpectedQuarantine` is the direction whose `VerdictDetail` actually answers "did the relevant control catch this," which is what a campaign's gate needs to reason about. `caught=false` declares the opposite expectation (`ExpectedDeliver`) against the *same wire message* — a different declared prediction, not a different attack. |

**What this means for the campaign design:** "executable" below means *code-complete, tested against fixtures/httptest/a local SMTP server/real Postgres, and wired into the real `ExecuteEmailGWRun` persistence path*. It does **not** mean "has ever produced a real customer verdict." The campaign layer must work correctly in exactly the same mode every other real vertical in this initiative works in — `emailgwProvider` may be `nil` (unconfigured), and the campaign trigger path must refuse clearly (503), never fabricate a result.

## 1. The three-level hierarchy, and where it already exists

| Level | Name | Already exists? | Where |
|---|---|---|---|
| 1 | Campaign | **No — this document builds it.** | `internal/emailgwcampaign` (new), orchestration in `internal/api` (new) |
| 2 | Stage / variant | Approximately, unnamed | The expectation-ID granularity (`"EG-002.known-good"`, etc.), resolved today via `emailgwefficacy.ExpectationByID` |
| 3 | Expectation / evidence | Fully exists | `MailExpectation`, `EfficacyResult` (independently-scored `Prevention`/`DetectionVerdict`/`ResponseVerdict`), `VerifyMailExpectation` |

EG-001–EG-010 map onto this hierarchy as: EG-001–EG-009 are each a Level-2 bundle of 2 Level-3 expectation IDs (mostly known-good/known-bad pairs); EG-010 is a Level-2 concept observing two dimensions of one Level-3 expectation. None of the existing ten belong at Level 1 — they were never designed as multi-stage narratives, and this document does not retroactively force them into one. The EG-001–EG-010 → Level-2/3 mapping itself is deferred to the end of this pass (§8), after the campaign model is proven, per explicit direction: the sequential orchestration model is the foundational risk, not the mapping.

## 2. Rejected alternative: reusing `internal/exercise`'s `PlanStep`/`StepExecution` engine

`internal/exercise` already has a generic, DB-persisted, restart-safe, conditionally-gated multi-step executor: `PlanStep.DependsOn`/`Condition` (`"step:{id}:clicked"` etc.), `StepStatus` (including `StepSkipped` — the exact "never fabricate a downstream result" semantics this design needs), `StepExecution` rows polled and advanced by a running executor (`exExecutor.Start()`, already live in `main.go`). This is the right *shape*. It is not reusable here:

- **Hard import cycle.** `internal/emailgwefficacy` already imports `internal/exercise` (for `SpoofableSMTPInjector`, wired in `injection.go`). For `internal/exercise`'s own executor to evaluate a condition against a real `VerdictDetail`, it would need to import `internal/emailgwefficacy` back — a direct, unconditional bidirectional cycle, not the test-only cycle `internal/emailgwrun`'s executor placement already worked around. Breaking this would mean extracting `SpoofableSMTPInjector` out of `internal/exercise` into a new dependency-free package — a real, defensible refactor, but one that touches a large, already-in-production, unrelated subsystem (live human-phishing-awareness exercises, its own scoring model, its own template library, polled every 5s by `exExecutor`) for a benefit (shared DAG plumbing) this initiative does not need at its current, much smaller scale.
- **Wrong domain vocabulary.** `exercise`'s own `Condition` grammar (`clicked`/`reported`/`timeout`) and `ExerciseScore` (`HumanScore`/`ClickRate`/`ReportRate`) are phishing-awareness concepts — did a *human* click, not whether a *gateway control* produced a `VerdictDetail`. Reusing the engine would mean extending its condition grammar and step types with gateway-specific concepts for a different package's own object model, inside a shared component many other features depend on.

**Decision:** build a new, small, self-contained sequencer, borrowing `internal/exercise`'s *proven semantic discipline* (dependency + condition-gated steps, an explicit non-fabricating blocked/skipped status, DB-persisted restart-safe state) without touching `internal/exercise` itself. This matches this initiative's own established pattern (every phase has been a small, additive, self-contained package; precedent elsewhere in this codebase — e.g. the AD Mastery initiative's own explicit decision not to touch `dispatchRun` — is to build alongside shared infrastructure, not inside it, when the scale doesn't justify the shared risk).

## 3. Campaign and stage model

```go
// package internal/emailgwcampaign — pure types + static templates,
// mirrors internal/emailgwrun's own role (types only; orchestration
// logic lives in internal/api for the same import-cycle reason
// internal/emailgwrun's executor does).

type StageKind string
const (
	// StageKindInjected dispatches a real email_gw_runs row via the
	// existing ExecuteEmailGWRun -- a real SMTP send, a real dwell
	// window, a real VerifyMailExpectation call.
	StageKindInjected StageKind = "injected"
	// StageKindDerived never sends anything new. It reads a dimension
	// of an EARLIER stage's own already-collected EfficacyResult --
	// Prevention/Detection/Response are already three independent
	// dimensions of ONE verified message (VerifyMailExpectation's own
	// design); a derived stage exists so the campaign's own evidence
	// trail names "the detection check" and "the response check" as
	// their own stage-level outcomes, without sending a second,
	// redundant message whose identity would otherwise differ from
	// the fraud message the campaign is actually validating.
	StageKindDerived StageKind = "derived"
)

type Dimension string
const (
	DimensionPrevention Dimension = "prevention"
	DimensionDetection  Dimension = "detection"
	DimensionResponse   Dimension = "response"
)

// GateCondition decides, from an upstream stage's own real recorded
// VerdictDetail (never a different stage's, never an invented one),
// whether a downstream stage is permitted to dispatch. PermittedVerdicts
// is the ONLY mechanism that allows progression -- anything else
// (a different confirmed verdict, Inconclusive, or the upstream stage
// never having run at all) produces StageBlockedByPrerequisite, each
// with its own distinct recorded reason (see §4).
type GateCondition struct {
	UpstreamStageKey  string
	UpstreamDimension Dimension
	PermittedVerdicts []emailgwefficacy.EmailGWVerdict
}

type StageTemplate struct {
	Key               string
	Label             string
	Kind              StageKind
	ExpectationID     string    // StageKindInjected only
	ReadsFromStageKey string    // StageKindDerived only
	ReadsDimension    Dimension // StageKindDerived only
	// Gate is nil for a campaign's first stage (nothing to gate on).
	Gate *GateCondition
}

type CampaignTemplate struct {
	ID     string // e.g. "bec-supplier-fraud"
	Name   string
	Stages []StageTemplate // ordered; ordinal = index
}
```

Templates are static Go functions returning a `CampaignTemplate`, same convention as `EmailGWScenarioRegistry()` — not DB-authored, not user-editable in this pass. `BECSupplierFraudTemplate()` is the one built this pass (§7).

## 4. Sequential dispatch and blocked-stage semantics

A stage is dispatched only after its upstream stage's **actual recorded** `VerdictDetail` for the gate's named dimension is evaluated against `PermittedVerdicts`. Three real outcomes, evaluated as three **explicitly distinct branches**, not one undifferentiated check — per direction, a confirmed block, an inconclusive result, and a never-executed upstream stage must not collapse into the same reasoning path, even where two of them land on the same final stored status:

| Upstream condition | Transition | Stored stage status | Recorded reason (example) |
|---|---|---|---|
| Upstream verdict ∈ `PermittedVerdicts` | **Proceed** — dispatch this stage for real | `pending` → `dispatched` | — |
| Upstream verdict is a confirmed, non-permitted verdict | Block | `blocked_by_prerequisite` | `"upstream stage 'identity-probe' verdict = confirmed-success (blocked); fraud-chain pretext never reached the target"` |
| Upstream verdict is `Inconclusive` | Block | `blocked_by_prerequisite` | `"upstream stage 'identity-probe' outcome indeterminate (no enforcement evidence found); insufficient evidence to justify continuation"` |
| Upstream stage itself is `blocked_by_prerequisite` or `cancelled` (cascading) | Block | `blocked_by_prerequisite` | `"upstream stage 'identity-probe' never executed: <upstream's own reason>"` |

A blocked stage **never** gets an `email_gw_runs` row — `run_id` stays `NULL`. This is the structural guarantee against fabrication: there is no run to query, nothing to mark "skipped successfully," nothing an evidence reader could mistake for an executed result.

**BEC's own gate (§7):** stage 2 ("fraud-payload") proceeds only when stage 1's ("identity-probe") `Prevention` verdict is `ConfirmedFailure` — the identity/impersonation pretext was delivered, so continuing the SAME attacker's narrative with the real fraud instruction is the only case that represents an actual continuing attack chain. `ConfirmedSuccess` (the pretext was blocked) and `Inconclusive` both block stage 2, for the distinct reasons shown above.

## 5. Async execution: injection, dwell windows, verification, retries, timeouts, cancellation, restarts

A `StageKindInjected` stage's dispatch is a direct call into the existing, unmodified `ExecuteEmailGWRun` (`internal/api/emailgwrun_executor.go`) — no new injection or dwell-window logic. This reuses, unchanged: real SMTP injection via `emailgwefficacy.InjectScenarioMessage`, the existing dwell-window defaults/clamping, the existing one-shot `VerifyMailExpectation` call, and the existing `StatusCompleted`/`StatusPartial`/`StatusFailed` derivation.

**New behavior needed on top of the unmodified executor:**

- **Continuation hook.** `finishEmailGWRunAfterWindow` (called both by the live goroutine and by `RecoverEmailGWRuns`'s boot sweep — so both paths get this for free) gains one additional step after writing the run's terminal status: check whether this `run_id` is referenced by an `email_gw_campaign_stages` row, and if so call `continueEmailGWCampaign` to evaluate and dispatch the next stage (or mark the campaign complete).
- **Retries.** A transient dispatch failure (the one case `ExecuteEmailGWRun` itself can return an error for *after* scenario/gate validation already passed — e.g. a momentary SMTP connection failure) gets up to 2 retries with a short fixed backoff before the stage (and, by cascade, every downstream stage) is marked `failed`. This is new, bounded, fixed-constant behavior — not a configurable retry policy; `ExecuteEmailGWRun`'s own existing "reject up front, before any row exists" validation (unknown scenario ID, unwired `EnvelopeFrom`) is never retried, since retrying a non-transient validation failure can never succeed.
- **Timeouts.** Already bounded by the existing per-run dwell window; no separate campaign-level timeout is introduced. A stage's own run can never hang indefinitely (`RecoverEmailGWRuns` already forces completion once a run's window has closed, even across a restart), so a campaign can never hang indefinitely either — it is a chain of already-bounded links.
- **Cancellation.** `CancelEmailGWCampaign` sets the campaign row's `status` to `cancelling`. The continuation hook checks this flag **before** dispatching the next stage (never retroactively — an already-dispatched stage's own in-flight run finishes exactly as it would have, same best-effort posture as `CancelRun`'s own `cancelGracePeriod`); every stage that would otherwise have been dispatched is instead marked `cancelled` (a status distinct from `blocked_by_prerequisite`, carrying its own distinct reason: cancellation is an operator decision, not an evidentiary gate failing).
- **Process restarts — the one genuinely new recovery gap.** `RecoverEmailGWRuns` already resumes any individual run stuck at `StatusRunning` across a restart. It does **not** cover a narrower race: the process crashing *after* a stage's run reaches a terminal status but *before* the continuation hook has dispatched the next stage. A new boot sweep, `RecoverEmailGWCampaigns`, closes this: find every `email_gw_campaign_stages` row at `status='dispatched'` whose referenced run is already terminal, and call `continueEmailGWCampaign` for each. Both this sweep and the live continuation path can race to dispatch the same next stage (e.g. a concurrent recovery sweep and a goroutine that was already mid-continuation at crash time); duplicate dispatch is prevented by a `UNIQUE (campaign_id, ordinal)` constraint on `email_gw_campaign_stages`, with the insert's unique-violation treated as "already advanced, benign no-op" (reusing the existing `isUniqueViolation` helper in `internal/api/handlers.go`, same pattern already used by `internal/relationships`/`internal/verification`).

## 6. Persistence and recovery

```sql
CREATE TABLE email_gw_campaigns (
    id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    template_id   text        NOT NULL,       -- e.g. "bec-supplier-fraud"
    status        text        NOT NULL DEFAULT 'running',
    initiated_by  text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT NOW(),
    completed_at  timestamptz,
    CONSTRAINT email_gw_campaigns_status_check
        CHECK (status IN ('running','completed','partial','failed','cancelling','cancelled'))
);

CREATE TABLE email_gw_campaign_stages (
    id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    campaign_id     text        NOT NULL REFERENCES email_gw_campaigns(id),
    ordinal         int         NOT NULL,
    stage_key       text        NOT NULL,
    run_id          text        REFERENCES email_gw_runs(id), -- NULL until dispatched; permanently NULL if blocked/cancelled
    status          text        NOT NULL DEFAULT 'pending',
    blocked_reason  text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT NOW(),
    completed_at    timestamptz,
    CONSTRAINT email_gw_campaign_stages_status_check
        CHECK (status IN ('pending','dispatched','completed','blocked_by_prerequisite','failed','cancelled')),
    CONSTRAINT email_gw_campaign_stages_unique_ordinal UNIQUE (campaign_id, ordinal)
);

ALTER TABLE email_gw_runs ADD COLUMN IF NOT EXISTS campaign_id text; -- mirrors cloud_runs.campaign_id exactly
CREATE INDEX idx_email_gw_runs_campaign ON email_gw_runs (campaign_id);
```

Recovery, in full: `RecoverEmailGWRuns` (existing, unmodified) resumes any individual run still genuinely waiting out its window. `RecoverEmailGWCampaigns` (new) resumes any stage whose run finished but whose campaign was never advanced past it — covering exactly the restart race §5 names, via the same `UNIQUE (campaign_id, ordinal)` duplicate-dispatch guard used by the live path.

## 7. Evidence and rollups

`email_gw_campaign_stages` stores `run_id`, never a copy of `EfficacyResult` — the evidence of record stays exactly where it already lives, on the referenced `email_gw_runs.Result`, read fresh. `GET /api/emailgw-campaigns/{id}` returns the campaign plus every stage, each stage's own full `EmailGWRun` (fetched by `run_id` when non-null) inlined, and every blocked/cancelled stage's own `blocked_reason` verbatim — a campaign-level rollup (e.g. `{total: 4, completed: 1, blockedByPrerequisite: 3}`) is compute-on-read over the stage statuses, same discipline as `cloudCampaignRollup`/`buildEmailGWRunsSummary`, and **never** collapses a blocked or failed stage into the rollup's "completed" bucket.

## 8. Authorization and safety

- `POST /api/emailgw-campaigns` gated by `auth.RequirePermission(auth.CanRunScenario)` — same permission `TriggerEmailGWRun`/`TriggerCloudPlanRun` already require.
- `GET` endpoints baseline-authenticated-only, same as every other EmailGW/cloud-run endpoint.
- No new recipients, no new sender identities: every injected stage resolves through the existing `emailgwefficacy.ExpectationByID`, which already only returns scenarios whose `Recipient`/`EnvelopeFrom`/`HeaderFrom` are proven (by `TestScenarioBuilders_NeverNameARealDomain`) to stay in the synthetic `.test` namespace.
- Execution limits: a campaign template's stage count is fixed in Go (not user-suppliable), bounding total real sends per campaign to the template's own small, reviewed count (4, for BEC).
- No new cleanup requirement: a campaign introduces no new external resource (no new mailbox, no new relay) beyond what each stage's own `emailgwrun` already manages.
- `h.emailgwProvider == nil` → `POST /api/emailgw-campaigns` returns 503, identical posture to `TriggerEmailGWRun`, checked before any campaign/stage row is ever inserted.

## 9. Testing

Required coverage, each proven against real Postgres (testcontainers) and a local SMTP test server, never fixtures-only for the sequencing logic itself:
- Stage 1 dispatches for real; stage 2 proceeds when stage 1's real recorded `Prevention` verdict is `ConfirmedFailure`.
- Stage 2 is `blocked_by_prerequisite`, with the confirmed-block-specific reason, when stage 1 resolves `ConfirmedSuccess`.
- Stage 2 is `blocked_by_prerequisite`, with the inconclusive-specific reason, when stage 1 resolves `Inconclusive` (no evidence provided).
- Stages 3/4 (`StageKindDerived`) correctly read stage 2's own `DetectionVerdict`/`ResponseVerdict` without any new send, and themselves cascade to `blocked_by_prerequisite` when stage 2 never ran.
- A transient injection failure retries up to the fixed bound, then fails the stage and cascades the block downstream.
- `RecoverEmailGWCampaigns` resumes a campaign whose stage 1 run is already terminal but whose stage 2 was never dispatched (the restart race), without duplicate-dispatching stage 2 when called twice concurrently (the `UNIQUE (campaign_id, ordinal)` guard).
- `CancelEmailGWCampaign` prevents the next stage's dispatch and marks remaining stages `cancelled`, distinct from `blocked_by_prerequisite`.
- The full HTTP surface: 503 unconfigured, 400 unknown template, 201 success, `GET` list/get round-trips including the rollup, 404.

## 10. The BEC vertical slice (`bec-supplier-fraud`)

| Stage | Key | Kind | Source | Gate |
|---|---|---|---|---|
| 1 | `identity-probe` | Injected | `EG-002.known-good` (`ExecutiveImpersonationExpectation(true)`) | none (first stage) |
| 2 | `fraud-payload` | Injected | `EG-005.known-good` (`SupplierPaymentDiversionExpectation(true)`) | stage 1's `Prevention` ∈ {`ConfirmedFailure`} |
| 3 | `detection-check` | Derived | reads stage 2's own `DetectionVerdict` | none (cascades from stage 2's own status) |
| 4 | `response-check` | Derived | reads stage 2's own `ResponseVerdict` | none (cascades from stage 2's own status) |

Both injected stages use the `caught=true` direction (§0.1) — the direction whose `VerdictDetail` answers "did the relevant control catch this," which is what the campaign's own gate and final rollup need to reason about. Stage 4's real-world outcome for this specific narrative is expected to be `Inconclusive` far more often than not: `SupplierPaymentDiversionExpectation` does not model a later post-delivery reclassification the way `PostDeliveryThreatResponseExpectation` does, so there is usually nothing for Defender's own AIR/ZAP remediation to act on. That is an honest, documented finding about this narrative's own scope — not a capability gap, and not to be papered over with an invented "unsupported" status distinct from `Inconclusive` (the evidence path itself is real and wired; the narrative simply rarely gives it anything to confirm).

## 11a. EG-001–EG-010 mapped into the hierarchy

Per direction, this mapping was completed immediately after the BEC slice proved the sequencing model, not before. Every EG-ID below is Level 2 (a bundle of one or more Level-3 expectation IDs); none is promoted to Level 1 — none of the existing ten was designed as a multi-stage narrative, and this mapping does not retroactively force one. "Wired" is re-verified against `scenarios.go` directly (not assumed): a builder sets `EnvelopeFrom` for real SMTP injection, or it doesn't.

| EG-ID | Level-2 name (`EmailGWScenarioRegistry`) | Level-3 expectation IDs | Wired for real injection? |
|---|---|---|---|
| EG-001 | Domain spoofing (SPF/DKIM/DMARC) | `spf`/`dkim`/`dmarc` × known-good/known-bad (6) | No — needs a lab domain with real SPF/DKIM/DMARC records, not yet provisioned |
| EG-002 | Executive impersonation | known-good/known-bad (2) | **Yes**, both directions — used as BEC stage 1 |
| EG-003 | Credential phishing (URL harvesting + URL rewrite) | `credential-url` (wired) + `url-rewrite` (not wired) × known-good/known-bad (4) | Partial — `credential-url` yes, `url-rewrite` no |
| EG-004 | Malicious attachment (EICAR) | known-good/known-bad (2) | No — needs a real MIME attachment, not yet wired |
| EG-005 | Supplier payment diversion | known-good/known-bad (2) | **Yes**, both directions — used as BEC stage 2 |
| EG-006 | Sensitive-data leakage (outbound DLP) | known-good/known-bad (2) | No |
| EG-007 | External auto-forwarding | known-good/known-bad (2) | N/A — not a `MailExpectation` at all (an inbox-rule check); no live adapter exists either (`FixtureInboxRuleProvider` only) |
| EG-008 | Post-delivery threat response | known-good/known-bad (2, identical underlying send) | **Yes** — used as the source for BEC stages 3/4's own derived-stage pattern |
| EG-009 | Authentication exception scope | known-good/known-bad (2) | No |
| EG-010 | Detection-to-response chain | `detection`/`response` (2, same underlying send as EG-008) | **Yes** (same send as EG-008) |

Three of the four wired scenarios (EG-002, EG-005, EG-008/EG-010's shared send) are exactly the three this design's BEC slice already exercises for real — not a coincidence: a campaign's own injected stages can only ever be built from an already-wired expectation, so the wired subset of EG-001–EG-010 is also, by construction, the only subset immediately available to any future campaign family. The six unwired scenarios (EG-001, EG-003's `url-rewrite` leg, EG-004, EG-006, EG-007, EG-009) remain exactly as capable or incapable as they were before this pass — this mapping changes nothing about their own wiring status, it only states where each one sits in the hierarchy.

## 11. Explicitly deferred (not this pass)

- The EG-001–EG-010 → Level-2/3 mapping (done immediately after this slice, §0 and the top-level task list — small and low-risk, as directed).
- The other five illustrative campaign families (credential phishing, malware/post-delivery response, data exfiltration, trust/configuration weaknesses, mailbox compromise) — this design generalizes to them once `CampaignTemplate`/`GateCondition` are proven against one real template; building all six now would repeat §2's own objection to inflating a catalogue before the foundation is proven.
- Sector-specific campaign variants, vendor-aware cross-gateway expectations, a rendered campaign report — all real future asks, none blocking this pass.
