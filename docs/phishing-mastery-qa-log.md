# Phishing BAS Mastery — Deferred QA Log

This document tracks every verification gap, blocked item, or deliberate scope exclusion for the Phishing BAS Mastery initiative (`phishing.txt`, repo root; design doc `docs/superpowers/specs/2026-10-18-phishing-bas-mastery-phase0-roadmap-design.md`). Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming Phishing BAS Mastery is "done" or making any external maturity claim about it — mirrors the role `docs/dlp-mastery-qa-log.md`, `docs/av-mastery-qa-log.md`, `docs/waf-mastery-qa-log.md`, `docs/webgw-mastery-qa-log.md` and `docs/emailgw-mastery-qa-log.md` play for their own initiatives.

## Test coverage, as of 2026-10-18 (`go test ./internal/phishval/... ./internal/phishcatalog/... ./internal/phishbridge/... ./internal/phishidentity/...`, all green)

Every package has real, deterministic test coverage — no `TODO`/skipped tests anywhere in these four packages. Nothing below is untested code; the open items are about live-tenant/live-vendor verification, not missing unit coverage.

- **`internal/phishval`** — the 7-dimension outcome model's own evaluator (`Evaluate*` functions per dimension), pure unit tests, no I/O.
- **`internal/phishcatalog`** — 44 `Scenario` entries, construction-time validation (`AudspectPhishingCatalog`, duplicate-ID/invalid-field checks), `CoverageReport`/`RequireNoCoverageRegression` (including `TestRequireNoCoverageRegression_Downgrade_Errors`, `_ScenarioRemoved_Errors`, `_NewlyAddedScenario_NeverAPenalty`), 11 `IndustryProfile`s (construction validation + `FilterScenarios` real-selection proof, not just metadata).
- **`internal/phishbridge`** — one-way translation tests from `emailgwefficacy`/`emailgwcampaign`/`exercise`/`phishidentity`/`internal/actions` into `phishval.Observation`, each with an explicit known-good and known-bad end-to-end case (e.g. `TestPHBEC002_...`, `TestPHDET001_...`, `TestPHIR002_...`, `TestPHCHN002_...`, `TestPHID001_...`, `TestPHIR003_...`).
- **`internal/phishidentity`** — real Microsoft Graph v1.0 adapter, every call proven against `httptest` (OAuth-consent listing, `RevokeAndVerifySignInSessions`'s 3-outcome retry logic including a genuine propagation-delay case, `CreateSharingInvite`/`CreateCalendarEventLure` + read-back verify + delete, all scoping/authorization rejections individually tested).

**Current catalog coverage snapshot** (`AudspectPhishingCoverageReport()`, re-measured 2026-10-18 after the attachment-depth closure): 44 scenarios total — 18 catalog-only, 2 fixture-tested, 24 adapter-tested, 0 live-validated. ("Adapter-tested" = real code path, proven against `httptest`/deterministic fixtures or a real local SMTP server, never contacted a live vendor tenant. "Live-validated" = proven against a real tenant — zero scenarios have reached this tier yet, for any vendor, in this initiative.)

## Open items — blocked on live tenant/vendor access, not an engineering gap

### 1. Every Microsoft Graph-backed scenario — adapter code built and tested (httptest only); zero live-tenant verification

**Scenarios affected:** PH-IR-002 (session revocation), PH-CHN-002/004 (SharePoint sharing invite / calendar lure), PH-ID-002 (OAuth consent listing), PH-ID-003/004/005 (device-code/MFA-fatigue/session-theft — still catalog-only, no Graph call built at all yet).

**What's unverified:** the real `signInSessionsValidFromDateTime` propagation timing in production (this session's tests simulate a 2-poll delay; real Entra ID propagation delay is undocumented and could exceed the 3-attempt/2s default budget), real Graph throttling behavior under `RevokeAndVerifySignInSessions`'s retry loop, and whether `CreateSharingInvite`/`CreateCalendarEventLure`'s read-back verification races against real Graph eventual consistency the way the fixture tests assume it doesn't.

**Resolution path:** a Microsoft 365 tenant with admin-consented Graph permissions (`User.ReadWrite.All` for session revocation, `Files.ReadWrite.All` for sharing invites, `Calendars.ReadWrite` for calendar lures, `Policy.Read.All`/sign-in-log read access for PH-ID-003/004/005, not yet built).

### 2. PH-IR-003 (endpoint follow-through) — dispatch-level evidence only, no independent postcondition verification exists anywhere in this codebase

**Status:** Built and tested this session (`phishbridge.FromEPPResponseAction`, wrapping the already-real `internal/actions.Execute` against CrowdStrike/Defender/SentinelOne). `actions.StatusCompleted` proves the EPP vendor accepted and completed the dispatched isolate/kill-process/quarantine request — it does **not** prove the host is independently confirmed isolated or the process independently confirmed dead.

**Why this can't be closed further right now:** `internal/rwevidence.ContainmentObserver`, the one place in this codebase built to perform that independent check, is itself fake-backed only (not a real verifier either) — there is no real postcondition-verification layer anywhere to call. Closing this fully would mean building one (e.g. a real `ListMachines`/device-health re-query after dispatch, mirroring `RevokeAndVerifySignInSessions`'s own baseline→dispatch→reread pattern), which is new scope, not a live-tenant blocker alone.

**Resolution path:** (a) a live EPP tenant to verify the dispatch call itself against, and (b) a decision to build a real independent postcondition verifier for endpoint actions (new work, not yet scoped).

### 3. Mailbox search-and-purge (PH-IR-001's remaining half) — deferred by explicit decision, not partially built

**Status:** Deliberately not built. Research (2026-10-18) confirmed the real API shape (`POST /security/cases/ediscoveryCases/{caseId}/searches/{searchId}/purgeData`) is beta/preview, licensing-gated (E5/G5, `eDiscovery.ReadWrite.All`), multi-step (create case → create search → estimate → purge), with community-reported reliability issues (202 success but nothing actually deleted).

**Resolution path:** only build this once Microsoft's eDiscovery purge API exits preview, or the user explicitly asks for a beta-caveated implementation anyway.

### 4. Voice/vishing (PH-CHN-007) — deferred by explicit decision, zero telephony infrastructure

**Status:** Deliberately not built — no Twilio/SIP integration exists anywhere in this codebase, and building one solely to fill a scenario-count gap was explicitly rejected by the user.

**Resolution path:** a standalone build-vs-defer decision, not a QA gap.

### 5. Locale/i18n — deferred by explicit decision, no real rendering capability exists

**Status:** Deliberately not built — no i18n/RTL rendering infrastructure exists anywhere in this codebase; tag-only locale metadata was explicitly rejected as fake completeness.

**Resolution path:** only build once real i18n rendering infrastructure exists somewhere in this codebase to reuse.

## Resolved items

### PH-ID-001 (credential-harvesting simulation) — RESOLVED 2026-10-18

Was catalog-only on a stale note ("no typed read-side accessor yet"). `exercise.Store.ListEvidence` already existed and already returned everything needed; the real gap was the missing `phishval` translation. Built `phishbridge.FromExerciseInteractionEvidence`, now also the first real bridge for the `UserInteraction` dimension across the whole initiative (previously zero scenarios used it). 6 tests, all passing, including explicit priority-ordering proofs (report-after-click still grades Reported, submission beats click/open).

### PH-IR-003 (endpoint follow-through, dispatch level) — PARTIALLY RESOLVED 2026-10-18

See Open item #2 above for what remains. Dispatch-level bridge (`phishbridge.FromEPPResponseAction`) built and tested against `internal/actions.Execute` with a fake `VendorClient` (mirroring `internal/actions`' own test double exactly). 2 tests, both passing.

### PH-AUTH-006 (lookalike-domain detection) — RESOLVED 2026-10-18, catalog correction only

Was marked "genuine gap: no scenario builder exists" — wrong. `emailgwefficacy.SupplierPaymentDiversionExpectation` (PH-BEC-002's own mapped implementation) already tests domain-reputation/newly-observed-domain heuristics, by its own doc comment. Corrected to an overlap decision onto PH-BEC-002, the same pattern already used for PH-AUTH-001/PH-AUTH-005. No new code; a bookkeeping fix.

### PH-AUTH-007 (internal sender spoofing) — RESOLVED 2026-10-18

Was marked "no emailgwefficacy scenario builder wires it into a MailExpectation yet" — this implied a locked-package change was needed; it didn't. `MailExpectation` is a plain exported struct and `InjectScenarioMessage`/`VerifyMailExpectation` are already generic exported entry points that take their content/evidence as parameters, never consulting emailgwefficacy's private `scenarioTestContent` map. Built `phishbridge.InternalSenderSpoofExpectation` + `DispatchInternalSenderSpoof`, entirely in `phishbridge`, zero lines of `emailgwefficacy` changed. 3 tests: fixture-based known-good/known-bad evaluation, plus a real local-SMTP-server dispatch proof (mirroring `emailgwefficacy`'s own `injection_test.go` pattern) confirming the spoofed HELO identity and internal-looking envelope actually reach the wire. PH-EVA-002 (inbound relay-path bypass) corrected to an overlap decision onto this scenario at the same time — `InjectionTarget.RelayHost` vs. `TargetMX` is a dispatch-target configuration choice, not a distinct verification mechanism; showing a genuine relay-path bypass would need a second, differently-configured real gateway, which doesn't exist in this environment (a real remaining infrastructure gap, noted on PH-EVA-002's own entry, not re-opened as new scope here).

### PH-AUTH-009 (forwarding and mailing-list behavior) — RESOLVED 2026-10-18

Unlike PH-AUTH-006/007, this gap note was accurate about what was missing: `emailgwefficacy.SuspiciousAutoForwardExpectation`/`VerifyInboxRuleExpectation` (EG-007) already existed and already covers external auto-forwarding detection, but as a mailbox-configuration-state claim (`VerdictDetail`), a different evidence shape from `MailExpectation`/`EfficacyResult` — it genuinely needed its own translation, not a new scenario builder. Built `phishbridge.FromSingleDimensionDetectionVerdict` (initially named `FromInboxRuleVerdict`, generalized once PH-AUTH-010 needed the identical translation logic for a different `VerdictDetail`-returning check), mapping to phishval's Detection dimension only (this check is single-dimensional by design — nothing about the forwarded message's own delivery/enforcement). 3 tests: known-good (detected), known-bad (confirmed not detected), and an explicit no-evidence-found case proving it grades Inconclusive, never fabricating either outcome from an empty search.

### BEC/sender-compromise depth reuse audit — RESOLVED 2026-10-18 (PH-AUTH-010 built; PH-BEC-004/005/006/008 corrected to overlap decisions)

Per explicit instruction, audited PH-AUTH-010 and PH-BEC-004/005/006/008 against existing campaign templates, execution paths, evidence, and tests before writing anything new.

**PH-AUTH-010 (compromised legitimate sender) — genuinely buildable, built.** Found `emailgwefficacy/mailboxcompromise.go` already contains two complete, previously-unused-anywhere scenario families: `SuspiciousOAuthConsentGrantExpectation`/`VerifyOAuthConsentGrantExpectation` and `SuspiciousDelegatedMailboxAccessExpectation`/`VerifyDelegatedMailboxAccessExpectation` — the exact mailbox/identity-compromise-detection mechanism this scenario needed, built for a different area ("mailbox persistence") and never mapped to a PH-* ID. Mapped to the delegated-access one (the OAuth-consent one stays unused, reserved for a future scenario that needs that specific angle rather than being force-fit here). Reused `FromSingleDimensionDetectionVerdict` (see above) — zero new bridge logic needed. 3 tests, all passing.

**PH-BEC-004/005/008 (payroll/HR, procurement/PO, customer/partner impersonation) — corrected to overlap decisions, no code.** All three are narrative retextualizations of PH-BEC-002's own `SupplierPaymentDiversionExpectation` domain-reputation heuristic — the control doesn't care whether the financial-redirect pretext is "supplier," "payroll," "procurement," or "customer." This is the identical pattern already governing PH-BEC-002's own declared `PH-BEC-003`/`PH-BEC-007` variants and PH-AUTH-006's correction: authoring new narrative content for each would be the duplication phishing.txt's own capability #3 acceptance bar explicitly warns against, not a genuine new capability. Corrected the catalog notes from "genuine gap" to overlap decisions; no new code.

**PH-BEC-006 (reply-chain hijacking) — corrected to a partial overlap, genuine remaining gap named explicitly.** The account-compromise precondition is the identical evidence PH-AUTH-010 now covers. What stays a real, separate, unbuilt gap: detecting that a reply injected into an existing thread is anomalous relative to that thread's own history — no email-threading/content-anomaly capability exists anywhere in this codebase to test that independently. Correctly left catalog-only rather than faked by reusing the compromise signal alone.

Net result of this slice: 1 real build (PH-AUTH-010), 4 honest bookkeeping corrections (no new code, no duplicated engine), 0 scope creep into the still-genuine PH-BEC-006 reply-chain-anomaly gap.

### PH-ATT-002/PH-ATT-003 (PDF/Office attachment depth) — RESOLVED 2026-10-18

Both were genuine gaps with no existing content-generator to reuse — unlike every closure above, this required new generation code, which the user explicitly asked for ("actual PDF/Office-document generation, reproducible benign test artifacts, and verifiable outcomes"), not fixture strings with a link substring embedded.

Built `buildMinimalPDFWithLink`/`buildMinimalDOCXWithExternalLink` in `phishbridge/attachmentdepth.go`: a real, valid, minimal PDF with a byte-accurate xref table and a genuine `/Link` annotation whose action is a `/URI`; a real, valid, minimal OOXML Word document (an actual ZIP archive with `word/_rels/document.xml.rels` declaring a `TargetMode="External"` hyperlink relationship). Both reproducible (byte-identical output for the same input URI). Wired through `exercise.SpoofableSMTPInjector`'s existing multipart-attachment path (the same mechanism `EICARAttachmentExpectation` already uses) via `emailgwefficacy.InjectScenarioMessage` — zero changes to the locked `emailgwefficacy` package, same technique as PH-AUTH-007.

8 tests: 2 unit proofs that the generated artifacts are genuinely valid/parseable/reproducible (not just string-contains checks), 4 fixture-based known-good/known-bad evaluation proofs (mirroring the established pattern), and 2 real-dispatch proofs that go further than any prior dispatch test in this initiative — each one decodes the actual base64 attachment part out of the real SMTP wire payload and re-parses it: the PDF is confirmed to start with the real header and contain the `/URI` action; the DOCX is confirmed to open as a real zip archive whose own relationship XML declares the expected external link. "Verifiable outcomes" in the sense the user asked for, not merely "a file was attached."
