# Phishing BAS Mastery — Deferred QA Log

This document tracks every verification gap, blocked item, or deliberate scope exclusion for the Phishing BAS Mastery initiative (`phishing.txt`, repo root; design doc `docs/superpowers/specs/2026-10-18-phishing-bas-mastery-phase0-roadmap-design.md`). Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming Phishing BAS Mastery is "done" or making any external maturity claim about it — mirrors the role `docs/dlp-mastery-qa-log.md`, `docs/av-mastery-qa-log.md`, `docs/waf-mastery-qa-log.md`, `docs/webgw-mastery-qa-log.md` and `docs/emailgw-mastery-qa-log.md` play for their own initiatives.

## Test coverage, as of 2026-10-18 (`go test ./internal/phishval/... ./internal/phishcatalog/... ./internal/phishbridge/... ./internal/phishidentity/...`, all green)

Every package has real, deterministic test coverage — no `TODO`/skipped tests anywhere in these four packages. Nothing below is untested code; the open items are about live-tenant/live-vendor verification, not missing unit coverage.

- **`internal/phishval`** — the 7-dimension outcome model's own evaluator (`Evaluate*` functions per dimension), pure unit tests, no I/O.
- **`internal/phishcatalog`** — 44 `Scenario` entries, construction-time validation (`AudspectPhishingCatalog`, duplicate-ID/invalid-field checks), `CoverageReport`/`RequireNoCoverageRegression` (including `TestRequireNoCoverageRegression_Downgrade_Errors`, `_ScenarioRemoved_Errors`, `_NewlyAddedScenario_NeverAPenalty`), 11 `IndustryProfile`s (construction validation + `FilterScenarios` real-selection proof, not just metadata).
- **`internal/phishbridge`** — one-way translation tests from `emailgwefficacy`/`emailgwcampaign`/`exercise`/`phishidentity`/`internal/actions` into `phishval.Observation`, each with an explicit known-good and known-bad end-to-end case (e.g. `TestPHBEC002_...`, `TestPHDET001_...`, `TestPHIR002_...`, `TestPHCHN002_...`, `TestPHID001_...`, `TestPHIR003_...`).
- **`internal/phishidentity`** — real Microsoft Graph v1.0 adapter, every call proven against `httptest` (OAuth-consent listing, `RevokeAndVerifySignInSessions`'s 3-outcome retry logic including a genuine propagation-delay case, `CreateSharingInvite`/`CreateCalendarEventLure` + read-back verify + delete, all scoping/authorization rejections individually tested).

**Current catalog coverage snapshot** (`AudspectPhishingCoverageReport()`, re-measured 2026-10-18 after this session's PH-ID-001/PH-IR-003 closures): 44 scenarios total — 23 catalog-only, 2 fixture-tested, 19 adapter-tested, 0 live-validated. ("Adapter-tested" = real code path, proven against `httptest`/deterministic fixtures, never contacted a live vendor tenant. "Live-validated" = proven against a real tenant — zero scenarios have reached this tier yet, for any vendor, in this initiative.)

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
