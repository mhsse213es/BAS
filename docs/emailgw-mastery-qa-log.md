# Email Gateway BAS Mastery — Deferred QA Log

This document tracks every question, verification gap, or follow-up item that comes up while implementing the Email Gateway BAS Mastery initiative (`docs/superpowers/specs/2026-10-15-emailgw-mastery-architecture-design.md`) that cannot be resolved immediately — because it's blocked on external access, a licensing/cost decision, a tenant/account permission, or something else outside this session's control. Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming EmailGW Mastery is "done" or making any external maturity claim about it — mirrors the role `docs/webgw-mastery-qa-log.md` plays for Web Gateway Mastery and `project_network_bas_acceptance_review.md` played for Network BAS Mastery.

## Open items

### 1b. M365 Defender for Office 365 tenant provisioning/licensing — open

**Status:** Open, blocked on account/licensing access, not an engineering gap.

**What's needed:** a Microsoft 365 tenant with Defender for Office 365 licensing (Plan 1 or 2) and an app registration with admin-consented `SecurityAnalyzedMessage.Read.All` (and, for detection, the existing Defender alert scope already used by `orchestrator/internal/vendors/defender.Client`).

**Tenant status:** unconfirmed. `project_azure_real_discovery_integration` (prior-session memory) names an existing Entra tenant (`ed059a30-...`) used for unrelated Azure resource-discovery work, itself blocked there on a missing Azure subscription and a missing admin role. Whether that tenant carries or could be licensed with Defender for Office 365 is a separate, unanswered question — not assumed resolved by anything already known about that tenant's Azure-side blockers. A fresh Microsoft 365 Developer Program tenant (free, renewable, includes Defender for Office 365 Plan 2) is the other option.

**What this means for Phase 3b:** the API-path question (item #1, below) is now resolved by documentation research — this is the only remaining blocker for live execution. `AnalyzedEmailEvidenceProvider`'s request-building/response-mapping can and should be built and proven against `httptest` now, exactly as `CloudflareGatewayPolicyProvider` was before Cloudflare account access existed; only the real-tenant integration test stays skipped until this item resolves.

**Resolution path:** provision a tenant (existing Azure tenant licensed for Defender for O365, or a fresh M365 Developer Program tenant) and admin-consent the app registration for `SecurityAnalyzedMessage.Read.All`.

## Resolved items

### 1. M365 Defender enforcement-evidence/policy-configuration API path — RESOLVED 2026-10-15: a confirmed v1.0 Graph endpoint exists, no PowerShell needed

**Status:** Resolved by documentation research (not yet verified hands-on against a real tenant — that remains item #1b above). This reverses this item's original framing, which incorrectly assumed Exchange Online PowerShell with certificate-based auth was the only path; it is not.

**What was found:** Microsoft Graph's **`GET /security/collaboration/analyzedEmails`** is a **v1.0 (stable, not beta)** endpoint, namespace `microsoft.graph.security` — [List analyzedEmails](https://learn.microsoft.com/en-us/graph/api/security-collaborationroot-list-analyzedemails?view=graph-rest-1.0). It is the REST backing for the Microsoft 365 Defender portal's Threat Explorer, announced for programmatic use in July 2024 — [Announcing Microsoft Defender for Office 365 API's for retrieving threat data and remediating emails](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/announcing-microsoft-defender-for-office-365-api%e2%80%99s-for-retrieving-threat-data-an/4199777).

- **Permission:** Application (app-only) permission `SecurityAnalyzedMessage.Read.All`, least-privileged — **client-credentials OAuth2 against `graph.microsoft.com`, the exact same auth model and scope `internal/platform/msauth.EntraTokenSource` and `internal/vendors/defender.Client` already use.** No certificate-based auth, no PowerShell, no new credential/execution model needed anywhere in this codebase.
- **Query:** `startTime`/`endTime` plus OData `$filter`, confirmed filterable by `networkMessageId` and `recipientEmailAddress` (Microsoft's own documented example filters by both together).
- **Response carries both evidence legs Phase 3b needed:**
  - **Enforcement evidence:** `policyAction` (string), `policy` (string, which policy fired), `originalDelivery`/`latestDelivery` — each an `analyzedEmailDeliveryDetail` with `action` (`unknown|deliveredToJunk|delivered|blocked|replaced|unknownFutureValue`) and `location` (`unknown|inbox_folder|junkFolder|deletedFolder|quarantine|onprem_external|failed|dropped|others|unknownFutureValue`) — [analyzedEmailDeliveryDetail](https://learn.microsoft.com/en-us/graph/api/resources/security-analyzedemaildeliverydetail?view=graph-rest-1.0).
  - **SPF/DKIM/DMARC evidence (area A, exactly Phase 3a's own scenarios):** `authenticationDetails` — an `analyzedEmailAuthenticationDetail` with `dmarc`, `dkim`, `senderPolicyFramework`, `compositeAuthentication`, each a pass/fail/softfail string — [analyzedEmailAuthenticationDetail](https://learn.microsoft.com/en-us/graph/api/resources/security-analyzedemailauthenticationdetail?view=graph-rest-1.0).
  - **Detection correlation:** `alertIds`, `threatTypes`, `detectionMethods` — the same correlation `DefenderDetectionProvider` (Phase 3a) already does via `alerts_v2`, now available directly on the message record instead of needing a separate alert query.
  - **Correlation keys:** `networkMessageId`, `internetMessageId`, `recipientEmailAddress`, `subject`.

**What's still unverified (flagged honestly, not assumed):**
- **Finding the `networkMessageId` for a just-sent test message.** It's Microsoft-365-generated on acceptance, not known to `SpoofableSMTPInjector` in advance. Likely resolved by filtering `analyzedEmails` on `recipientEmailAddress` + the test's time window + matching `subject`/`internetMessageId` instead — ordinary correlation, not a structural blocker, but not yet proven against a real tenant.
- **Whether completely clean, non-malicious test mail (the "should deliver" legitimate-mail case) shows up in `analyzedEmails` at all**, or whether it's limited to mail with some analysis/threat signal. The Threat Explorer UI this API backs has an "All email" view suggesting yes, but this isn't stated explicitly in the property reference — verify hands-on.
- **Rate limits, pagination behavior (`$skiptoken`/`$top`), and whether `SecurityAnalyzedMessage.Read.All` alone suffices or a second permission is layered on in practice** — common gaps between a reference page and real tenant behavior.

**What this means for Phase 3b:** the implementation spec's "Scope Refinement" section is updated accordingly (§ below). The enforcement adapter is buildable now, httptest-backed, with zero new auth model — only real-tenant access (item #1b) gates the live integration test.

**Built, 2026-10-15 (`12d72380`):** `AnalyzedEmailEvidenceProvider` (`orchestrator/internal/emailgwefficacy/analyzedemail.go`), `defender.Client.QueryAnalyzedEmails` (`orchestrator/internal/vendors/defender/client.go`), and `DefenderMailEvidenceProvider` (composes it with `DefenderDetectionProvider` into one full `MailEvidenceProvider`). An httptest-backed end-to-end test (`TestDefenderMailEvidenceProvider_SPFScenario_EndToEnd_BothLegsSourceLive`) proves Phase 3's own exit criterion — both `Enforcement` and `Detection` evidence present and tagged `SourceLive` — for the SPF known-bad scenario. Only the real-tenant integration tests (`TestAnalyzedEmailEvidenceProvider_RealAPI_SkipsWithoutCredentials`, `TestDefenderDetectionProvider_RealAPI_SkipsWithoutCredentials`) remain skipped pending item #1b.

### 2. Additional vendor access (Phase 5) — Proofpoint/Mimecast/Cisco Secure Email/FortiMail all marked `NotTested`, documented gaps

**Status:** Resolved for Phase 5's own exit criterion (the exit criterion only requires marking a gap, not closing it) — remains open if a live adapter for any of these four is ever wanted later.

**What was needed:** Phase 5's exit criterion requires at least one additional vendor adapter (beyond M365 Defender) either integrated end-to-end or explicitly, visibly marked `NotTested`/`not-applicable` with the specific blocking gap documented.

**What was verified (2026-10-15):** none of the four named vendors offer a genuinely reproducible, self-serve trial matching the bar M365's Developer Program met — the same sales-gated pattern WebGW Mastery already found for its own 6 non-Cloudflare SWG candidates.
- **Proofpoint:** no confirmed self-serve trial or API sandbox in any result found; G-Cloud reseller listings for Proofpoint SaaS explicitly show "API sandbox or test environment: No."
- **Mimecast:** no free plan; trial appears sales-assisted, with no confirmed self-serve API-credential path. Points to "contact sales" or a reseller.
- **Cisco Secure Email:** a 45-day free trial exists, but restricted to companies with 100+ employees, and signup is sales-assisted ("a Cisco team member will be in contact soon") — not self-serve. Whether a trial tenant includes API credentials is unconfirmed.
- **FortiMail:** the closest to self-serve — FortiMail-VM ships a built-in 15-day evaluation-mode trial with no sales contact required to deploy the VM itself — but it is time-boxed (15 days, one source disputes whether it works on KVM at all) and licensing/activation likely needs a FortiCloud account, the same "self-hostable but short-lived and phone-home-dependent" shape WebGW Mastery found for FortiProxy-VM and did not pick as its first live adapter for exactly that reproducibility concern.

**Consequence:** all four remain `NotTested`, access unverified beyond what's documented here — no fixed order among them is locked, matching the architecture spec's own §2.3 condition #1 language.

**Resolution path, if ever revisited:** FortiMail is the most plausible next candidate given its lower access friction, but its reproducibility concern (15-day window, FortiCloud phone-home) would need to be weighed the same way WebGW Mastery weighed it for FortiProxy before committing engineering time to it.

### 3. RBI 2016 Cyber Security Framework circular (RBI/2015-16/418) — reported repealed, cross-cutting staleness finding

**Status:** Fully resolved, including cross-cutting. Originally flagged here as found-but-not-fixed elsewhere; the user asked for the cross-cutting fix too, done 2026-10-16.

**What was found (2026-10-15):** while researching India's seed regulatory obligation for this package's own `regulatory.go`, multiple independent secondary (compliance-vendor) sources converge on: the RBI's 2016 Cyber Security Framework circular (RBI/2015-16/418, DBS.CO/CSITE/BC.11/33.01.001/2015-16) — the same circular `webgwefficacy`'s own `regulatory.go` cites (`rbi-csf-net-02`, built the same day as that package's Phase 4) — was repealed effective 31 July 2026, superseded by the Reserve Bank of India (Commercial Banks — Cybersecurity, Technology: Risk, Resilience and Assurance Framework) Directions, 2026 (RBI/DoS/2026-27/410, DoS.CO.CSITEG.4/31.01.015/2026-27). None of these sources are RBI's own primary text (which is a scanned PDF behind a CAPTCHA gate this session could not OCR), so this is reported, not independently confirmed, but the repeal is consistent across every source found and none contradicted it.

**What this package did:** `IndiaRBISecureMailObligation()` (`regulatory.go`) cites the 2026 directions, not the 2016 circular, and its `Note` field states this staleness finding explicitly.

**Cross-cutting fix, 2026-10-16 (done at the user's request):** both other places in the repo citing the same repealed circular were corrected to cite the 2026 RBI Commercial Banks Cybersecurity Directions instead:
- `webgwefficacy`'s own `regulatory_test.go` (`rbi-csf-net-02` → `rbi-cybersecurity-directions-2026-net-02`).
- `internal/compliance/mappings/rbi_csf.yaml` (the 25-control catalog consumed by `internal/api`/`internal/compliance`/`internal/reporting`) — `version`/`name`/`published_year` updated; `id: RBI_CSF` deliberately left unchanged (a hardcoded match key elsewhere); the 25 controls themselves were not individually re-verified against the new document's paragraph numbering, flagged as such in the YAML's own header comment.

Full detail of both fixes lives in `docs/webgw-mastery-qa-log.md` item #9, since the work itself is in that package/catalog, not this one — this entry stays here as the index pointer so a reader of only this EmailGW log doesn't have to go looking for whether it was ever addressed.

### 4. Console wiring (not one of the original 6 phases) — `/api/emailgw/coverage[.html]` added, matching WebGW's own production bar

**Status:** Resolved 2026-10-16, at the user's request, after they asked what rebuilding would actually surface in the console and the honest answer was "nothing" -- `internal/emailgwefficacy` had zero production callers anywhere in the repo.

**What was found:** none of Audspect's mastery verticals have a dedicated web UI page. The actual, real precedent for "in production" is WebGW Mastery's own `GET /api/webgw/industry-profiles[.html]` -- a bespoke `internal/api` handler calling the package's exported functions directly, with no generic scenario-run pipeline involved and no link from any `web/src/features/*.js` page. `internal/adefficacy` has no handler at all despite being "done."

**What shipped, matching that same bar exactly:**
- `emailgwefficacy.CoverageReport.Areas()` (`coverage.go`) -- a new read-only accessor returning a copy of the report's per-area data, mirroring the existing `Exclusions()` method. Needed because `AreaCoverage` already had JSON tags, but nothing exposed the raw slice.
- `internal/reporting/emailgw_coverage.go` -- `BuildEmailGWCoverageReport()`/`EmailGWCoverageReportHTML()`, mirroring `webgw_industry_profiles.go`'s structure. No industry-profile narrative (emailgwefficacy deliberately deferred those -- see the architecture spec's Phase 5 amendment); renders the 7 taxonomy areas' status directly instead.
- `internal/api/emailgw_handlers.go` -- `GetEmailGWCoverage` (JSON) / `GetEmailGWCoverageHTML`, mirroring `webgw_industry_profile_handlers.go`.
- Routes: `GET /api/emailgw/coverage` and `GET /api/emailgw/coverage.html` (`routes.go`).

**What this deliberately does NOT include:** a web UI page/nav entry (no precedent exists for ANY vertical having one; flagged to the user as a materially bigger, separate ask before starting, and they chose the smaller scope), and no live-tenant credential wiring (the M365 Defender adapter still only reads `AUDSPECT_EMAILGW_DEFENDER_*` env vars -- a real multi-tenant credential UI would reuse `web/src/features/integrations.js`'s existing "Respond connector" pattern, which already has a `microsoft_defender` provider for Defender for *Endpoint*, a different product from Defender for *Office 365* -- not attempted here).
