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
