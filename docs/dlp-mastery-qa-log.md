# DLP BAS Mastery — Deferred QA Log

This document tracks every question, verification gap, or follow-up item for the DLP BAS Mastery initiative (`dlp.txt`) that cannot be resolved immediately — because it's blocked on external access, a licensing decision, a tenant/account permission, or something else outside this session's control. Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming either DLP vendor connector is "done" or making any external maturity claim about them — mirrors the role `docs/emailgw-mastery-qa-log.md`, `docs/av-mastery-qa-log.md`, `docs/waf-mastery-qa-log.md` and `docs/webgw-mastery-qa-log.md` play for their own initiatives.

## Open items

### 1. Microsoft Purview tenant provisioning/licensing + admin consent — open

**Status:** Open, blocked on account/licensing access, not an engineering gap.

**What's needed:** a Microsoft 365 tenant with Purview/compliance licensing (unified audit logging enabled), an app registration with admin-consented Application permissions `ActivityFeed.Read` and `ActivityFeed.ReadDlp` against `manage.office.com`.

**Tenant status:** unconfirmed. `project_azure_real_discovery_integration` (prior-session memory) names an existing Entra tenant (`ed059a30-...`) used for unrelated Azure resource-discovery work, itself blocked there on a missing Azure subscription and a missing admin role for Graph consent. That same missing-admin-role gap is the identical mechanism Purview's application-permission admin consent needs — very likely blocks this too, not independently verified.

**What this means for Priority 5:** `internal/vendors/purview`'s request-building/response-mapping (`EnsureSubscriptionStarted`, `QueryDLPEvents`) is built and proven against `httptest` now, exactly as `AnalyzedEmailEvidenceProvider` was before Defender-for-O365 tenant access existed (`docs/emailgw-mastery-qa-log.md` item 1b). Only the real-tenant integration stays deferred.

**What's still unverified once a tenant exists:**
- The exact `Office 365 Management Activity API` error code/text for "subscription already enabled" — `EnsureSubscriptionStarted` currently matches a case-insensitive substring ("already enabled") against the error message, which is Microsoft's documented wording but not guaranteed stable across tenants/API versions.
- Rate limits and pagination behavior on `activity/feed/subscriptions/content` for a high-volume tenant.
- Whether `ActivityFeed.ReadDlp` alone suffices for full `PolicyDetails`/`Actions` field detail, or whether a separate "Read DLP sensitive data" grant (documented by Microsoft as a distinct permission) is also required to see sensitive-data match detail, not just the policy/rule names this client currently surfaces.

**Resolution path:** provision a tenant (the existing Azure tenant, if it can be licensed for Purview, or a fresh Microsoft 365 Developer Program tenant) and admin-consent the app registration for both scopes above.

### 2. Trellix DLP license, API credentials, and the exact incident schema — open

**Status:** Open, blocked on vendor account/licensing access, not purely an engineering gap — the exact response schema is also genuinely unconfirmed by documentation research (see below).

**What's needed:** a Trellix account with DLP module licensing and an IAM client-credentials application with a DLP-incident-scoped grant.

**What's still unverified, independent of account access:**
- The exact JSON response envelope/field names for a DLP incident record from the Events API v2 `type=incidents` endpoint — research (2026-10-18) confirmed the endpoint's existence and general shape (regional hosts, `type=incidents` query param) but not an official, published field reference for DLP-specific incidents. `trellixdlp.Incident`'s fields (`ID`/`Timestamp`/`Severity`/`PolicyName`/`Action`/`Status`) are this package's best-effort mapping, not a confirmed schema.
- Which of Trellix's own conflicting documented token endpoints/domains is current: `https://iam.cloud.trellix.com/iam/v1.0/token` (used as this client's default) vs. the legacy `https://iam.mcafee-cloud.com/iam/v1.1/token`, and which regional Events API host (US/Singapore/Frankfurt/Sydney/India) applies to a given account.
- Whether the client-credentials grant genuinely uses HTTP Basic auth for the DLP-incidents scope specifically (confirmed for Trellix EDR/ePO integrations in the docs found; not confirmed DLP-specific).

**What this means for Priority 5:** `internal/vendors/trellixdlp`'s request-building/response-mapping (`QueryDLPIncidents`) is built and proven against `httptest` now, matching the same best-effort-but-explicit-about-the-gap posture as item 1 above. This package carries a stronger disclaimer than `purview`'s, since even the *response schema* (not just tenant access) is unconfirmed — see the package's own doc comment in `client.go`.

**Resolution path:** get Trellix DLP API documentation/sandbox access (the Trellix Developer Portal at developer.manage.trellix.com, or a support-provided DLP incident API reference) and a licensed test account; correct `Incident`'s field mapping and the token/events endpoint defaults against whatever the real account's IAM Client Credentials page and the real incident API reference show.

## Resolved items

(none yet)
