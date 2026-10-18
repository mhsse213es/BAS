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

### 3. DLP-MOB (mobile DLP channel) — open, blocked on missing mobile agent, not a configuration or licensing gap

**Status:** Open, blocked on infrastructure Audspect does not have — a genuine engineering gap, not deferred for the same reason as items 1-2 above.

**What's needed:** `dlp.txt` §3B names `DLP-MOB` ("Supported mobile DLP controls, managed versus unmanaged applications, copy/paste restrictions and document sharing") as one of 10 exfiltration-channel scenario families. Audspect's agent runs on Windows/macOS/Linux endpoints only (confirmed by repo audit 2026-10-18: zero references to a mobile/Android/iOS agent anywhere in `internal/agent*` or `internal/models/schema.go`). Testing a real mobile DLP control (an MDM-enrolled device, a managed-app copy/paste restriction, a mobile DLP agent's own policy enforcement) requires a mobile execution surface — an actual Android/iOS agent, or at minimum an MDM/EMM API integration — that does not exist in this codebase at all.

**What this means:** per `dlp.txt`'s own non-negotiable engineering rule 1 ("Capability-aware execution: fail closed when required preconditions or authorization are absent; report NOT_TESTED rather than inventing a result") and §10's acceptance criterion ("Unsupported channels and unlicensed capabilities remain explicitly untested"), DLP-MOB is recorded here as an explicit, named, unsupported capability rather than a fabricated scenario that doesn't actually exercise a mobile environment. No `dlp-exfiltration-mobile.yaml` scenario exists, and none should be written until a real mobile execution surface exists to run it against — a scenario whose steps run on the existing Windows/macOS/Linux agent cannot genuinely test a mobile DLP control, regardless of how the payload is shaped.

**Resolution path:** build a mobile agent (Android/iOS) or an MDM/EMM API integration (e.g. Microsoft Intune, Google Workspace Endpoint Management) first — a separate, substantial engineering effort, not a follow-up to this initiative's existing scenario-authoring work. Until then, DLP-MOB stays at zero coverage, honestly.

### 4. Forcepoint DLP license, API credentials, and the exact incident schema — open

**Status:** Open, blocked on vendor account/licensing access, not purely an engineering gap — the exact incident response schema and token-cache lifetime are also genuinely unconfirmed by documentation research (see below).

**What's needed:** a Forcepoint DLP Manager account with a local **Application-type** administrator user (Network-type accounts cannot be used for API access) and DLP incident-query licensing/role.

**What's still unverified, independent of account access:**
- The exact JSON field names in an incident response record from `POST /dlp/rest/v1/incidents` — research (2026-10-18) confirmed the endpoint path, the filters-mode (vs. ID-list) request shape, the 10,000-row response cap, and the single-type-per-call (`INCIDENTS`/`DISCOVERY`) constraint, but the REST API Guide pages found (dated Dec 2021/Mar 2022, versioned for DLP 9.0/10) document endpoints and parameters, not a field-level incident schema. `forcepointdlp.Incident`'s fields (`ID`/`Timestamp`/`Policy`/`Department`/`RiskLevel`/`Severity`/`Action`/`Status`) are this package's best-effort mapping, not a confirmed schema.
- The access token's real cache lifetime — this client caches for a fixed 15 minutes as a conservative default; no documented token lifetime was found for the 2-step refresh-token/access-token exchange.
- The exact date-range filter parameter name inside the `filters` object — confirmed that `policy`/`department`/`riskLevel` are valid filter fields, but not confirmed whether `dateRange.start`/`dateRange.end` (this client's best-effort guess) matches the real parameter names.
- Pagination beyond the documented 10,000-row-per-response cap — `QueryDLPIncidents` does not page through results, so a real tenant with more than 10,000 incidents in the queried window would return a silently truncated (not erroring) result. Matches `purview`'s and `trellixdlp`'s own current non-paginating scope, not a new gap specific to this client.

**What this means for Priority 5:** `internal/vendors/forcepointdlp`'s request-building/response-mapping (`QueryDLPIncidents`) is built and proven against `httptest` now, matching the same best-effort-but-explicit-about-the-gap posture as items 1-2 above. See the package's own doc comment in `client.go`.

**Resolution path:** get a Forcepoint DLP Manager test account with an Application-type administrator user and DLP incident licensing, and the current (not 2021/2022-dated) REST API Guide for the installed version; correct `Incident`'s field mapping, the token cache lifetime, and the date-range filter parameter name against what the real account's API responses show.

### 5. Symantec (Broadcom) DLP license, API generation, and the exact incident schema — open

**Status:** Open, blocked on vendor account/licensing access, not purely an engineering gap — which of 2 documented API generations applies, and the exact incident response schema, are also genuinely unconfirmed by documentation research (see below).

**What's needed:** a Symantec/Broadcom DLP Enforce server account (a service account with DLP incident-query role) and confirmation of which API generation the license covers.

**What's still unverified, independent of account access:**
- Which of Symantec's two documented API generations a given license maps to: the 15.7+ REST API or the 16+ "Incident Reporting and Update API" web service — both exist in the documentation found, and this client's best-effort implementation cannot determine which a real account uses.
- The exact login endpoint path and incident-list endpoint path — research (2026-10-18) confirmed the auth *mechanism* (forms-based username/password, not OAuth — the Cortex XSOAR `symantec-data-loss-prevention-v2` integration's own config fields are exactly Enforce server URL + username + password) and the incident filter vocabulary (earliest time, status, severity, incident type, default page size 50), but not official endpoint paths. `LoginURL`'s/`IncidentsURL`'s defaults (`/ProtectManager/webservices/v2/authenticate` and `.../incidents`) are this package's best-effort guess, not confirmed paths.
- The post-login session mechanics — this client's best-effort guess is a `sessionToken` query parameter on the incidents request; no documented convention (cookie vs. header vs. query param) was found for what happens after a successful forms login.
- Pagination beyond the documented default page size of 50 — `QueryDLPIncidents` does not page through results, so a real tenant with more than one page of incidents in the queried window would return a silently truncated (not erroring) result. Matches `purview`'s and `trellixdlp`'s own current non-paginating scope, not a new gap specific to this client.
- The exact JSON field names in an incident response record — `symantecdlp.Incident`'s fields (`ID`/`DetectionDate`/`Status`/`Severity`/`IncidentType`) are this package's best-effort mapping aligned to the confirmed filter vocabulary, not a confirmed response schema.

**What this means for Priority 5:** `internal/vendors/symantecdlp`'s request-building/response-mapping (`QueryDLPIncidents`) is built and proven against `httptest` now. Its login step deliberately never retries a rejected attempt internally, since a documented account-lockout risk (default 6 failed attempts, 60-minute lockout) makes an automatic retry actively dangerous against a real account — this is a correctness decision, not a gap. See the package's own doc comment in `client.go`.

**Resolution path:** get a Symantec/Broadcom DLP Enforce test account, confirm which API generation (15.7+ REST vs. 16+ Incident Reporting) the license covers, and the current official API reference for that generation; correct the endpoint paths, session mechanics, and `Incident`'s field mapping against what the real account's API responses show.

## Resolved items

(none yet)
