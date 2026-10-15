# Email Gateway BAS Mastery — Deferred QA Log

This document tracks every question, verification gap, or follow-up item that comes up while implementing the Email Gateway BAS Mastery initiative (`docs/superpowers/specs/2026-10-15-emailgw-mastery-architecture-design.md`) that cannot be resolved immediately — because it's blocked on external access, a licensing/cost decision, a tenant/account permission, or something else outside this session's control. Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming EmailGW Mastery is "done" or making any external maturity claim about it — mirrors the role `docs/webgw-mastery-qa-log.md` plays for Web Gateway Mastery and `project_network_bas_acceptance_review.md` played for Network BAS Mastery.

## Open items

### 1. M365 Defender enforcement-evidence/policy-configuration API path — open, unverified

**Status:** Open, blocked on tenant access and API-path research, not yet an engineering gap with a known fix.

**What's needed:** a way to read (a) Safe Links/Safe Attachments/anti-phishing policy configuration and (b) per-message delivery/quarantine outcome, for a real Microsoft 365 Defender for Office 365 tenant — the `EnforcementEvidenceFor` half of `emailgwefficacy.MailEvidenceProvider` (`docs/superpowers/specs/2026-10-15-emailgw-mastery-phase3-first-real-vertical-design.md` §Scope Refinement).

**What's confirmed:** detection evidence (Microsoft Graph security alerts, `security/alerts_v2`) has a working REST path via the existing `orchestrator/internal/vendors/defender.Client` (client-credentials OAuth, `internal/platform/msauth.EntraTokenSource`) — the same shape every other Microsoft-family connector in this codebase already uses.

**What's not confirmed:** policy configuration and message-trace/quarantine outcome have no confirmed REST path. The industry-standard mechanism — Exchange Online PowerShell (`ExchangeOnlineManagement` module: `Get-SafeLinksPolicy`, `Get-SafeAttachmentPolicy`, `Get-AntiPhishPolicy`, `Get-MessageTrace`, `Get-QuarantineMessage`) — requires certificate-based app-only authentication and a PowerShell execution dependency, neither of which exists anywhere in this codebase today (every existing connector is a plain `net/http` call with client-secret OAuth). The Office 365 Management Activity API (`manage.office.com`, Exchange workload audit events) is an unverified alternative with the right auth shape (REST, client-credentials) but unconfirmed data granularity for this use case.

**Tenant status:** also unconfirmed. `project_azure_real_discovery_integration` (prior-session memory) names an existing Entra tenant (`ed059a30-...`) used for unrelated Azure resource-discovery work, itself blocked there on a missing Azure subscription and a missing admin role. Whether that tenant carries or could be licensed with Defender for Office 365 is a separate, unanswered question — not assumed resolved by anything already known about that tenant's Azure-side blockers.

**What this means for Phase 3:** Phase 3 splits into 3a (scenario content, the `SpoofableSMTPInjector` test sender, and the `DefenderDetectionProvider` detection-only adapter — all fixture/`httptest`-backed where live access is unavailable) and 3b (the enforcement-evidence/policy-configuration adapter, blocked here). Phase 3a proceeds without this item resolving; Phase 3b's exit criteria are not claimed met until it does.

**Resolution path, when it unblocks:** once a tenant with Defender for Office 365 licensing is available (either the existing Azure tenant gains that licensing, or a fresh Microsoft 365 Developer Program tenant is provisioned), hands-on-verify which path — Management Activity API, Exchange Online PowerShell with cert-auth, or something else — actually carries the needed data on that tenant. If PowerShell turns out required, design its credential/execution model as its own small decision before writing adapter code against it, rather than assuming it fits the existing `net/http`-only connector pattern.

## Resolved items

_None yet._
