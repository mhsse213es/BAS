# Web Gateway BAS Mastery — Deferred QA Log

This document tracks every question, verification gap, or follow-up item that comes up while implementing the Web Gateway BAS Mastery initiative (`docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md`) that cannot be resolved immediately — because it's blocked on external access, a cost decision, a tenant/account permission, or something else outside this session's control. Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming WebGW Mastery is "done" or making any external maturity claim about it — mirrors the role `project_network_bas_acceptance_review.md` played for Network BAS Mastery.

## Open items

### 1. Cloudflare Gateway account access — blocked, no card available

**Status:** Open, blocked on the user's end (not an engineering gap).

**What's needed:** The master spec locks Cloudflare Gateway as WebGW Mastery's first live SWG adapter (§2.3), with Phase 2's exit criteria requiring at least one scenario to execute end-to-end against the *real* Cloudflare Gateway API — policy management, TLS inspection, and (most importantly) per-request gateway-evidence retrieval.

**Why it's blocked:** Cloudflare Zero Trust signup requires a card for identity verification, even for the free tier. The user does not currently have one. This blocks account creation entirely — not just the paid tiers that `Logpush`/`Log Explorer` might require for evidence retrieval (which was already a separate open question — see below).

**What this means for Phase 2:** Phase 2 proceeds fixture-backed for every component (URL policy, TLS-inspection visibility, DLP uploads, identity-scoped policy, SIEM-correlation pattern), extending `internal/webgwefficacy` exactly as Phase 1 did. The live Cloudflare adapter itself (`internal/webgwefficacy`'s `GatewayEvidenceProvider` implementation that calls Cloudflare's real API) is deferred until the user has account access. Phase 2's own implementation plan will mark this explicitly rather than silently treating fixture-backed work as if it met the "real" exit criterion — per the master spec's own condition #8 (document the gap, never silently substitute a mock for a claim of real coverage).

**Resolution path, when it unblocks:** user gets a card (physical or virtual) → create the free Zero Trust account → use the real credentials with `CloudflareGatewayPolicyProvider` (built 2026-10-15, see item #2's resolution) to exercise the policy-management API live → hand an API token back for Phase 2b's env-gated integration test (`TestCloudflareGatewayPolicyProvider_RealAPI...`, skips without credentials) to actually run.

### 2. Cloudflare per-request Gateway evidence retrieval — tier eligibility, RESOLVED 2026-10-15: no free-tier API exists

**Status:** Resolved (definitively, from Cloudflare's own current documentation) — not what was hoped for. Per-request evidence retrieval requires payment beyond the free Gateway tier, full stop. This resolution survives even after item #1 (account access) unblocks.

**What's needed:** A way to pull the gateway's own per-request decision record (did it block/allow *this specific* synthetic test request) via API — required by the evidence contract (spec §2.3 condition #3) so prevention/detection verdicts are never inferred from client-side success alone.

**What's confirmed, now with sources:**
- **Policy management** (`gateway/rules` create/read/update, `POST`/`GET /accounts/{account_id}/gateway/rules[/{id}]`) works on the free tier with a Bearer API token — [Cloudflare API: create a Zero Trust Gateway rule](https://developers.cloudflare.com/api/operations/zero-trust-gateway-rules-create-zero-trust-gateway-rule).
- **TLS inspection toggling** (`tls_decrypt` on `cloudflare_zero_trust_gateway_settings`, Cloudflare's own default cert) requires only the Zero Trust Write token permission, not Enterprise — [Cloudflare: TLS decryption](https://developers.cloudflare.com/cloudflare-one/policies/gateway/http-policies/tls-decryption).
- **Logpush for Zero Trust Gateway logs is Enterprise-only.** Cloudflare's own Zero Trust Logpush integration page carries a top-of-page "Enterprise-only" label covering the `gateway_http` dataset specifically — [Cloudflare: Logpush integration](https://developers.cloudflare.com/cloudflare-one/insights/logs/logpush/). The "recent blog post" lead about Logpush opening to self-serve plans generally does not extend to Zero Trust Gateway logs; this closes that lead.
- **Log Explorer has no free tier or trial at any plan level.** "Log Explorer is available as a paid add-on for any Application Services or Zero Trust purchase. There is no free version or trial available at this time." — [Cloudflare: Log Explorer pricing](https://developers.cloudflare.com/log-explorer/pricing). It is a metered add-on on top of whatever base plan is purchased, free or paid.
- **Free-tier Gateway HTTP log retention is 24 hours**, dashboard-viewable only, with no documented bulk-export or per-record query API at that tier — [Cloudflare: Zero Trust logs](https://developers.cloudflare.com/cloudflare-one/insights/logs).
- The undocumented, community-reported "gateway activities" REST endpoint remains unofficial and unverified — still not a path this initiative will depend on (per the master spec's own condition #7, mocked/undocumented behavior is never substituted for proven real coverage).

**Consequence for Phase 2b's scope, locked 2026-10-15:** the live Cloudflare adapter, on the account tier the user can actually obtain (free), can prove **policy correctness** (is the intended rule configured and enforced in Cloudflare's own live configuration) via the real `gateway/rules` API — it cannot prove **per-request attack-resistance or detection evidence** without an additional paid Log Explorer add-on or an Enterprise plan, neither of which this initiative assumes the user will purchase. `CloudflareGatewayPolicyProvider`, built 2026-10-15, implements Phase 3's existing `PolicyConfigEvidenceProvider` interface (`drift.go`) against Cloudflare's real, documented API — reusing an existing interface rather than inventing a new one, and giving `SourceLive` its first real producer anywhere in this package. Per-request evidence retrieval remains open, now explicitly priced rather than merely unconfirmed: it requires either the Log Explorer add-on or an Enterprise plan, a cost/sales decision for the user to make separately, not an engineering gap to close.

### 3. Additional SWG vendor access (Phase 4) — Zscaler marked Unsupported, documented gap

**Status:** Resolved for Phase 4's own exit criterion (the exit criterion only requires marking a gap, not closing it) — remains open if a live Zscaler adapter is ever wanted later.

**What was needed:** Phase 4's exit criterion requires at least one additional vendor adapter (beyond Cloudflare) either integrated end-to-end or explicitly, visibly marked Unsupported with the specific blocking gap documented.

**What was verified (2026-10-15):** Zscaler Internet Access has no public self-serve trial or signup flow. zscaler.com's own pages route every trial/demo path through "Request a Demo" / "Contact Us" -- a sales engagement, not an account a user can create unassisted. Secondary sources (G-Cloud procurement listings, pricing-review sites) describe it as an enterprise product sold via custom quote, with API access to `help.zscaler.com/zia/api` "available on request" -- no confirmed path to API credentials without going through that sales gate. This mirrors the same vendor-feasibility pattern already found for Netskope/Forcepoint/Skyhigh/Broadcom during Phase 2 research (all sales-gated) and FortiProxy-VM (a time-boxed trial dependent on Fortinet's own FDN phone-home infrastructure) -- none of the 6 Phase 4 vendor candidates offer genuine self-serve API trial access as of this date.

**Resolution path, if ever revisited:** would require the user (or Audspect) to go through Zscaler's sales/demo process and obtain a trial tenant with API credentials -- same shape as the Cloudflare blocker in item #1, but via a sales relationship rather than a missing payment method.

## Resolved items

*(none yet)*
