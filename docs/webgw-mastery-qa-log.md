# Web Gateway BAS Mastery — Deferred QA Log

This document tracks every question, verification gap, or follow-up item that comes up while implementing the Web Gateway BAS Mastery initiative (`docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md`) that cannot be resolved immediately — because it's blocked on external access, a cost decision, a tenant/account permission, or something else outside this session's control. Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming WebGW Mastery is "done" or making any external maturity claim about it — mirrors the role `project_network_bas_acceptance_review.md` played for Network BAS Mastery.

## Open items

### 1. Cloudflare Gateway account access — blocked, no card available

**Status:** Open, blocked on the user's end (not an engineering gap).

**What's needed:** The master spec locks Cloudflare Gateway as WebGW Mastery's first live SWG adapter (§2.3), with Phase 2's exit criteria requiring at least one scenario to execute end-to-end against the *real* Cloudflare Gateway API — policy management, TLS inspection, and (most importantly) per-request gateway-evidence retrieval.

**Why it's blocked:** Cloudflare Zero Trust signup requires a card for identity verification, even for the free tier. The user does not currently have one. This blocks account creation entirely — not just the paid tiers that `Logpush`/`Log Explorer` might require for evidence retrieval (which was already a separate open question — see below).

**What this means for Phase 2:** Phase 2 proceeds fixture-backed for every component (URL policy, TLS-inspection visibility, DLP uploads, identity-scoped policy, SIEM-correlation pattern), extending `internal/webgwefficacy` exactly as Phase 1 did. The live Cloudflare adapter itself (`internal/webgwefficacy`'s `GatewayEvidenceProvider` implementation that calls Cloudflare's real API) is deferred until the user has account access. Phase 2's own implementation plan will mark this explicitly rather than silently treating fixture-backed work as if it met the "real" exit criterion — per the master spec's own condition #8 (document the gap, never silently substitute a mock for a claim of real coverage).

**Resolution path, when it unblocks:** user gets a card (physical or virtual) → create the free Zero Trust account → work through the verification checklist already drafted in this conversation (confirm policy management API, TLS decrypt toggle, and — critically — whether Log Explorer's `gateway_http` SQL API or Logpush is reachable on the free/low tier) → hand findings + an API token back for Phase 2's live-adapter sub-task to resume.

### 2. Cloudflare per-request Gateway evidence retrieval — tier eligibility unconfirmed (subsumed by #1, kept separate since it survives even if #1 unblocks)

**Status:** Open, unconfirmed from documentation alone.

**What's needed:** A way to pull the gateway's own per-request decision record (did it block/allow *this specific* synthetic test request) via API — required by the evidence contract (spec §2.3 condition #3) so prevention/detection verdicts are never inferred from client-side success alone.

**What's confirmed:** Policy management (`gateway/rules` create/update) and TLS inspection toggling (`tls_decrypt`, Cloudflare's own default cert) work without Enterprise.

**What's unconfirmed:** Whether any of these three paths work below Enterprise/Contract tier:
1. An undocumented, community-reported "gateway activities" REST endpoint — unofficial, risky to depend on long-term.
2. Logpush of the `gateway_http` dataset to a destination we control — historically described as Enterprise/Contract-only for Zero Trust logs; a recent (~10 days old at research time) Cloudflare blog post claims Logpush is opening to self-serve plans generally, but it's unclear whether that extends to Zero Trust Gateway specifically.
3. **Log Explorer's SQL API** over an R2-backed `gateway_http` dataset — the most promising lead found: genuinely documented, no HTTP-specific (only DNS-specific) plan restriction found in official docs, supports per-record SQL queries. Tier/pricing eligibility for this specific dataset is still unconfirmed.

**Resolution path:** only answerable hands-on, once account access (#1) is unblocked.

### 3. Additional SWG vendor access (Phase 4) — Zscaler marked Unsupported, documented gap

**Status:** Resolved for Phase 4's own exit criterion (the exit criterion only requires marking a gap, not closing it) — remains open if a live Zscaler adapter is ever wanted later.

**What was needed:** Phase 4's exit criterion requires at least one additional vendor adapter (beyond Cloudflare) either integrated end-to-end or explicitly, visibly marked Unsupported with the specific blocking gap documented.

**What was verified (2026-10-15):** Zscaler Internet Access has no public self-serve trial or signup flow. zscaler.com's own pages route every trial/demo path through "Request a Demo" / "Contact Us" -- a sales engagement, not an account a user can create unassisted. Secondary sources (G-Cloud procurement listings, pricing-review sites) describe it as an enterprise product sold via custom quote, with API access to `help.zscaler.com/zia/api` "available on request" -- no confirmed path to API credentials without going through that sales gate. This mirrors the same vendor-feasibility pattern already found for Netskope/Forcepoint/Skyhigh/Broadcom during Phase 2 research (all sales-gated) and FortiProxy-VM (a time-boxed trial dependent on Fortinet's own FDN phone-home infrastructure) -- none of the 6 Phase 4 vendor candidates offer genuine self-serve API trial access as of this date.

**Resolution path, if ever revisited:** would require the user (or Audspect) to go through Zscaler's sales/demo process and obtain a trial tenant with API credentials -- same shape as the Cloudflare blocker in item #1, but via a sales relationship rather than a missing payment method.

## Resolved items

*(none yet)*
