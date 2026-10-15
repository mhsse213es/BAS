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

### 4. `internal/webgwefficacy` has zero production callers, repo-wide

**Status:** Open, deferred by scope choice (not a code defect).

**What's needed:** No CLI command, HTTP handler, or report renderer anywhere in this repository imports `internal/webgwefficacy` yet -- confirmed via `grep -rl "internal/webgwefficacy"` outside the package itself returning nothing. Every capability (verification pipeline, mutation testing, coverage reporting, regulatory mapping, industry profiles' `PrioritySummary`) is proven real and correct by this package's own test suite, but none of it is wired into anything a user or operator actually runs.

**Why it's deferred:** Every phase (1 through 5, plus the later domain-04/07/RBI/industry-profile work) scoped itself to "prove the capability end-to-end against real or fixture data," never to "surface it in the product." This was a deliberate, repeated scope choice, not an oversight -- but it means `IndustryProfile.PrioritySummary`'s own doc comment now explicitly warns that "real reader" means "read by this package's tests," not "called by the product."

**Resolution path:** wire at least one capability (most naturally `PrioritySummary`, or the coverage/mutation-testing reports) into a CLI command or API endpoint, once there's a concrete consumer (a report page, a CLI flag) to design against.

### 5. `IndustryProfile`/`NewIndustryProfile` — 3 low-risk validation gaps, latent given today's 4 shipped profiles

**Status:** Open, deferred as low-risk (found during the whole-arc final review 2026-10-15).

**What's needed, if ever revisited:**
1. `NewIndustryProfile` doesn't reject a duplicate ID within `priorityDomainIDs` -- a profile could list the same domain twice with no construction-time error.
2. `businessImpactWeight` keys aren't required to be a subset of `priorityDomainIDs` -- a weight entered for a non-priority domain validates fine and is silently never rendered by `PrioritySummary` (which only iterates `PriorityDomainIDs`).
3. `weightLabel`'s `%.1f` formatting rounds to one decimal place -- a future profile using e.g. `0.85` would render as `"weight 0.8"` or `"weight 0.9"`, losing the configured precision.

**Why it's deferred:** none of the 4 shipped profiles (BFSI/NBFC, Healthcare, Manufacturing/OT-adjacent, MSP/shared-tenant) hit any of these three; each is latent, not live.

**Resolution path:** cheap insurance to add if/when a 5th industry profile is ever shipped -- re-check against these three specifically at that point.

### 6. `mutation.go`/`coverage.go` -- 5 deferred minors from the Phase 5 design-upgrade review

**Status:** Open, deferred as low-risk (found 2026-10-15).

**What's needed, if ever revisited:**
1. `RunMutationTest` has no nil-guard on its three closure parameters -- passing `nil` panics with no caller-facing message.
2. `MutationResult` discards each stage's `VerdictDetail.Reason` text, keeping only the raw `WebGWVerdict` -- diagnosing *why* `RecoveryConfirmed` came back false requires re-deriving the reason from the original closures.
3. `NewCoverageReport` doesn't reject an empty `DomainID` on its own (only catches it indirectly via the duplicate-ID check if a second empty-ID entry follows).
4. `CoverageReport.Summary()`'s zero-domain branch returns a hardcoded string rather than going through the same `fmt.Sprintf` path as every other branch -- only non-emptiness is tested, not exact content.
5. `CoverageReport` has no convenience method for listing not-covered domain *names* (only a count via `NotCoveredCount()`) -- a caller wanting a remediation-ready list has to call `AudspectWebGWCoverageReport()` again and filter manually.

**Why it's deferred:** none block any phase's own exit criteria; all are edge-case hardening a reviewer flagged as worth doing only once a second real caller emerges.

**Resolution path:** revisit if/when this package gains a production caller (see item #4) that would actually exercise these edges.

## Resolved items

*(none yet)*
