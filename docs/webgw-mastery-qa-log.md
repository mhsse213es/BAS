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

### 4. `internal/webgwefficacy` has zero production callers, repo-wide — RESOLVED 2026-10-15

**Status:** Resolved for `IndustryProfile`/`PrioritySummary`/`Describe`. Every other capability in this package (verification pipeline, mutation testing, coverage reporting, regulatory mapping) still has zero production callers -- this item now tracks only those.

**What was resolved:** Three production surfaces now call `internal/webgwefficacy` directly: the `cmd/webgwprofile` CLI (`webgwprofile <profile-name>`), `GET /api/webgw/industry-profiles` (JSON, same authenticated tier as `/api/ad/coverage`), and `GET /api/webgw/industry-profiles.html` (a new `internal/reporting` renderer, HTML only -- no PDF/Chrome-sidecar, deliberately lightweight). All three resolve profile names through the same single source of truth (`webgwefficacy.IndustryProfileNames`/`BuildIndustryProfile`), so none can drift from the other two. `IndustryProfile`'s own doc comment's "no file outside this package imports internal/webgwefficacy" caveat is now stale and needs updating to reflect this.

**What's still open:** the coverage-reporting (`coverage.go`), mutation-testing (`mutation.go`), and regulatory-mapping (`regulatory.go`) capabilities remain proven only by this package's own test suite -- no CLI, API, or report renders any of them yet.

**Resolution path, for what remains:** same pattern as `IndustryProfile` -- a CLI command or API endpoint reading `AudspectWebGWCoverageReport()`/`RunMutationTest`/`MapObligationToScenarioEvidence` directly, once there's a concrete consumer to design against.

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

### 7. `VerifyPolicyBaselineExpectation` never checks `StillActive` outside the exception-expiry path -- a disabled rule can still verdict `Pass` — RESOLVED 2026-10-15

**Status:** Resolved. Found during Phase 2b's final-review pass; pre-existing in Phase 3's `drift.go`, not introduced by Phase 2b -- `CloudflareGatewayPolicyProvider` was simply the first real, live producer of a meaningful `StillActive` value, which is what gave this gap real consequence for the first time.

**What was wrong:** `VerifyPolicyBaselineExpectation` (`drift.go`) only ever read a record's `StillActive` field inside the expired-exception check (`exp.ExceptionExpiresAt != nil && asOf.After(*exp.ExceptionExpiresAt) && latest.StillActive`). When no exception was declared -- the normal case -- a rule fully disabled in the real Cloudflare console (`enabled: true` → `false`) with its `action`/`filters`/`traffic` otherwise untouched produced an *identical* `ObservedConfigHash` (deliberately, since `configHashFor` hashes only the fields that determine enforced behavior) and therefore an unchanged `Pass` verdict -- even though the rule was no longer enforcing anything live.

**What changed (`ebae9d1c`):** added an independent `!latest.StillActive` → `Fail` branch before the exception-expiry check; simplified that branch's own condition (dropped the now-redundant `&& latest.StillActive`, since reaching it now guarantees StillActive is true). Fixed 3 pre-existing tests (`HashMatches_Pass`, `HashMismatch_Fail`, `MultipleRecords_MostRecentWins`) that implicitly relied on `StillActive`'s Go zero-value default never mattering outside the exception path -- they now explicitly set `StillActive: true`. Added a dedicated negative test (`DisabledRuleMatchingHash_Fail`) reproducing the exact gap (disabled rule, matching hash, no exception declared), confirmed it failed against the pre-fix code, then confirmed the fix made it pass.

**Independently reviewed 2026-10-15:** a fresh reviewer walked all 2×3×2 `(StillActive) x (exception state) x (hash)` combinations by hand, confirmed none produce an unreasonable verdict, traced `TestPolicyCorrectnessScenario_CloudflareRealResponseShape_FlowsThroughExistingPipeline` field-by-field to confirm it's genuinely unaffected (not just untouched by luck), confirmed the function's only callers are inside this package, and reran the full suite (133/0), `go vet`, `gofmt`, and the zero-cross-package-dependency check. No Critical or Important findings. One deferred Minor: `TestVerifyPolicyBaselineExpectation_ProviderErrorWithRecords_RecordsIgnored`'s `PolicyConfigEvidence` literal still omits `StillActive` (correctly irrelevant -- the error path returns before `latest` is ever read -- but worth a one-line comment for a future reader scanning for every literal that needs it). Not fixed; cosmetic only.

### 8. Branch reconciliation with `main`'s own parallel WebGW Mastery work — RESOLVED 2026-10-15

**Status:** Resolved. `main` was moved by a different concurrent session independently pursuing this same initiative (see `feedback_concurrent_sessions_main` memory) — its work was never credited toward this branch's own accounting until merged and verified here.

**What main had that this branch didn't:** `industry.go`/`industry_test.go` (BFSI/Healthcare/Manufacturing/MSP industry profiles, §3), an RBI (India) regulatory obligation added alongside the existing CERT-In one (`regulatory_test.go`), and a `NewCoverageReport` validation hardening (rejects any `DomainCoverage` with an unrecognized `Status`, closing a gap found in main's own review pass). All three merged in cleanly — none overlapped code this branch had touched since the fork point (`cc66be67`).

**What this branch had that main didn't:** Phase 2b's live `CloudflareGatewayPolicyProvider` (`cloudflare.go`), and a dedicated `dns.go` type family for domain 07's C2-domain-resolution angle.

### 9. RBI Cyber Security Framework circular (RBI/2015-16/418) cited in `regulatory_test.go` — reported repealed — RESOLVED 2026-10-16

**Status:** Resolved. Found as a side effect of the separate EmailGW Mastery initiative's own Phase 5 regulatory research (`docs/emailgw-mastery-qa-log.md` item #3), not by this package's own work — flagged to the user there, then fixed here on request.

**What was wrong:** `TestMapObligationToScenarioEvidence_RBICyberSecurityFramework_FirewallPerimeterSecurity`'s `RegulatoryObligation` (`rbi-csf-net-02`) cited the 2016 RBI Cyber Security Framework circular (RBI/2015-16/418, DBS.CO/CSITE/BC.11/33.01.001/2015-16) — independently verified against rbi.org.in at the time it was written, but multiple convergent secondary (compliance-vendor) sources now report that circular repealed effective 31 July 2026, superseded by the Reserve Bank of India (Commercial Banks — Cybersecurity, Technology: Risk, Resilience and Assurance Framework) Directions, 2026 (RBI/DoS/2026-27/410, DoS.CO.CSITEG.4/31.01.015/2026-27). None of these sources are RBI's own primary text (a scanned PDF behind a CAPTCHA gate), so the repeal is reported, not independently re-confirmed by this session, but it is consistent across every source found.

**What changed:** the obligation now cites the 2026 directions (`ID` renamed `rbi-cybersecurity-directions-2026-net-02`), with a `Note` recording the correction and why. The specific paragraph covering firewall/perimeter-security controls under the new directions was not located in this session's research (unlike EmailGW Mastery's own mail-security obligation, which did find its specific section) — `SourceReference` says so explicitly rather than inventing a paragraph number.

**Follow-up, also RESOLVED 2026-10-16:** `internal/compliance/mappings/rbi_csf.yaml`'s own metadata (`version`/`name`/`published_year`) was fixed too, at the user's request. It now cites the 2026 directions instead of the repealed 2016 circular. `id: RBI_CSF` was deliberately left unchanged — it's matched literally in `internal/api/handlers.go`'s `complianceShortName` and in several tests, the same way `CERT_IN`'s own id stays stable across MeitY's revisions. The file's 25 controls themselves were NOT individually re-verified against the new directions' own paragraph numbering (only the "Secure Mail and Messaging Systems" section was independently located, for a different package's own research) — carried forward as a reasonable baseline with that caveat documented in the YAML's own header comment, not silently presented as verified. Known gap, not filled: secondary sources report the 2026 directions add further areas (data governance, cryptography, secure SDLC, vendor/third-party risk, source code escrow, cloud security, teleworking) with no corresponding controls yet in this catalog — flagged in the YAML itself rather than fabricated. All `internal/compliance`/`internal/api` tests (including the Docker-backed `internal/api` suite) pass unchanged.

**The real collision, and how it was resolved:** both branches independently closed domain 04 with an EICAR-test-file scenario reusing `HTTPExpectation` — genuinely the same claim proven twice with different string literals. Kept this branch's `TestMalwareFileScenario_EICARTestFileBlocked`/`_Missed`; dropped main's `TestMalwareDownloadScenario_EICARTestFileBlocked`/`_Missed` as redundant, not complementary. Domain 07 was closed by both branches via genuinely different angles — this branch's `dns.go`-based C2-domain-resolution-policy test, and main's `HTTPExpectation`-based alternate-DoH-resolver-bypass test — kept **both**, since they prove different sub-capabilities (is a known-bad domain's resolution blocked, vs. is an unauthorized external resolver reachable at all), not the same one twice. §5's coverage-matrix table and `scenarios_test.go`'s coverage-reporting-test doc comment were updated to describe the merged, reconciled state. Full suite green post-merge (`go test ./internal/webgwefficacy/... -v`), zero internal-package dependency confirmed unchanged.

## Categorized test destinations (internal/webgwefficacy/destinations.go) — 2026-10-24

### Implemented coverage (proven in this repo)
- `AudspectWebGWDestinationCatalog()` returns 10 categorized destinations: phishing (3), command-and-control (3), URL filtering (2), and safe file download (2). Each category has known-bad destinations (must block) and known-good destinations (must allow), so a control that blocks everything or allows everything cannot pass.
- `NewTestDestination` enforces construction-time safety: host must sit under a reserved test TLD (`.test`, `.example`, `.invalid`, `.localhost`); IP literals, userinfo, non-http(s) schemes and empty notes are refused; safe-file destinations may only end in `eicar.com` or `sample.txt`.
- Every destination is verified through the existing `VerifyHTTPExpectation` pipeline in both directions: gateway evidence matching the expected action gives Prevention Pass, and evidence showing the opposite action gives Prevention Fail. The package suite passes (`go test ./internal/webgwefficacy/`).

### Verified detection (NOT yet shown)
- Every result above is fixture-backed. No request was sent to any destination, and no live web gateway was tested. The fixture evidence is written by the test itself, so passing shows the verifier's logic, not a real gateway's behaviour.
- No endpoint-executed scenario exists for these destinations yet. Running them from a real endpoint through a real gateway needs a lab gateway and is a staging task.
- The safe-file destinations name the EICAR anti-virus test file and a benign text file. Nothing was downloaded.
- Known limitation: `VerifyHTTPExpectation` sets Detection to Pass whenever any gateway evidence exists. That is pre-existing behaviour and is not changed here, so detection is not independently scored by these tests.

## Category breadth and file-type downloads (internal/webgwefficacy/destinations.go) — 2026-10-28

From `docs/cymulate-comparison-gap-analysis.md`, web gateway gaps 2 and 3. The catalog grows from 10 to 43 destinations.

- **URL filtering: 2 -> 16 categories.** Blocked: gambling, adult, anonymizer, peer-to-peer, malware-hosting, cryptomining, hacking,
  newly-registered-domain, illegal-drugs. Allowed: news, education, government, health, search-engines, software-updates, finance.
  Policy-dependent categories (social media, streaming, webmail, shopping) are deliberately not catalogued, because the expected
  action depends on the customer's own policy and would produce false failures.
- **File downloads: 2 -> 22.** Twelve blocked-by-file-type downloads (`sample.exe`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.jar`,
  `.msi`, `.dll`, `.iso`, `.lnk`), five allowed ordinary types (`.pdf`, `.docx`, `.xlsx`, `.csv`, `.png`, with the existing `.txt`), and the
  three published EICAR names (`eicar.com`, `eicar.com.txt`, `eicarcom2.zip`).
- **Safety rule widened, not removed.** A catalogued file name must now be an EICAR name or `sample.<ext>` for an extension in a fixed
  set (`permittedFileName`). `payload.exe`, `mimikatz.exe`, `eicar.exe`, `sample.exe.php` and anything else is still rejected at
  construction. Every host stays under a reserved test TLD, so no entry can reach a real site.
- **Verified:** `destinations_breadth_test.go` (written first; it did not compile before `permittedFileName` existed) pins the category
  and file-type coverage, the EICAR variants, and the name rules. Every destination is checked in both directions by the existing
  verifier test. The `webgwefficacy` package passes.

**Still open:** this is a catalog of URLs with expected actions, checked against fixtures. No request is sent through a real gateway,
so none of the 43 has been shown blocked or allowed by a product, and `.test` names do not resolve anywhere, so a live run needs a lab
gateway with DNS and a file server for these names (the endpoint-executed scenario, a staging task). The export lists 154 categories
and about 450 file kinds; this is a representative set, not a corpus.
