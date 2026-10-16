# WAF BAS Mastery — Deferred QA Log

This document tracks every verification gap, blocked item, or deliberate scope exclusion that came up while implementing the WAF BAS Mastery initiative (`waf.txt`, repo root — no separate design spec was written for the 10 phase packages; the 10 customer-facing enterprise assessment scenarios layered on top of them were driven from a written spec/plan pair, see `docs/superpowers/plans/2026-10-15-waf-bas-phase2-wafcatalog.md` for one example). Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming WAF Mastery is "done" or making any external maturity claim about it — mirrors the role `docs/webgw-mastery-qa-log.md` plays for Web Gateway BAS Mastery and `docs/av-mastery-qa-log.md` for AV/NGAV BAS Mastery.

**Note on this doc's own history:** like the AV/NGAV mastery QA log, this initiative's testing/QA detail was only ever reported in chat, never saved here, until this entry was added on 2026-10-16 in direct response to the user asking for it. Every item below is reconstructed from the actual current code (verified by direct read/grep on 2026-10-16) and from `waf.txt` itself, not from memory of what was said earlier.

## Open items

### 1. Real WAF vendor adapter — deferred by design, no live appliance integration exists

**Status:** Open, deferred by design (stated in `internal/wafval`'s own package doc comment, not an oversight).

**What's needed:** `internal/wafval` is explicitly "vendor-neutral" and "I/O-free" — it grades evidence it's handed, but produces none itself. A real adapter would need to drive an actual deployed WAF (Cloudflare, F5, AWS WAF, ModSecurity, etc.) with live test requests and pull its real enforcement/detection decisions back as `wafval.Observation` values.

**Why it's blocked:** `internal/wafval/wafval.go:7-8` states this directly: "The lab adapter that produces observations is a separate, deferred package." No lab/vendor access has been set up for this initiative, the same shape as AV/NGAV Mastery's own Defender-vertical gap (see `docs/av-mastery-qa-log.md` item #1).

**What this means today:** every one of the 10 customer-facing enterprise assessment scenarios in `internal/wafassessment` is fixture-backed only — each scenario's own `*Fixtures()` function hand-authors `wafval.CollectionResult` values rather than observing a real WAF. This is disclosed in-band in each scenario's `EvidenceRequirement` field ("fixture-backed in this phase").

**Resolution path:** build a real `wafval.Observation` producer against a specific vendor's API/logs once lab or vendor access exists — mirrors the AV/NGAV Defender-vertical resolution path exactly.

### 2. Retail/e-commerce and Government/critical-infrastructure industry profiles — named in `waf.txt` but not shipped

**Status:** Open, found during this QA-log pass (2026-10-16) by re-reading `waf.txt` §4 directly against what `internal/wafprofile` actually ships — not previously logged anywhere.

**What's needed:** `waf.txt`'s own §4 industry table names 6 sectors: BFSI, NBFC, Manufacturing, Healthcare, **Retail and e-commerce**, and **Government and critical infrastructure** — plus India/UAE regional profiles. `internal/wafprofile/catalog.go`'s `AudspectWAFProfileCatalog()` ships exactly 4 of those 6 (BFSI, NBFC, Manufacturing, Healthcare) plus the 2 regional profiles (India, UAE). Retail/e-commerce and Government/critical-infrastructure have no `Profile` of their own.

**Why it's open rather than resolved by a documented exclusion:** unlike AV/NGAV Mastery's own Government/MSP exclusion (`internal/avprofile`'s package doc comment explicitly states why those two were left out — no vector cleanly represents their distinguishing concern), `internal/wafprofile` has no equivalent doc comment explaining why Retail/e-commerce or Government/critical-infrastructure were skipped. `wafcatalog`'s real vector set (API/auth/rate/cache/bot-abuse families) plausibly covers Retail and e-commerce's own named priorities ("checkout, payment workflows, account abuse, inventory APIs, scraping and bot controls") reasonably well — this looks like an uncaptured gap, not a reasoned exclusion.

**Resolution path:** add `WAFPROFILE-RETAIL` (likely API-001..003, RATE-001..002, bot-abuse vectors) and either add `WAFPROFILE-GOVERNMENT` (if a vector set genuinely maps to its named priorities — availability, exposed endpoints, logging) or document explicitly why it doesn't, the way `avprofile` did for Government/MSP.

### 3. Three of the 9 new enterprise scenarios wire only 2 vectors each, with no deliberately-untested one

**Status:** Open, deferred as low-risk — found during the final whole-branch review (2026-10-16, fresh Sonnet subagent, 0 Critical/0 Important findings overall).

**What's confirmed (verified directly 2026-10-16):** `AudspectHTTPProtocolIntegrityFixtures()` (HTTPPARSE-001 Missed, HTTPPARSE-002 Blocked), `AudspectFileUploadFixtures()`-equivalent in `catalog_fileupload.go` (FILEUP-001 Missed, FILEUP-002 Blocked), and the routing/cache scenario in `catalog_routingcache.go` (CACHE-001 Missed, CACHE-002 Blocked) each wire exactly 2 vectors, both with fixtures supplied — no vector is left out of the fixture map to exercise the `ScenarioIncomplete`-via-`UntestedVectorIDs` path.

**Why it's deferred:** `EvaluateScenario`'s `Incomplete`-without-failure branch is already covered by other scenarios' own seed data (confirmed at Phase 4 of the exploit-prevention scenario and reused by the shared `aggregateByPrecedence` rule) — this is a gap in these 3 scenarios' own seed data, not an uncovered code path overall.

**Resolution path:** add a third, deliberately-fixture-omitted vector to each of these 3 scenarios' catalogs if/when a reviewer wants per-scenario Incomplete coverage, not just suite-wide coverage.

### 4. Only 5 of 10 enterprise scenarios have a dedicated handler-level test

**Status:** Open, deferred as low-risk — found during the same final whole-branch review.

**What's confirmed (verified directly 2026-10-16):** `internal/api/waf_assessment_handlers_test.go` has dedicated tests for exactly 5 scenarios: Exploit Prevention (`TestGetWAFExploitPreventionScenario_ReturnsRealFailOutcome` + its HTML counterpart), HTTP Protocol Integrity, API Protection, Detection/Telemetry, and Origin Resilience. The other 5 (Automated Abuse, Policy Integrity, Routing/Cache, File Upload, Legitimate Traffic) rely only on the generic `wafScenarioJSONHandler`/`wafScenarioHTMLHandler` closure's own tests plus `internal/wafassessment`'s own package-level tests — never exercised through a scenario-specific handler test.

**Why it's deferred:** the generic handler closure is itself tested, and each scenario's underlying `EvaluateScenario` call is tested at the `wafassessment` package level — this is a gap in handler-level test density, not in logical coverage.

**Resolution path:** add the remaining 5 scenario-specific handler tests if/when a regression in the generic closure's routing needs scenario-level evidence to debug.

## Resolved items

### 5. Final whole-branch review of enterprise scenarios 02-10 — RESOLVED 2026-10-16

**Status:** Resolved — review ran clean.

**What was reviewed:** a fresh Sonnet subagent reviewed the whole branch (`de38a206..dc983084`) covering all 9 new enterprise assessment scenarios layered on the 10 phase packages.

**Result:** 0 Critical, 0 Important findings — "ready to ship as-is." Specifically confirmed by direct trace: the detection-telemetry and origin-resilience scenarios' own non-`wafval` verdict taxonomies (`detectionOutcomeClass`, `originOutcomeClass`) never leak into `wafval`'s shared `failingVerdict` classifier (each evaluation kind with its own closed taxonomy is classified independently, since the taxonomies share no failing-value strings — reusing `failingVerdict` across them would have silently misclassified every real failure as a pass); `failingVerdict`'s `VerdictIncorrectlyBlocked` addition (needed for scenario 9's `ClaimFalsePositive` vectors) is provably unreachable from any `ClaimPrevention` evaluation, so it's additive and regression-safe; the scenario registry, `routes.go`, and `rbac_matrix_test.go` all list the exact same 10 slugs. Items #3 and #4 above are this review's only deferred minors that weren't fixed in the same pass.

## Test/build summary (as of 2026-10-16, commit `dc983084`)

- `go build ./...` and `go vet ./...`: clean throughout every phase of this initiative.
- All 10 phase packages (`wafval`, `wafcatalog`, `wafpolicygap`, `wafapiflow`, `wafbotabuse`, `waforigin`, `wafdetection`, `wafprofile`, `wafverify`) plus `internal/wafassessment` (the 10 enterprise scenarios) pass their own test suites.
- `internal/wafefficacy` + `internal/reporting/waf_coverage.go`/`waf_industry_profiles.go` + `internal/api/waf_efficacy_handlers.go` console integration: `/api/waf/coverage(.html)`, `/api/waf/industry-profiles(.html)` — all tested.
- `/api/waf/scenarios/<slug>(.html)` × 10 (slug ≠ catalog `EnterpriseScenario.ID`, resolved through a shared slug-keyed registry): all 10 present in both `routes.go` and `rbac_matrix_test.go`, confirmed not contributing to `TestRBACMatrix_NoDrift`'s failure list (that failure list is pre-existing, unrelated emailgw/webgw drift — see item below).
- `TestRBACMatrix_NoDrift`: red, but only from the same pre-existing, unrelated `emailgw-mastery` merge drift (`e783e7a2`) on `/api/emailgw-*`/`/api/webgw/industry-profiles*` routes documented in `docs/av-mastery-qa-log.md` — confirmed never caused by this initiative, not fixed here (belongs to a different initiative).
