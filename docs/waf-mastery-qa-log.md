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

### 0. `TestRBACMatrix_NoDrift` — the pre-existing emailgw/webgw drift referenced throughout this doc is now RESOLVED, by a different concurrent session

**Status:** Resolved, not by this initiative. Confirmed 2026-10-16 (same day this doc was written): `TestRBACMatrix_NoDrift` now passes cleanly. A concurrent session actively working in this same shared checkout appears to have fixed the missing `routeMatrix` entries for `/api/emailgw-*`/`/api/webgw/industry-profiles*` independently. Every other item in this doc that cites that drift as "pre-existing, unrelated" is still accurate as a historical note — it just no longer reproduces as of this date.

### 2. Retail/e-commerce and Government/critical-infrastructure industry profiles — RESOLVED 2026-10-16

**Status:** Resolved, same day it was found.

**What was wrong:** `waf.txt`'s own §4 industry table names 6 sectors: BFSI, NBFC, Manufacturing, Healthcare, **Retail and e-commerce**, and **Government and critical infrastructure** — plus India/UAE regional profiles. `internal/wafprofile/catalog.go`'s `AudspectWAFProfileCatalog()` shipped only 4 of those 6 (BFSI, NBFC, Manufacturing, Healthcare) plus the 2 regional profiles. Unlike AV/NGAV Mastery's own Government/MSP exclusion (which has an explicit doc comment explaining why no vector fits), `wafprofile` had no such comment here — this was a genuine uncaptured gap, not a reasoned exclusion.

**What changed (`60dc56e8`):** added `WAFPROFILE-RETAIL` (API-001 checkout/orders BOLA, API-003 inventory-API data exposure, AUTH-001 account-abuse credential-stuffing, RATE-001 pricing-endpoint scraping/bot burst; PCI-DSS Unverified compliance reference, same disclosure style as BFSI's own) and `WAFPROFILE-GOVERNMENT` (PATHTRAV-001 exposed-endpoint traversal, SSRF-002 cloud-metadata exposure, SQLI-001 sensitive-data exposure, POLICY-002 legacy-compatibility exception; NIST Cybersecurity Framework Unverified reference, explicitly disclosed as a generic placeholder since `waf.txt` names no specific national framework for this row). `waf.txt`'s own named "logging" priority for Government has no corresponding `wafcatalog` vector — the new profile's `Rationale` says so explicitly rather than forcing a weak mapping, pointing at `internal/wafdetection` instead. All 3 places that hardcoded the profile count (`wafprofile`'s own test, `internal/reporting`'s HTML report test, `internal/api`'s JSON handler test) were updated 6→8 total / 4→6 industry. Full `go build`/`go vet`/package test suite green.

### 5. Final whole-branch review of enterprise scenarios 02-10 — RESOLVED 2026-10-16

**Status:** Resolved — review ran clean.

**What was reviewed:** a fresh Sonnet subagent reviewed the whole branch (`de38a206..dc983084`) covering all 9 new enterprise assessment scenarios layered on the 10 phase packages.

**Result:** 0 Critical, 0 Important findings — "ready to ship as-is." Specifically confirmed by direct trace: the detection-telemetry and origin-resilience scenarios' own non-`wafval` verdict taxonomies (`detectionOutcomeClass`, `originOutcomeClass`) never leak into `wafval`'s shared `failingVerdict` classifier (each evaluation kind with its own closed taxonomy is classified independently, since the taxonomies share no failing-value strings — reusing `failingVerdict` across them would have silently misclassified every real failure as a pass); `failingVerdict`'s `VerdictIncorrectlyBlocked` addition (needed for scenario 9's `ClaimFalsePositive` vectors) is provably unreachable from any `ClaimPrevention` evaluation, so it's additive and regression-safe; the scenario registry, `routes.go`, and `rbac_matrix_test.go` all list the exact same 10 slugs. Items #3 and #4 above are this review's only deferred minors that weren't fixed in the same pass.

## Test/build summary (as of 2026-10-16, commit `60dc56e8`)

- `go build ./...` and `go vet ./...`: clean throughout every phase of this initiative.
- All 10 phase packages (`wafval`, `wafcatalog`, `wafpolicygap`, `wafapiflow`, `wafbotabuse`, `waforigin`, `wafdetection`, `wafprofile`, `wafverify`) plus `internal/wafassessment` (the 10 enterprise scenarios) pass their own test suites. `wafprofile` now ships 8 profiles (6 industry + 2 regional, see item #2).
- `internal/wafefficacy` + `internal/reporting/waf_coverage.go`/`waf_industry_profiles.go` + `internal/api/waf_efficacy_handlers.go` console integration: `/api/waf/coverage(.html)`, `/api/waf/industry-profiles(.html)` — all tested.
- `/api/waf/scenarios/<slug>(.html)` × 10 (slug ≠ catalog `EnterpriseScenario.ID`, resolved through a shared slug-keyed registry): all 10 present in both `routes.go` and `rbac_matrix_test.go`.
- `TestRBACMatrix_NoDrift`: now passes cleanly as of 2026-10-16 — see item #0.


## CVE assessment catalog (internal/cvecatalog, internal/cveval, internal/cvelab) — 2026-10-24

A separate, new initiative against the same Cymulate-comparison gap list as the WAF payload-corpus work above
(priority 2 of that list: CVE-specific simulations). Built in this order, per the owner's own milestone, with
safeguards built and tested before any payload beyond the first CVE was added.

**Catalog (`internal/cvecatalog`):** `CVEEntry` carries CVE ID, CWE IDs, severity, affected product + version
ranges, preconditions, execution profile, at least one external reference, a `LastVerified` date, and two
`ConfigFixture` values (vulnerable/patched) with an `Implies` field the constructor forces to match which fixture
it is — a vulnerable fixture can never be miscoded to imply `NOT_VULNERABLE`. One entry shipped: CVE-2021-44228
(Log4Shell), `ExecutionProfile: lab_capable`. `ExecutionProfile: lab_capable` is a statement about what kind of
check this CVE supports in principle — **no real network-sending prober exists for it yet** (see below).

**Verdict contract (`internal/cveval`):** five terminal verdicts — `VULNERABLE`, `NOT_VULNERABLE`,
`INCONCLUSIVE`, `ERROR`, `SKIPPED` — with `SKIPPED` first-class so a check that never ran is never silently
absent from a report. `ValidateResult` enforces "never report a CVE as tested merely because a Result value
exists": `VULNERABLE`/`NOT_VULNERABLE` require non-empty `Evidence.Source` and `Evidence.Detail`; `ERROR`/
`SKIPPED`/`INCONCLUSIVE` require a free-text `Detail`.

**Lab execution gate (`internal/cvelab`):** the safeguards the owner asked to be built before more payloads.
Live execution requires, in order: the entry's `ExecutionProfile` must be `lab_capable`; `RunRequest.Authorized`
must be explicitly true (never inferred — obtaining real authorization is the caller's own integration concern,
same discipline as `wafval.Expectation.PolicyVerified`); a `LabTarget` on an explicit, exact-match allow-list
(`AllowedLabTargets`, operator-configured, empty by default); `IsPublicAddress` refuses any target that is not a
literal private/loopback/link-local IP — **a hostname target is refused outright, never resolved**, to close a
DNS-based bypass, and a public address is refused even if it was allow-listed by mistake (tested directly); a
positive `Timeout` and `MaxRequests`; and a configured `Prober` (nil by default — no live execution is possible
in any deployment that hasn't wired one in). A `Prober` that times out reports `INCONCLUSIVE`, never `ERROR` or
a guessed verdict; a `Prober` that returns a `cveval`-invalid result is downgraded to `ERROR` rather than passed
through, since it is external, pluggable code. Every assessment — fixture or live, found or unknown CVE — is
audited through a fail-closed `Audit` interface (a failed write aborts before any further work), mirroring
`internal/k8sscenario`'s own audit discipline.

**What does not exist yet, stated plainly:** no real `Prober` implementation. `internal/cvelab`'s `Prober`
interface is the deferred seam, exactly like `wafval`'s own "the lab adapter that produces observations is a
separate, deferred package" line — building a live Log4Shell JNDI-triggering sender without a real lab to test
it against was explicitly declined this round, per the owner's own instruction ("do not introduce external
callbacks or uncontrolled command execution"). Only one CVE is cataloged. No console/API wiring exists for this
initiative; it is a Go-internal package only, same scope as the owner's milestone asked for.

**Tests:** `go test ./internal/cveval/... ./internal/cvecatalog/... ./internal/cvelab/...` — all pass, covering
catalog construction validation (malformed CVE/CWE IDs, missing references, bad date, fixture `Implies`
mismatches, duplicate indicators), fixture evaluation (exact-match only, no substring match), and every live-
execution gate individually (not lab-capable, unauthorized, off-allow-list, public address even if allow-listed,
missing timeout, missing request limit, no prober, probe timeout vs. probe error vs. an invalid probe result,
fail-closed audit on the first write). Full WAF regression suite (`wafcatalog`/`wafassessment`/`wafevasion`/
`wafpolicygap`/`wafprofile`/`wafval`/`waforigin`) and `go build ./...`/`go vet ./...` all pass unchanged.
