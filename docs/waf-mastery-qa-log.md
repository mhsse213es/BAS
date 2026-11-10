# WAF BAS Mastery — Deferred QA Log

This document tracks every verification gap, blocked item, or deliberate scope exclusion that came up while implementing the WAF BAS Mastery initiative (`waf.txt`, repo root — no separate design spec was written for the 10 phase packages; the 10 customer-facing enterprise assessment scenarios layered on top of them were driven from a written spec/plan pair, see `docs/superpowers/plans/2026-10-15-waf-bas-phase2-wafcatalog.md` for one example). Each entry stays here until it's actually resolved; resolving one means updating its own entry with the resolution and date, not deleting it.

This is the single place to check before claiming WAF Mastery is "done" or making any external maturity claim about it — mirrors the role `docs/webgw-mastery-qa-log.md` plays for Web Gateway BAS Mastery and `docs/av-mastery-qa-log.md` for AV/NGAV BAS Mastery.

**Note on this doc's own history:** like the AV/NGAV mastery QA log, this initiative's testing/QA detail was only ever reported in chat, never saved here, until this entry was added on 2026-10-16 in direct response to the user asking for it. Every item below is reconstructed from the actual current code (verified by direct read/grep on 2026-10-16) and from `waf.txt` itself, not from memory of what was said earlier.

## Open items

## Resolved items

### 1. Real WAF vendor adapter — RESOLVED (partial) 2026-11-10 -- self-hosted, no vendor tenant used or needed

**Status:** Resolved for one real engine, with an honestly bounded scope. The user confirmed up front that no
commercial WAF tenant (Cloudflare, F5, AWS WAF, etc.) is available for this initiative; rather than stay blocked on
that, this used the same self-owned-target philosophy `internal/apibas/lab` already uses elsewhere in this repo:
self-host a real, open-source WAF engine instead of a vendor API.

**What was built:** `lab/wafmodsec/docker-compose.yml` runs a real ModSecurity + OWASP CRS v4 WAF
(`owasp/modsecurity-crs`, nginx variant, pinned by image digest) in front of a permissive HTTP echo origin
(`mendhak/http-https-echo`, also pinned by digest) -- no vendor account, tenant, or signup involved anywhere.
`internal/vendors/modsecwaf` (`client.go`) is a real, I/O-performing HTTP client: `BuildRequest` turns a real
`wafcatalog.RequestTemplate` into a genuine `*http.Request` (implements the `""` and `"query:<param>"`
`PayloadLocation` forms only -- other forms return an explicit error rather than being silently misinterpreted),
and `Client.Send` executes it against the live container. `internal/wafmodsec` (`bridge.go`) mirrors
`internal/avdefender`'s split from `internal/vendors/defender` exactly: it turns the real raw HTTP response into
two independent `wafval.CollectionResult` values -- the WAF engine's own enforcement decision (HTTP status code)
and the origin app's own receipt confirmation (the echo server's distinctive JSON body, present only when a
request actually reached it) -- both derived from the one proxied response, which is legitimate because the echo
origin's body is produced by a genuinely separate process/container, not inferred.

**Live-verified, not just built:** `internal/wafmodsec/live_test.go`'s `TestLive_RealWAFCatalogVectors_AgainstLiveModSecurityLab`
was actually run against the real running container this session (gated behind `WAF_MODSEC_LAB_URL`, so it never
runs in the normal `go test ./...` suite). It drives 4 real `wafcatalog` vectors end to end -- `SQLI-001`,
`XSS-001`, `PATHTRAV-001`, `HTTPPARSE-002`, one per family, chosen because each uses only the `PayloadLocation`
forms `BuildRequest` implements -- both malicious and benign legs, and asserts the real `wafval.Verdict`
`wafval.EvaluateClaim` derives from the real response. All 8 sub-tests passed against the live container:
malicious legs resolved to `VerdictBlocked` (`403` from ModSecurity for SQLi/XSS/path-traversal, `405` from
nginx's own method whitelist for the TRACE verb-tampering case -- both equally prevent origin reach, which is all
this axis models), benign legs resolved to `VerdictAllowed`. `lab/wafmodsec/smoke.sh` is a standalone curl-based
re-check of the same 8 cases, also run and passing. This is a stronger resolution than the AV/NGAV Defender-bridge
precedent this doc's old text pointed at -- that bridge was built but never run against a live tenant; this one
has been run, live, for real.

**What's still genuinely open (disclosed, not hidden):**
- Only 4 of the catalog's 65 vectors are wired -- the rest need `header:`/`body:json:`/`body:multipart:` support in
  `modsecwaf.BuildRequest`, which does not exist yet (explicit error today, not silent misinterpretation).
- `wafmodsec` does not parse ModSecurity's audit log, so it never asserts `wafval.DetectionMatched`/`DetectionNotMatched`
  -- an allowed-through malicious request resolves to `VerdictInconclusive` under `ClaimPrevention`, not
  `VerdictMissed`, until that follow-up lands.
- Wired into exactly ONE of the 10 `internal/wafassessment` enterprise scenarios and exactly one `internal/api`
  route (see follow-ups below) -- a console user still sees the fixture-backed result for every other scenario.
- This closes the gap for ModSecurity/CRS specifically, not for a commercial vendor API (Cloudflare/F5/AWS WAF) --
  if/when the user gets a real tenant for one of those, that integration is still new work, on the
  `internal/vendors/defender`-style pattern this now has a second real example of.

**Same-day follow-up: wired into `AudspectExploitPreventionScenario`.** `internal/wafmodsec/exploitprevention.go`'s
`BuildExploitPreventionLiveFixtures` drives 3 of that scenario's 8 contributing vectors (`SQLI-001`, `XSS-001`,
`PATHTRAV-001` -- the ones `BuildRequest` can replay) against the live lab and hands the result to the real,
UNMODIFIED `wafassessment.EvaluateScenario` -- `wafassessment` itself was not touched, keeping it vendor-neutral
and I/O-free; the live-wiring glue lives entirely in `internal/wafmodsec`, which is free to depend on it. The
other 5 vectors get no fixture at all, on purpose, so they surface through `UntestedVectorIDs` rather than being
papered over. `TestLive_ExploitPreventionScenario_ThreeOfEightVectorsLive` ran this against the real container:
all 3 live vectors resolved `VerdictBlocked`, the other 5 came back in `UntestedVectorIDs`, and the scenario's
real outcome was `ScenarioIncomplete` -- correct, since 5 of 8 vectors have no live evidence yet, and precedence
never lets an untested vector pass silently.

**Second same-day follow-up: wired into the API, `GET /api/waf/scenarios/exploit-prevention/live`.** Serves the
above through `internal/wafmodsec.RunExploitPreventionLive`, in the exact same JSON shape every other
`/api/waf/scenarios/<slug>` route uses, registered at the same `tierAny` (Viewer+Analyst+Admin, JWT-only) tier --
safe at that tier because the live target comes from the server's own `WAF_MODSEC_LAB_URL` environment variable,
never from the request, so there is no SSRF surface from this being broadly readable. Missing that env var returns
`503` naming it, rather than ever silently falling back to the fixture-backed result; an unreachable lab returns
`502`.

This surfaced a real, pre-existing honesty gap worth fixing properly rather than working around: `wafassessment`'s
`EvaluateScenarioWithSeverities` hardcoded every `VectorAssertion.EvidenceSource` to `EvidenceSourceFixture` --
`EvidenceSourceLiveExecution` existed only "for forward compatibility," per its own doc comment, with no code path
able to produce it. Serving this route as-is would have mislabeled genuinely live evidence as a fixture in the
JSON response. Fixed with one small, backward-compatible addition: `VectorFixture` gained an `EvidenceSource`
field; `EvaluateScenarioWithSeverities` now uses it when set and falls back to `EvidenceSourceFixture` when it
isn't (every existing hand-authored fixture across all 10 scenarios leaves it unset, so none of their behavior
changed -- proven by the full existing `wafassessment` suite staying green, plus one new test,
`TestEvaluateScenario_FixtureEvidenceSourceOverride_PropagatesToAssertion`). `BuildExploitPreventionLiveFixtures`
now sets `EvidenceSourceLiveExecution` on its 3 live fixtures.

Live-verified: `TestWafExploitPreventionLiveJSONHandler_RealLab_ReturnsRealLiveOutcome` drives the handler itself
(no router, no mock) against the real running container -- `outcome":"incomplete"`, the 3 live vectors render
`"evidenceSource":"live_execution"`, no assertion anywhere renders `"fixture"`, and the 5 untested IDs are present.
A second, fast unit test (`..._NoLabConfigured_Returns503`) proves the refusal path with no live dependency.
`TestRBACMatrix_NoDrift`/`TestRBACMatrix_AuthorizationBoundary` both pass with the new route matrixed.

**Third same-day follow-up: wired 4 more of the other 9 scenarios, partially; disclosed why the remaining 5
genuinely can't be yet.** Same `Run<Scenario>Live(ctx, client)` pattern as `RunExploitPreventionLive`, one new file
each in `internal/wafmodsec`:

| Scenario | Live vectors | Verdicts (confirmed against the real lab) |
|---|---|---|
| `http-protocol-integrity` | `HTTPPARSE-002` (1/3) | `Blocked` |
| `routing-cache-integrity` | `CACHE-002`, `CACHE-003` (2/3) | `Inconclusive`, `Blocked` |
| `api-protection` | `API-003`, `APIFLOW-005` (2/8) | `Inconclusive`, `Inconclusive` |
| `legitimate-traffic` | `SQLI-001`/`XSS-001`/`PATHTRAV-001`/`RATE-001` benign legs (4/6) | all `Allowed` |

`api-protection` mixes two independent catalogs (`wafcatalog`'s `API-003` and `wafapiflow`'s `APIFLOW-005`) through
one `modsecwaf.Client` via a small local converter (`apiflowToWafcatalogTemplate`) between their structurally
identical `RequestTemplate` types -- no change to `modsecwaf` itself. `legitimate-traffic` drives each vector's
BENIGN counterpart (not its malicious payload), evaluated as `wafval.ClaimFalsePositive` -- `BuildCollectionResults`
needed no change either, since it reports Enforcement/Origin from the raw response the same way regardless of
which leg produced it.

The `Inconclusive` verdicts on `CACHE-002`/`API-003`/`APIFLOW-005` are a real, curl-confirmed finding against the
live container, not an adapter bug: CRS genuinely returns 200 for all three, because a generic WAF has no
business-logic or cache-layer awareness to catch a static-extension cache-deception trick, a `fields=*`
over-exposure, or an absurd `limit=` value.

This surfaced a SECOND occurrence of the exact `EvidenceSource`-hardcoding bug fixed in the API follow-up above:
`EvaluateLegitimateTrafficScenario` (in `falsepositive.go`) had the identical hardcode-to-`EvidenceSourceFixture`
bug as `EvaluateScenarioWithSeverities`, just never caught because nothing had driven live evidence through it
yet. Fixed the same way, with the same new-test-first proof
(`TestEvaluateLegitimateTrafficScenario_FixtureEvidenceSourceOverride_PropagatesToAssertion`).

**5 scenarios get NO live wiring, for real, disclosed reasons:**
- `automated-abuse` -- every vector (`RATE-001/002`, `BOTABUSE-001..004`) is a multi-request, timed-burst
  behavioral claim; a single `modsecwaf.Client.Send` call can't honestly represent "50 requests in 2 seconds" or
  "the 501st request in a 60-second window." Driving one request and calling it a rate-limit test would be a false
  claim, not a thin slice.
- `detection-telemetry` -- evidence is SIEM/alert-pipeline completeness and timing; there is no HTTP request to
  replay at all.
- `file-upload-content-trust` -- every vector is `body:multipart:...`, a real, disclosed `BuildRequest` gap.
- `origin-resilience` -- deployment-topology claims (direct-origin reachability, fail-open, cross-node consistency)
  need a multi-node/dual-path network setup this lab's single WAF-fronted origin doesn't have.
- `policy-integrity` -- a genuine two-leg baseline-vs-weakened policy comparison; this lab has exactly one fixed
  CRS configuration, with no second, deliberately-weakened policy to compare against.

**Fourth same-day follow-up: wired the other 4 live-partial scenarios into the API too.** `wafExploitPreventionLiveJSONHandler`'s
body was pulled out into a new shared `wafScenarioLiveJSONHandler(run liveScenarioRunner)` -- the live counterpart
of the existing fixture-backed `wafScenarioJSONHandler(slug)` factory, parameterized by `internal/wafmodsec`'s
`Run<Scenario>Live` function instead of a slug. 4 new routes registered the same way, through a `liveScenarios`
slice in `routes.go` (exploit-prevention's own route now goes through the same loop):

- `GET /api/waf/scenarios/http-protocol-integrity/live`
- `GET /api/waf/scenarios/routing-cache-integrity/live`
- `GET /api/waf/scenarios/api-protection/live`
- `GET /api/waf/scenarios/legitimate-traffic/live`

Same `tierAny` RBAC tier, same 503-if-unconfigured/502-if-unreachable refusal, same never-falls-back-to-fixture
guarantee as exploit-prevention's route -- all inherited for free from the shared handler, not reimplemented per
route. `TestRBACMatrix_NoDrift`/`AuthorizationBoundary` pass with all 4 new routes matrixed. Live-verified: all 4
routes hit via the handler itself (no router, no mock) against the real running container, verdicts matching the
curl-confirmed ground truth from the third follow-up exactly (`HTTPPARSE-002` blocked, `CACHE-003` blocked,
`CACHE-002`/`API-003`/`APIFLOW-005` inconclusive, all 4 legitimate-traffic benign legs allowed), every assertion
`evidenceSource:"live_execution"`, none `"fixture"`.

**Fifth same-day follow-up: built real multipart support and unblocked `file-upload-content-trust`.** User response
to the disclosed 5-scenario gap: "if each needs real new capability so be it" -- greenlighting real new work
instead of leaving them unwired. Started with the most tractable: `modsecwaf.BuildRequest` gained a real
`"body:multipart:<field>"` case (RED-first: 2 new tests proving the raw payload travels verbatim on the wire,
then implemented with Go's `mime/multipart`). `<field> == "filename"` sends Payload as the file's NAME (a fixed,
inert placeholder content); any other `<field>` sends Payload as the file's CONTENT (a fixed placeholder
filename) -- either way the real attack string reaches the WAF unescaped, same discipline as every other
PayloadLocation form.

New `internal/wafmodsec/fileuploadcontenttrust.go` wires 2 of `AudspectFileUploadContentTrustScenario`'s 3
vectors: `FILEUP-003` (path-traversal filename) is curl-confirmed `Blocked` -- CRS's generic traversal rule fires
on the filename regardless of which field carries it. `FILEUP-001` (PHP web-shell content) is curl-confirmed
`Inconclusive` -- CRS's default rule set does not inspect uploaded file content for embedded PHP, a genuine,
confirmed finding about this configuration, not a bug. `FILEUP-002` (a decompression-bomb archive) stays
unwired even with multipart support in place: its catalog `Payload` is a human description, not real bytes, and
this lab's origin has no archive-extraction logic for a bomb to even detonate against -- multipart support alone
doesn't make this one honestly replayable.

Wired into the API too, same loop as the other 5 live routes: `GET /api/waf/scenarios/file-upload-content-trust/live`.
Live-verified end to end (adapter + scenario + API), `TestRBACMatrix_NoDrift`/`AuthorizationBoundary` pass with the
new route matrixed.

**Resolution path for what's left:** extend `BuildRequest`'s remaining PayloadLocation cases (header:/body:json:/body:xml:);
add audit-log parsing to `wafmodsec` so a real `VerdictMissed` becomes claimable; a second, deliberately-weakened
lab instance to unblock `policy-integrity`; a burst-driving harness (plus real rate-limit config in the lab) to
unblock `automated-abuse`; a multi-node/dual-path lab topology to unblock `origin-resilience`; a real alerting
backend to unblock `detection-telemetry`.

See `lab/wafmodsec/README.md` for how to run the lab and every live test (`go test ./internal/wafmodsec/... -run TestLive_ -v`).

### 3. Three of the 9 new enterprise scenarios wire only 2 vectors each, with no deliberately-untested one — RESOLVED 2026-11-10

**Status:** Resolved (see `docs/api-bas-mastery-qa-log.md`, "REQ-007: WAF assessment hardening", same-day follow-up,
for full detail).

**What was wrong (found 2026-10-16):** `AudspectHTTPProtocolIntegrityFixtures()` (HTTPPARSE-001 Missed,
HTTPPARSE-002 Blocked), `catalog_fileupload.go`'s fixtures (FILEUP-001 Missed, FILEUP-002 Blocked), and
`catalog_routingcache.go`'s fixtures (CACHE-001 Missed, CACHE-002 Blocked) each wired exactly 2 vectors, both with
fixtures supplied — no vector was left out of the fixture map to exercise the `ScenarioIncomplete`-via-
`UntestedVectorIDs` path for these 3 scenarios specifically (the path itself was already covered suite-wide by
other scenarios' own seed data, e.g. the exploit-prevention and policy-integrity scenarios' own untested legs).

**What changed:** added one genuinely new, real, CWE-mapped `wafcatalog` vector per family rather than inventing a
throwaway scenario-only placeholder: `FILEUP-003` (path traversal via a crafted upload filename, CWE-22),
`HTTPPARSE-003` (HTTP response splitting via CRLF injection into a reflected header, CWE-93), and `CACHE-003`
(cache poisoning via parameter cloaking with an unkeyed query-string parameter, CWE-20). Each was wired into its
scenario's `ContributingVectorIDs` (2→3) but deliberately left out of that scenario's own `*Fixtures()` map, so
`EvaluateScenario`'s `aggregateByPrecedence` now puts the new ID into `UntestedVectorIDs` for that scenario
directly — proven by three new `..._IsDeliberatelyUntested` tests, one per scenario, asserting both that the
fixture map has no entry for the new ID and that `UntestedVectorIDs` contains it (outcome stays `ScenarioFail`:
the pre-existing Missed vector still wins by the non-offsetting precedence rule, since this closes an
evidence-density gap, not an outcome-changing one).

The routing-cache scenario's own doc comment previously said "named honestly rather than padded with invented
vectors" — that stance was about not fabricating a vector with no CWE grounding just to pad a count; CACHE-003 is
a real, independently documented cache-poisoning technique (unkeyed/cloaked parameters, distinct from CACHE-001's
unkeyed header and CACHE-002's extension-based deception), so the comment was updated rather than contradicted.

`wafcatalog`'s total seed count moved 62→65; `TestAudspectWAFAttackCatalog_ReturnsValidatedCatalog` and the three
per-family `..._ValidAndUnique` tests were updated to match. Full `go build ./...`, `go vet`, and the
`wafcatalog`/`wafassessment`/`internal/api` test suites are green.

### 4. Only 5 of 10 enterprise scenarios have a dedicated handler-level test — RESOLVED 2026-11-10

**Status:** Resolved, in two passes the same day (see `docs/api-bas-mastery-qa-log.md`, "REQ-007: WAF assessment
hardening" and its same-day follow-up, for full detail).

**What was wrong:** `internal/api/waf_assessment_handlers_test.go` had dedicated tests for only 5 of the 10
enterprise scenarios (Exploit Prevention, HTTP Protocol Integrity, API Protection, Detection/Telemetry, Origin
Resilience); the other 5 (Automated Abuse, Policy Integrity, Routing/Cache, File Upload, Legitimate Traffic) relied
only on the generic closure's own test plus the `wafassessment` package-level tests.

**What changed:** added `TestWafScenarioJSONHandler_AutomatedAbuse_ReturnsRealFailOutcome`,
`..._FileUpload_...`, `..._RoutingCache_...`, `..._PolicyIntegrity_...`, and `..._LegitimateTraffic_...`, each
asserting the real `outcome`/`vectorId`/`scenarioName` for that scenario through the same shared
`wafScenarioJSONHandler` closure — no handler code changed, since the closure is already generic over
`reporting.BuildScenarioReport`'s output regardless of which evaluator (`EvaluateScenario`,
`EvaluatePolicyIntegrityScenario`, or a `ClaimFalsePositive`-graded call) produced it. Policy Integrity's `vectorId`
is a real policy-gap scenario id (`GAP-002`), not a `wafcatalog` vector id, confirming the handler renders whatever
`VectorAssertion.VectorID` the evaluator set, not a hardcoded catalog lookup.

All 10 enterprise scenarios now have a dedicated handler-level test. `go test ./internal/api/... -run
"TestWafScenarioJSONHandler|TestGetWAFExploitPreventionScenario|RBAC|Matrix"`: 20/20 pass, including
`TestRBACMatrix_NoDrift`.


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

### 12. Payload depth for SQL injection, XSS, path traversal and command injection -- 2026-10-28

Picked from `docs/cymulate-comparison-gap-analysis.md` (WAF, gap 1). The catalog had 3 SQL injection, 6 XSS, 2 path traversal and
2 command injection vectors, so a family counted as covered after one string.

**Added (`catalog_depth.go`), 25 vectors, catalog now 62:**

- **SQLI-004..010** -- time-based blind (MySQL `SLEEP`), stacked queries (MSSQL `WAITFOR`), Oracle error-based, inline-comment
  obfuscated UNION, case-mixed keywords, a JSON body field, and an HTTP header.
- **XSS-007..012** -- polyglot, SVG, iframe `srcdoc`, JSON-response script breakout, client-side template expression, double URL encoding.
- **PATHTRAV-003..008** -- Windows backslash to `win.ini`, single URL encoding, overlong UTF-8 `%c0%af`, null-byte extension bypass,
  absolute path, nested `....//` that survives one-pass stripping.
- **CMDI-003..008** -- pipe, `&&` and `||`, `$()`, encoded newline `%0a`, Windows `&` with `whoami`, time-based `sleep`.

Every vector has a benign twin on the same endpoint and location, and maps to the family's CWE (89, 79, 22, 78).

**Proven (`catalog_depth_test.go`, written first, 5 of the 10 tests failed before the vectors existed):** per-family minimum counts;
each family names the techniques a WAF must recognise (the test lists them); path traversal covers Unix, Windows and six encodings;
command injection covers both shells' operators; every vector has a twin on the same method and location; no two vectors send the
same request; every vector maps to its family's CWE; IDs are sequential; and a deny-list test fails the build if any payload could
change or delete data, fetch code or open a shell (`DROP`, `DELETE`, `rm -rf`, `wget`, `powershell`, `xp_cmdshell` and so on). The
`wafcatalog`, `wafassessment`, `wafefficacy`, `wafval`, `wafverify`, `wafprofile`, `wafdetection` and `wafevasion` tests pass.

**Still open (and the part that matters most):**
- The WAF side is a catalog graded against fixtures. **Nothing here sends a request to a WAF**, so none of the 62 vectors has been
  shown to be blocked or allowed by a real product (item 1 above: the vendor adapter is deferred by design).
- The new vectors are in the catalog but **not in any scoring scenario**: `WAFSCENARIO-EXPLOIT-PREVENTION` lists its eight vector IDs
  explicitly. Adding them needs fixtures, and inventing fixtures would be fake evidence.
- Per-request method and platform are still not tracked as separate fields (they are only visible in the request and its name).
- XSS payload depth is still modest next to Cymulate's roughly 7,800 requests; these are representative variants, not a corpus.
