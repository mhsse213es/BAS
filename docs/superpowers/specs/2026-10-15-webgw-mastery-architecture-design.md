# Web Gateway BAS Mastery: Architecture Specification

## Executive Summary

Audspect's Web Gateway (WebGW) Mastery initiative extends Audspect to validate deployed secure web gateway (SWG) products — determining whether a client's already-purchased Zscaler, Netskope, Forcepoint, Skyhigh, Broadcom, FortiProxy, or other SWG actually enforces its intended controls, not merely whether one is installed. The differentiator is control efficacy with defensible evidence, not attack volume: for every tested capability, Audspect must be able to state what control was expected, what the gateway actually did, whether the expected alert/telemetry fired, whether the required response occurred, and how much confidence the evidence supports — with prevention, detection, and response always scored independently, never collapsed into one pass/fail.

This specification is a **repository-verified gap analysis plus a five-phase roadmap**, scoped at the architecture level, following the same discipline as `docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md`. It establishes what already exists and must not be rebuilt, what is new, how the new work is structured, and the order of delivery. It does not contain file-by-file designs or task breakdowns — each phase gets its own implementation specification when that phase begins.

Source requirements document: `webGW.txt` (repo root). That document is a capability vision; this specification reconciles it against what Audspect's codebase actually contains today, and locks the specific first-provider and architecture decisions the vision document deliberately left open.

## 1. Repository-Verified Gap Analysis

Every classification below was checked directly against the current repository (a dedicated audit, not inferred from `webGW.txt`'s own description of what Audspect "should" do).

| webGW.txt domain | Status | Evidence |
|---|---|---|
| 01. URL filtering, categorization, reputation | **Missing** | Zero code anywhere in `internal/` implements URL-category policy testing, allowlist/denylist precedence checks, or reputation-feed validation. |
| 02. TLS inspection and encrypted traffic | **Missing** | No certificate-trust, inspection-coverage, or inspection-exception testing code exists for any web-proxy context. |
| 03. DLP and web exfiltration | **Strong reuse available** | `internal/cloudsink` implements real HTTP routes mimicking seven cloud-storage providers' actual upload-request shapes (S3, GCS, Azure Blob, Dropbox, Box, OneDrive, GDrive), mounted on the orchestrator's own API server. `internal/webhooksink` covers Slack/Teams/GitHub/GitLab. `internal/api/dlp_sink.go` is a generic HTTP sink issuing short-lived tokens. Non-HTTP sinks (`smtpsink`/`sftpsink`/`dnssink`/`telnetsink`) exist but are out of scope here — a different channel. Scenario YAMLs already exist: `dlp-exfiltration-cloud-storage.yaml`, `dlp-exfiltration-coderepo.yaml`, `dlp-exfiltration-webhook.yaml`, `collection-staging-exfil.yaml`, `insider-threat-kill-chain.yaml`. `internal/reporting/dlp.go` compares against an outcome vocabulary (`Allow/Block/Warn/Justify/Audit/Quarantine/Encrypt/Redact`, `scenario/outcome_catalog.go`) but explicitly verifies only local OS-level success/prevention — it has no concept of a gateway's own policy verdict. **This is the strongest existing asset for this initiative.** |
| 04. Malware, exploit delivery, file protection | **Missing** | No EICAR/download-reputation/file-type-mismatch testing exists against a web-proxy context. `cloudsink`'s upload-shaped endpoints are a plausible basis for a future download-simulation extension, but nothing download-specific exists today. |
| 05. Identity, authentication, policy assignment | **Missing** | No gateway-facing identity/SAML/OIDC/group-policy testing exists. |
| 06. SaaS, shadow IT, cloud application controls | **Partial reuse** | `cloudsink`/`webhooksink` already mimic several real SaaS upload endpoints (domain 03's asset doubles here), but zero CASB-specific policy verdict (personal-vs-corporate-tenant distinction, OAuth-app risk scoring) exists. |
| 07. DNS, covert channels, C2 protection | **Existing, wrong angle** | `internal/dnssink` + `dlp-exfiltration-dns-tunnel.yaml` validate whether DNS-tunneled *data exfiltration* is blocked/detected — a data-movement-domain capability, not gateway-side DNS policy (DoH/DoT enforcement, alternate-resolver bypass detection). Same "existing but wrong angle" relationship Network BAS's own master spec found for its §1.6. This initiative's DNS work, when it arrives (Phase 3+), is a distinct capability from `dnssink` and must not modify it. |
| 08. Proxy bypass, protocol coverage, egress control | **Missing** | No PAC/WPAD, explicit/transparent-proxy, or egress-bypass testing exists. |
| 09. Configuration drift, exceptions, administration | **Missing** | No policy-drift or exception-expiry testing exists for any gateway-class product. `internal/regobligation`'s immutable-evidence-snapshot pattern (captured this session for India/UAE regulatory mapping) is a structural precedent worth imitating for drift-over-time tracking — not a type to import. |
| 10. Detection, telemetry, SIEM, response | **Pattern precedent only** | `internal/detectverify.Connector` (`Verify(ctx,req)`, `TestConnection(ctx)`) with 7 real vendor implementations (`crowdstrike.go`, `defenderxdr.go`, `elastic.go`, `qradar.go`, `sentinel.go`, `splunk.go`, `trellix.go`) is the established, proven shape for "call a real vendor API, normalize the response, correlate against an expected test." All 7 are EDR/SIEM-class. Zero web-gateway-class (SWG) connector exists anywhere, and no grep hit for Zscaler/Netskope/Forcepoint/Skyhigh/Broadcom/FortiProxy turned up any code — only a deferred-items line in an unrelated spec and an unrelated JSON enrichment file. |
| 11. Availability, resilience, performance-related security | **Missing** | No gateway failover/fail-open/fail-closed testing exists. |
| 12. Cross-control attack chains, industry-specific exposure | **Missing** | No multi-stage gateway+endpoint+identity+SIEM correlation scenario exists. Depends on domains 01-11 existing first, same dependency shape as Network BAS's own Phase 7 on Phases 1-6. |

**Verdict-taxonomy precedent assessment:** three verdict/outcome types already exist in this codebase — `scenario.ExecutionOutcome` (Executed/Blocked/Error/Skipped → FAIL/PASS/ERROR/SKIPPED, endpoint-technique domain), `networkefficacy.EfficacyVerdict` (met/not-met/inconclusive, network-flow domain), and the DLP outcome-catalog comparator (Allow/Block/Warn/... vs. three primitive local observations). **None has `Unsupported` or `Not-applicable` as a first-class state**, and `webGW.txt`'s own quality model explicitly requires both, plus independently-scored prevention/detection/response. **Decision: WebGW gets its own, fresh 5-state verdict type — `Pass/Fail/Inconclusive/Unsupported/NotApplicable` — never unified with any of the three existing taxonomies.** This is locked (see §2) rather than left as an open question, because unifying verdict models across domains this different (endpoint execution, network flow, HTTP policy) has already been rejected once this session (`internal/networkefficacy`'s own doc comment states it is "deliberately independent of `internal/detectverify`") and the same reasoning applies here with one more domain added.

**Control-efficacy architecture precedent assessment:** `internal/networkefficacy` (built this session, Network BAS Phase 4) has the right *shape* — `ControlExpectation` (what should happen) → evidence providers (what a real product's logs say happened) → a verdict carrying both a result and a reason — but its matching primitive is a network 5-tuple (`Flow{SourceCIDR,DestCIDR,Port,Protocol}`), which does not fit an HTTP request (URL, host, category, user, destination application). **Decision: build a new, parallel `internal/webgwefficacy` package, architecturally independent of `internal/networkefficacy` and `internal/detectverify`** (no import of either), reusing only the structural pattern — expectation vs. evidence vs. verdict, with explicit provenance and an explicit "nothing here means inconclusive, not failing" discipline — exactly as `internal/networkefficacy` itself reused `internal/detectverify`'s *pattern* without importing it.

## 2. Architecture

### 2.1 Package: `internal/webgwefficacy`

A new, independent leaf package. It imports no other Audspect package by default; any future cross-reference (e.g., to `internal/networkpolicy` for a declared egress policy) follows the exact "read-only reference by stable ID, never shared types" discipline Network BAS Mastery used throughout, and must be justified in that phase's own implementation spec, not assumed here.

Core types (names final, field lists indicative — each phase's own implementation spec nails down exact fields and JSON tags):

```go
// HTTPExpectation is what a web-gateway policy was declared to be
// expected to do for a request shape -- never inferred from observed
// behavior.
type HTTPExpectation struct {
    RequestURL     string
    URLCategory    string
    User           string   // identity/group this expectation applies to
    ExpectedAction ExpectedGatewayAction // allow | block | challenge | quarantine
    ControlProduct string   // e.g. "cloudflare-gateway"
    Note           string
}

type ExpectedGatewayAction string
const (
    ExpectedAllow      ExpectedGatewayAction = "allow"
    ExpectedBlock      ExpectedGatewayAction = "block"
    ExpectedChallenge  ExpectedGatewayAction = "challenge"
    ExpectedQuarantine ExpectedGatewayAction = "quarantine"
)

// GatewayEvidence is one normalized gateway log/policy-decision
// record, however it was obtained.
type GatewayEvidence struct {
    RequestURL string
    User       string
    Action     string // the gateway's own observed action
    Category   string // the gateway's own assigned category
    PolicyRule string // which rule/policy fired, if attributable
    Timestamp  time.Time
    Source     EvidenceSource // synthetic | recorded-fixture | live
    RawEvent   json.RawMessage
}

type EvidenceSource string
const (
    SourceSynthetic EvidenceSource = "synthetic"
    SourceFixture   EvidenceSource = "recorded-fixture"
    SourceLive      EvidenceSource = "live"
)

// GatewayEvidenceProvider supplies gateway evidence for a request
// shape and time window. A returned error means collection/parsing
// failed -- distinct from a successful search that found nothing.
type GatewayEvidenceProvider interface {
    GatewayEvidenceFor(req HTTPRequestRef, window TimeWindow) ([]GatewayEvidence, error)
}

// WebGWVerdict is the 5-state verdict every WebGW domain uses --
// never 3-state or 4-state, never unified with any other domain's
// taxonomy (locked, §1).
type WebGWVerdict string
const (
    VerdictPass          WebGWVerdict = "pass"
    VerdictFail          WebGWVerdict = "fail"
    VerdictInconclusive  WebGWVerdict = "inconclusive"
    VerdictUnsupported   WebGWVerdict = "unsupported"
    VerdictNotApplicable WebGWVerdict = "not-applicable"
)

// EfficacyResult keeps prevention, detection, and response as three
// independently-verdicted dimensions -- never collapsed into one
// overall pass/fail, per webGW.txt's own explicit requirement that a
// gateway "can block an action but fail to alert" and both are
// material findings.
type EfficacyResult struct {
    Expectation HTTPExpectation
    Observation HTTPObservation  // what the client-side test actually did/saw
    Evidence    []GatewayEvidence
    Prevention  VerdictDetail
    Detection   VerdictDetail
    Response    VerdictDetail
}

type VerdictDetail struct {
    Verdict WebGWVerdict
    Reason  string // required whenever Verdict != Pass
}
```

**Unsupported vs. Inconclusive, enforced structurally, not by convention:** a verdict-computation function takes the capability's availability as an explicit, separate input from the evidence found for a specific run. `Unsupported` means the integration/capability itself is not available (e.g., the connected vendor API lacks a required permission, or no adapter exists for this product at all) — this can be determined once, independent of any single test run. `Inconclusive` means the capability exists but this specific run's evidence or prerequisites are missing or ambiguous. Collapsing these into one state is exactly the imprecision `webGW.txt`'s quality model warns against, and each phase's acceptance criteria (§6) requires a test proving both states are independently reachable.

### 2.2 Vendor integration: borrowed pattern, not a shared interface

Vendor adapters (starting with Cloudflare Gateway, §2.3) are **not** `detectverify.Connector` implementations and do not import `internal/detectverify`. They borrow its proven *shape* — a config struct, a method that calls the real vendor API over HTTP, normalizes the response, and returns typed evidence — the same way `internal/networkefficacy`'s `RealSuricataProvider` borrowed the "read something real, parse it, tag its source" shape from that package's own fixture parser without creating a cross-package dependency. Each vendor adapter implements `GatewayEvidenceProvider` directly.

### 2.3 First live provider: Cloudflare Gateway (Zero Trust)

**Locked decision** (confirmed with the user after researching the originally-named vendor list): none of the six vendors named in `webGW.txt` (Zscaler, Netskope, Forcepoint, Skyhigh, Broadcom, FortiProxy) offer genuine self-serve trial access with API credentials — all require a sales/POV engagement. FortiProxy-VM is self-hostable but its trial license is time-boxed (15 days) and depends on periodic revalidation against Fortinet's license servers, which breaks long-term test-harness reproducibility. **Cloudflare Gateway (part of Cloudflare Zero Trust) is the first live adapter target instead** — genuine self-serve signup, a free tier covering up to 50 users, real HTTP/TLS-inspection/basic-DLP enforcement, and a documented REST API for both policy management and log retrieval.

This decision carries explicit conditions, locked for Phase 2's implementation spec to honor:

1. **Provider scope.** Cloudflare Gateway is the first live adapter. The six originally-named vendors remain planned candidates (§5), not supported integrations, until their own access/API/evidence/licensing is independently verified — no claim of support without that verification.
2. **API verification before implementation.** Phase 2's own implementation spec must confirm the exact API permissions, policy-management operations, log-retrieval endpoints, and account-plan requirements against Cloudflare's current documentation before any code is written against them — this document does not freeze those details, since Cloudflare's offering can change.
3. **Evidence contract.** Each controlled HTTP test is correlated against both the observed client-side result and the gateway's own log/policy-decision evidence. A missing or expired log yields `Inconclusive`, never an assumed `Pass`.
4. **TLS inspection verified independently.** Certificate deployment, endpoint trust, and inspection behavior are each verified on their own terms — a successful request is never read as proof that TLS inspection actually occurred.
5. **DLP validated with synthetic markers only.** Uses known, synthetic, non-sensitive data markers and controlled destinations, distinguishing an actual DLP block from an unrelated HTTP failure or a destination-side rejection — same discipline `webGW.txt` requires and `internal/cloudsink`'s existing scenarios already follow.
6. **Reproducibility under the free tier's log-retention limit.** The free tier keeps Zero Trust logs for roughly 24 hours. This is treated as a constraint to verify against current Cloudflare documentation before relying on it, not a permanent guarantee — evidence is captured promptly after each test and the normalized result (not the raw log) is what gets preserved long-term, with timestamp and provenance intact.
7. **Mock/live parity, never substituted silently.** Deterministic fixtures back unit and regression tests (so the suite runs without live network access or Cloudflare credentials). The live adapter is exercised only in integration tests explicitly labeled as such. A mocked response never counts as proof of real enforcement in any report.
8. **Fallback is a documented gap, never a silent substitution.** If an essential capability or API permission turns out unavailable on the account tier used, the acceptance criterion that depends on it is marked `Unsupported` and documented — the implementation does not silently fall back to a mock and report success.

**Boundary, stated explicitly so it is never overclaimed later:** validating against Cloudflare Gateway proves Audspect's architecture and evidence pipeline work against one real SWG-class product. It does not establish universal SWG coverage, and it does not imply the same behavior exists in Zscaler, Netskope, Forcepoint, Skyhigh, Broadcom, or FortiProxy. Any report citing this work must say so.

## 3. Phase Roadmap

Five phases, following `webGW.txt` §6's own recommended order (locked by the user as correct) and Network BAS Mastery's phase-specification discipline — each phase gets its own implementation spec when it begins; this document fixes only architecture and boundaries.

### Phase 1 — Foundation and Evidence Contract

**Goal:** `internal/webgwefficacy` exists, compiles, and is tested — the capability taxonomy (§1's 12 domains, as data, not code yet), scenario/expectation schema, the 5-state verdict type, the prevention/detection/response separation, provenance, evidence-source tagging, and regression-test scaffolding — with zero live vendor integration. Deterministic, fixture-backed tests only, mirroring exactly how `internal/networkefficacy` shipped its `SyntheticFirewallProvider`/`FixtureIDSProvider` before any real Suricata integration existed.

**Exit criteria:** `HTTPExpectation`, `GatewayEvidence`, `EfficacyResult`, `WebGWVerdict`, `EvidenceSource` all exist and are tested; a fixture-backed `GatewayEvidenceProvider` implementation proves the expectation→evidence→verdict pipeline end-to-end for at least one allow case and one block case; `Unsupported` and `Inconclusive` are each independently reachable and tested as distinct outcomes (not just documented as different).

### Phase 2 — First End-to-End Vertical

**Goal:** URL policy enforcement + TLS inspection visibility + DLP uploads (reusing `internal/cloudsink`'s synthetic markers and real upload-shaped endpoints) + identity-based policy + the Cloudflare Gateway live adapter (§2.3, all 8 conditions) + SIEM evidence correlation (borrowing `detectverify`'s connector *pattern*, not its interface).

**Exit criteria:** at least one URL-policy scenario, one TLS-inspection-visibility check, one DLP-upload scenario, and one identity-scoped policy scenario execute end-to-end against the real Cloudflare Gateway adapter, each producing an `EfficacyResult` with independently-verdicted prevention/detection/response, backed by evidence tagged `SourceLive`. A fixture-backed parallel exists for every one of these scenarios so the regression suite never requires live credentials.

**Amendment, 2026-10-15 (before any Phase 2 code was written):** the live Cloudflare Gateway adapter is blocked — the user has no card, which Cloudflare's signup requires even for its free tier, so the account itself cannot yet be created. Per condition #8 (§2.3): this is a documented gap, not a silent mock substitution. Phase 2 therefore splits into two sub-deliverables, tracked in `docs/webgw-mastery-qa-log.md`:
- **Phase 2a (proceeding now):** every component above — URL policy, TLS-inspection-visibility modeling, DLP uploads, identity-scoped policy, the SIEM-correlation pattern — built and proven fixture-backed only, extending `internal/webgwefficacy` exactly as Phase 1 did (new `FixtureGatewayProvider`-style fixtures per domain, no live vendor). This is the "deterministic fixtures first" half of condition #7, done in isolation from the half it was meant to pair with.
- **Phase 2b (deferred, blocked on QA log item #1):** the actual live Cloudflare Gateway adapter — `GatewayEvidenceProvider` calling Cloudflare's real API — resumes once the user has account access and has hands-on-verified which evidence-retrieval path (Log Explorer, Logpush, or neither) is reachable on the tier they end up with.
- Phase 2a's exit criteria below are restated against fixtures only; Phase 2's original exit criteria (evidence tagged `SourceLive`, executing against the real adapter) remain Phase 2b's and are not claimed met until Phase 2b actually ships.

**Phase 2a exit criteria (revised, fixture-only):** at least one URL-policy scenario, one TLS-inspection-visibility check, one DLP-upload scenario, and one identity-scoped policy scenario execute end-to-end against fixture-backed `GatewayEvidenceProvider` implementations, each producing an `EfficacyResult` with independently-verdicted prevention/detection/response, backed by evidence tagged `SourceFixture`. The SIEM-correlation pattern is proven against a fixture SIEM connector mirroring `detectverify`'s shape, not a real one.

**Amendment, 2026-10-15 (Phase 2b, scoped to what doesn't require account access):** the account-access blocker (QA log item #1) remains open — user confirmed no card yet. This round does the API-verification work condition #2.3-2 requires and builds what that verification enables, without live credentials.

**API verification, completed 2026-10-15 (resolves QA log item #2 definitively, sources cited there):**
- Policy management (`POST`/`GET /accounts/{account_id}/gateway/rules[/{id}]`, `Authorization: Bearer <API_TOKEN>`) and the `tls_decrypt` toggle are both confirmed available without an Enterprise plan.
- Per-request Gateway HTTP evidence retrieval is **not** available on the free tier through any supported path. Logpush for Zero Trust Gateway logs is Enterprise-only — Cloudflare's own integration page carries a top-of-page "Enterprise-only" label covering the `gateway_http` dataset. Log Explorer has no free tier or trial at any plan level, full stop — Cloudflare's own pricing page: "available as a paid add-on for any Application Services or Zero Trust purchase... no free version or trial available at this time." Free-tier HTTP log retention is 24 hours, dashboard-viewable only, with no documented bulk-export or per-record query API. The undocumented, community-reported "gateway activities" endpoint remains unofficial and is not depended on, per condition #7.

**Consequence — Phase 2b's scope is narrowed, not abandoned:** condition #3 (§2.3) requires correlating each test against the gateway's own evidence. On the tier actually available to the user, that evidence can only take the form of the gateway's own **live policy configuration state**, never a per-request decision log. Phase 2b therefore ships `CloudflareGatewayPolicyProvider`, a real implementation of Phase 3's existing `PolicyConfigEvidenceProvider` interface (`drift.go`) — reusing an existing interface rather than inventing a new one, and deliberately not `GatewayEvidenceProvider` — calling Cloudflare's real, documented `gateway/rules` API to confirm a rule's actual configured `action` matches what was declared, computing `ObservedConfigHash` from the rule's real `action`/`filters`/`traffic` fields and `StillActive` from `enabled`. This gives `SourceLive` its first real producer anywhere in this package. Per-request attack-resistance/detection evidence — the original Phase 2 exit criterion's `GatewayEvidence`/`SourceLive` language — remains blocked, now by a priced, documented cost decision (a Log Explorer add-on or an Enterprise plan) rather than an unconfirmed unknown, and is not reattempted until the user chooses to make that purchase. This narrows Phase 2b's ambition under condition #8; the gap is named here and in the QA log, never hidden behind a claim of full live coverage.

**What ships without live credentials:** `CloudflareGatewayPolicyProvider`'s real HTTP request-building and response-parsing logic, proven against `httptest` servers returning Cloudflare's exact documented response envelope shape — the same structural proof Azure's real-discovery integration used while blocked on tenant access. Construction is credential-gated (`NewCloudflareGatewayPolicyProviderFromEnv`, reading `CLOUDFLARE_ACCOUNT_ID`/`CLOUDFLARE_API_TOKEN`); the one test that would call the real Cloudflare API skips, not fails, when those env vars are unset, and becomes exercisable the moment the user has an account and a token with zero further code changes.

### Phase 3 — Policy and Bypass Mastery

**Goal:** exceptions and policy shadowing, proxy bypass and alternate protocols, fail-open/fail-closed behavior, SaaS/CASB controls, configuration drift, and the first cross-control attack chains (domains 06, 08, 09, and the start of 12).

**Exit criteria:** each addition includes both a known-good baseline and a negative test, per `webGW.txt`'s own requirement; at least one fail-open scenario and one policy-drift scenario execute end-to-end with evidence-backed verdicts.

### Phase 4 — Vendor Expansion and Regional Profiles

**Goal:** additional vendor adapters (Zscaler, Netskope, Forcepoint, Skyhigh, Broadcom, FortiProxy) added only after each one's own access/API/evidence/licensing is independently verified against that vendor's current offering — no fixed order among them is locked here. India/UAE regulatory mapping (CERT-In directions, RBI requirements, UAE Information Assurance Regulation) follows `internal/regobligation`'s established *pattern* (immutable evidence snapshots, versioned obligations, applicability by jurisdiction/sector/entity-type) without importing its types, mirroring how `regobligation` itself stayed independent of `internal/compliance`. Industry profiles (BFSI, healthcare, manufacturing/OT-adjacent, MSP/shared-tenant) are configuration — priorities, data classifications, business-impact weighting — layered onto the Phase 1-3 scenario library, never a second scoring system, per `webGW.txt`'s own explicit instruction.

**Exit criteria:** at least one additional vendor adapter is either integrated end-to-end or explicitly, visibly marked `Unsupported` with the specific blocking gap documented (never silently dropped); at least one regulatory obligation per jurisdiction (India, UAE) is mapped end-to-end from obligation to control to scenario to evidence, matching Network BAS Phase 7C's own bar.

### Phase 5 — Mastery Certification and Regression

**Goal:** coverage reporting with an explicit denominator and explicit exclusions (never an unqualified percentage), scenario mutation testing (weaken a policy in a lab, verify the relevant scenario catches the regression, restore, verify recovery), false-positive tracking, reproducibility metrics, evidence-completeness auditing, and release gates.

**Exit criteria:** at least one mutation test is proven to catch a deliberately-introduced regression and to confirm recovery after the fix; coverage reporting cites its denominator and exclusions on every report, never a bare percentage.

**Amendment, 2026-10-15 (design locked before any Phase 5 code was written):** Phase 5's own Goal text names six items, but its binding Exit Criteria name only two (mutation testing, coverage reporting) — the same Goal-text-vs-binding-exit-criteria distinction Phase 3 and Phase 4 already drew correctly. This round builds only the two exit-criteria items; false-positive tracking, reproducibility metrics, evidence-completeness auditing, and release gates remain available for a future round.

Two new leaf files in `internal/webgwefficacy`, continuing Phase 1-4's zero-dependency discipline unchanged:

- **`mutation.go`** — a generic, scenario-agnostic harness. `RunMutationTest(scenarioLabel string, runBaseline, runMutated, runRestored func() VerdictDetail) MutationResult` takes three closures the caller already wires to a real `Verify...` function against three different fixture configurations (baseline, deliberately weakened, reverted) — the harness never weakens or restores a policy itself, exactly as `webGW.txt`'s own quality-proof requirement #4 describes the discipline without this package inventing its own policy-mutation mechanics. `CaughtRegression` is true only when the baseline was actually `Pass` and the mutated run flipped to `Fail`. `RecoveryConfirmed` compares the restored verdict against the *original* baseline verdict, not a hardcoded `Pass` — so the harness stays usable for a negative-baseline scenario (one whose correct baseline is itself `Fail`) without forcing every mutation test through a positive-only lens.
- **`coverage.go`** — `DomainCoverage{DomainID, DomainName, Status, ExclusionReason}` with `CoverageStatus` one of `Covered`/`Excluded`/`NotCovered`; `NewCoverageReport(domains []DomainCoverage) (CoverageReport, error)` validates at construction (never at render time) that no `DomainID` repeats and that every `Excluded` domain carries a non-empty `ExclusionReason` — the same "document the gap, never silently drop" discipline this whole initiative already enforces for vendor status. `CoverageReport.Denominator()` always equals the full domain count, including `NotCovered` ones. `CoverageReport.Summary() string` is the only rendering surface and always embeds the count, the denominator, and every exclusion's reason together in one string — there is no code path that returns a bare percentage number on its own.

**Concrete coverage report, not just an abstract type:** `AudspectWebGWCoverageReport() (CoverageReport, error)` in `coverage.go` ships the actual, current, repository-verified classification of all 12 `webGW.txt` domains (mirroring this document's own §5 table) as real data, the same way Phase 4's `regulatory.go` shipped real CERT-In/UAE obligations rather than placeholder ones. This function must be updated at the end of every future phase that changes a domain's status — the same living-document discipline §5's own table header already states, now made executable. A domain whose status in this function diverges from §5's own table is a defect in whichever one is stale, not an acceptable permanent inconsistency.

### Post-Phase-5 domain closure: Domain 07 (DNS, covert channels and C2 protection)

**Amendment, 2026-10-15 (design locked before any domain-07 code was written):** all five phases' own binding exit criteria are now met; domain 07 was never named in any phase's exit criteria (only in §5's living table, "Planned here (Phase 3+)") — Phase 3's own Goal text explicitly named domains 06, 08, 09, and the start of 12, and left 07 for later. This is phase-unassigned domain-coverage closure work, not a new Phase 6.

`webGW.txt`'s own domain-07 text names six sub-capabilities (DoH/DoT policy, direct-IP/alternate-resolver bypass, DGA/suspicious-DNS behavior, web-based C2 simulation, webhook/cloud-service egress abuse, long-lived-session/anomalous-destination detection, DNS-filtering-vs-gateway-enforcement inconsistency). The first of these (DoH policy bypass) is already built under domain 08 (`TestProxyBypassScenario_DNSOverHTTPSCaught`/`_Missed`, proxy-bypass framing, reusing `HTTPExpectation` directly since a DoH request genuinely is an HTTP request). This round builds the one still-unbuilt capability most central to domain 07's own heading — **gateway-side DNS resolution policy against a known-malicious/C2 domain** — following the same Goal-text-vs-binding-scope discipline Phase 3/4/5 already used: one proven scenario now, the other five sub-capabilities remain available for a future round, not silently claimed.

**New leaf file, continuing the zero-dependency discipline unchanged: `dns.go`.** A DNS resolution is structurally different from an HTTP request (different protocol, no URL, no TLS to inspect) — the same reasoning that gave TLS inspection its own `tls.go` rather than overloading `HTTPExpectation` — so this gets its own small type family rather than stretching `RequestURL` to mean "a bare domain name," mirroring `tls.go`'s exact shape:

- `DNSQueryExpectation{QueryDomain, ThreatCategory, ExpectedAction ExpectedGatewayAction, ControlProduct, Note}` — a declared "this domain's resolution should be blocked/allowed by the gateway's own DNS policy" claim.
- `DNSResolutionEvidence{QueryDomain, Action string, ThreatCategory, Timestamp, Source EvidenceSource}` — `Action` is a plain string (e.g. `"block"`/`"allow"`), compared against `exp.ExpectedAction` case-sensitively with no normalization, matching `VerifyHTTPExpectation`'s own established discipline (an action-case mismatch is a real mismatch, never silently normalized away).
- `DNSResolutionEvidenceProvider` interface + `FixtureDNSResolutionProvider`, and `VerifyDNSQueryExpectation(exp, provider, window) VerdictDetail` — no evidence in the window is `Inconclusive`, never an assumed verdict; most-recent-by-timestamp wins via the shared `latestByTimestamp` helper, matching `tls.go`/`drift.go` exactly.

**Exit criterion for this round:** at least one known-good scenario (a C2/malicious-domain query correctly blocked by the gateway's own DNS policy) and one negative counterpart (the same query missed) execute end-to-end against a fixture-backed `DNSResolutionEvidenceProvider`, per `webGW.txt`'s own known-good-plus-negative requirement. `AudspectWebGWCoverageReport()` and §5's table are updated to reflect domain 07 moving to `Covered`/"Fixture-backed coverage added," keeping both in sync per this document's own living-document rule.

## 4. Safety and Quality Contract

Carried forward and adapted from `webGW.txt` §4-5, binding on every phase above, not aspirational text:

- **Prevention, detection, and response are always scored independently** (`EfficacyResult.Prevention`/`.Detection`/`.Response`, §2.1). A blocked request with no alert and an unblocked request with an alert are both material findings, never merged into one verdict.
- **Observed evidence is never confused with inferred evidence.** Every `GatewayEvidence` record carries an explicit `Source` (`synthetic`/`recorded-fixture`/`live`) — a mock result is never reported as proof a real product behaved a certain way, the same non-negotiable Network BAS Mastery carried from `network.txt` §9.
- **`Unsupported` and `Inconclusive` are structurally distinct** (§2.1) — a capability that genuinely does not exist is never reported the same way as a run whose evidence happened to be missing.
- **Independent evidence over a single log.** Where available, correlate the client-side test result, the gateway's own evidence, and SIEM telemetry — never rely on one gateway log as sole proof of gateway behavior, per `webGW.txt`'s own quality-proof requirement #2.
- **Reproducibility.** Every scenario has deterministic inputs and, where meaningful, both a known-allowed and a known-blocked case to prove the harness itself is functioning (positive and negative controls, quality-proof requirement #1).
- **Mutation testing proves the harness catches regressions**, not just that it passes today (quality-proof requirement #4, formalized as Phase 5's exit criterion).
- **No active probing into OT-adjacent web-gateway deployments without a separately-approved test design** — carried verbatim from `webGW.txt`'s manufacturing/industrial profile caveat and consistent with Network BAS Phase 7A's own OT/ICS safety posture.
- **A successful simulation or report is never presented as proof of regulatory compliance without qualified review** — the same non-negotiable Network BAS Phase 7C's master spec carried from `network.txt` §9, restated here because it is a universal Audspect principle, not a network-specific one.
- **No coverage percentage without a defined denominator and explicit exclusions** (quality-proof requirement, Phase 5's own exit criterion).

## 5. Coverage Matrix

Implemented / Reusable / Planned / Unsupported, per the repository-verified gap analysis in §1. This matrix is the living source of truth for "what can Audspect actually claim about WebGW" at any point — update it at the end of every phase, never advertise a domain's coverage beyond what this table currently says.

| Domain | Status (as of this spec) | Notes |
|---|---|---|
| 01. URL filtering/categorization/reputation | **Fixture-backed coverage added (Phase 2a)** | URL/category policy (malware-category block) proven end-to-end against Phase 1's `HTTPExpectation` pipeline (`scenarios_test.go`). No live vendor adapter; reputation-feed validation and allowlist/denylist precedence beyond this one case remain unbuilt. |
| 02. TLS inspection | **Fixture-backed coverage added (Phase 2a)** | TLS-inspection-visibility modeling (`tls.go`) — orthogonal to policy action, never inferred from request success. No live certificate-chain inspection; this models whether inspection was reported, not a real TLS MITM. |
| 03. DLP and web exfiltration | **Fixture-backed coverage added (Phase 2a)** | A real integration test (`dlp_integration_test.go`) PUTs a synthetic DLP marker through `internal/cloudsink`'s actual HTTP routes and confirms a DB receipt, then runs the result through this package's own verdict pipeline. `cloudsink`/`webhooksink`/`dlp_sink.go` remain the underlying reusable assets. |
| 04. Malware/exploit delivery/file protection | Planned (Phase 3+) | Net-new; EICAR-class download testing not yet designed. |
| 05. Identity/auth/policy assignment | **Fixture-backed coverage added (Phase 2a)** | Identity-scoped policy (same URL, different verdicts for different users) proven end-to-end against Phase 1's pipeline (`scenarios_test.go`). SAML/OIDC/group-policy-assignment testing itself remains unbuilt — this covers only per-user policy differentiation. |
| 06. SaaS/shadow IT/CASB | **Fixture-backed coverage added (Phase 3)** | Personal-vs-corporate-tenant distinction proven end-to-end against Phase 1's `HTTPExpectation` pipeline, unchanged (`scenarios_test.go`). No live vendor adapter; CASB-specific risk scoring beyond the tenant-distinction case remains unbuilt. |
| 07. DNS/covert channels/C2 | **Fixture-backed coverage added (post-Phase-5 domain closure)** | Gateway-side DNS resolution policy against a known-malicious/C2 domain (`dns.go`), proven end-to-end against Phase 1's verdict discipline (`scenarios_test.go`). `dnssink`/`dlp-exfiltration-dns-tunnel.yaml` stay untouched (data-movement domain). DoH/DoT policy bypass already covered under domain 08. DGA/suspicious-DNS behavior, web-based C2 simulation, webhook/cloud-service egress abuse, and long-lived-session/anomalous-destination detection remain unbuilt. |
| 08. Proxy bypass/egress control | **Fixture-backed coverage added (Phase 3)** | DNS-over-HTTPS bypass scenario proven end-to-end against Phase 1's `HTTPExpectation` pipeline, unchanged (`scenarios_test.go`). PAC/WPAD and other alternate-protocol bypass vectors remain unbuilt. |
| 09. Configuration drift/administration | **Fixture-backed coverage added (Phase 3)** | Policy-baseline config-hash drift and exception-expiry detection (`drift.go`); the `regobligation`-style snapshot pattern was imitated structurally, not imported. No live configuration-management API integration. |
| 10. Detection/telemetry/SIEM/response | **Fixture-backed coverage added (Phase 2a)** | SIEM-correlation pattern (`siem.go`, `CorrelateWithSIEM`) proven against a fixture SIEM connector mirroring `detectverify`'s shape, not a real one. No live SIEM/EDR vendor connector exists for SWG-class evidence. |
| 11. Availability/resilience | **Fixture-backed coverage added (Phase 3)** | Fail-open/fail-closed behavior verification (`failuremode.go`), brought forward from its original "Phase 3+, lowest priority" slot because Phase 3's own exit criteria required at least one fail-open scenario end-to-end. Performance-related security claims remain unbuilt. |
| 12. Cross-control attack chains/industry-specific | **Started (Phase 3)** | `ComposeAttackChain` composition primitive built and proven end-to-end by chaining a real HTTP-policy result with a real failure-mode result (`chain.go`). Industry-specific exposure scenarios and chains spanning 3+ steps remain Phase 4 work. |
| **Vendors** | | |
| Cloudflare Gateway | **API-verified, policy-correctness adapter built (Phase 2b); live execution blocked on account access** | Policy-management API confirmed and `CloudflareGatewayPolicyProvider` built against it (`cloudflare.go`), proven via `httptest` against Cloudflare's documented response shape — real `PolicyConfigEvidenceProvider` implementation, `SourceLive`'s first producer. Per-request evidence retrieval confirmed unavailable on the free tier (Logpush Enterprise-only; Log Explorer has no free tier ever) — scope is policy-correctness only. Live execution awaits account access, QA log item #1. |
| Zscaler | **Unsupported (Phase 4, documented gap)** | No self-serve trial/signup exists; every path routes through Zscaler's own sales/demo gate. See `docs/webgw-mastery-qa-log.md` item #3. |
| Netskope / Forcepoint / Skyhigh / Broadcom / FortiProxy | Planned candidates, access unverified | Same sales-gated pattern found for the other 5 vendors during Phase 2 research; no commitment to order. |
| **Industry profiles** | | |
| BFSI/NBFC, Healthcare, Manufacturing/OT-adjacent, MSP/shared-tenant | Planned (Phase 4) | Configuration layered on the Phase 1-3 scenario library, never a second scoring system. |
| **Regulatory** | | |
| India (CERT-In) / UAE (Information Assurance Regulation) | **Mapped end-to-end (Phase 4)** | `regulatory.go`: one obligation per jurisdiction (India CERT-In CI-13; UAE cross-referenced to NIST SC-07) mapped through a real Phase 1/3 scenario to an immutable evidence snapshot. Follows `regobligation`'s pattern, independent types. RBI (India) remains unmapped; one obligation per jurisdiction was this phase's own bar, matching Network BAS Phase 7C's minimal-seed precedent. |

## 6. Acceptance Criteria Methodology

Per-phase exit criteria are stated in §3; this section fixes how "done" is proven across every phase, so no phase's implementation spec has to reinvent the methodology.

- **Executable, not descriptive.** Every scenario's contract (`webGW.txt` §4's field table — identity, preconditions, expected result, observation, detection, evidence quality, verdict, reproduction, remediation, regression) is proven by a test that actually runs it, never by a written description of intended behavior.
- **Independent evidence requirement.** Any scenario whose finding would be rated above `Inconclusive` must cite at least one piece of evidence independent of the client-side test's own success/failure signal (a gateway log, a SIEM record, or both) wherever the integration tier supports it; where it doesn't (e.g., a fixture-only unit test), the test says so explicitly rather than implying live corroboration occurred.
- **Mutation testing, concretely.** For at least one scenario per phase from Phase 2 onward: deliberately weaken the relevant policy in the test environment, confirm the scenario's verdict flips to `Fail` (proving the harness detects the regression), restore the policy, confirm the verdict returns to `Pass`. A scenario that cannot be mutation-tested this way (e.g., because the vendor tier has no policy-write API) is marked `Unsupported` for mutation testing specifically, not silently skipped.
- **Regression gates.** Every phase's fixture-backed test suite must pass before that phase's live-adapter tests are considered meaningful — a live test failing while the fixture-backed equivalent passes is a signal to investigate the live integration, not the architecture.
- **Measurable completion, never a vibe.** A phase is "done" only when every item in its own §3 exit-criteria list has a passing, named test exercising it — "the pipeline looks right" is not a completion criterion at any phase.

## 7. Explicit Exclusions and Dependencies

**Excluded from this initiative, by design:**

- Unifying `webgwefficacy`'s verdict model with `scenario.ExecutionOutcome`, `networkefficacy.EfficacyVerdict`, or the DLP outcome-catalog comparator. Locked in §1-2; do not revisit without a fresh architectural decision, not a convenience refactor.
- Claiming any of Zscaler, Netskope, Forcepoint, Skyhigh, Broadcom, or FortiProxy as a "supported" integration before that vendor's own access/API/evidence/licensing has been independently verified (§2.3, §5).
- Live active probing into OT-adjacent web-gateway deployments without a separately-approved test design (§4, carried from `webGW.txt`'s manufacturing-profile caveat).
- Presenting a technical pass/fail result as a regulatory compliance determination (§4).
- Rebuilding `internal/cloudsink`, `internal/webhooksink`, `internal/api/dlp_sink.go`, or any existing DLP scenario YAML — these are reused as-is (§1, §5); this initiative extends them with a gateway-side verdict layer, never replaces their HTTP-sink behavior.
- Modifying `internal/dnssink` or `dlp-exfiltration-dns-tunnel.yaml` — those remain the data-movement domain's DNS-channel test, untouched (§1, §5).
- Importing `internal/networkefficacy`, `internal/detectverify`, `internal/compliance`, or `internal/regobligation` types into `internal/webgwefficacy` — every cross-package relationship in this initiative is a borrowed structural pattern, never a type-level dependency (§2).

**Depends on:**

- `internal/cloudsink`, `internal/webhooksink`, and `internal/api/dlp_sink.go` remaining stable and unmodified in their current form through at least Phase 2.
- A Cloudflare account and API credentials being provisioned before Phase 2 begins, handled with the same credential-handling discipline as every other live-integration credential in this codebase (never checked into git, rotated per standard practice).
- `internal/regobligation`'s pattern (not types) remaining a valid structural reference for Phase 4's regulatory-mapping work; if that package's own shape changes materially before Phase 4 begins, Phase 4's implementation spec must re-verify the reference.
- Each of Phase 2 through Phase 4 is gated on the prior phase's own exit criteria (§3, §6) actually passing — no phase begins implementation against an assumed-but-unverified prior phase.

## Conclusion

Web Gateway BAS Mastery extends Audspect into HTTP-policy-and-control validation by building one new, architecturally independent package (`internal/webgwefficacy`) that owns web-gateway control-efficacy evidence, with its own 5-state verdict type and an explicit prevention/detection/response separation — never unified with the three verdict taxonomies that already exist elsewhere in this codebase for other domains. The strongest existing asset, the DLP/exfiltration sink infrastructure (`cloudsink`/`webhooksink`/`dlp_sink.go` plus existing scenario YAMLs), is reused as-is and extended with a gateway-side verdict layer, not rebuilt. The first live vendor integration is Cloudflare Gateway — chosen after verifying that none of the six originally-named vendors offer genuine self-serve API access, under eight explicit conditions that keep the claim honest about what one real integration does and does not prove. The five-phase roadmap delivers the evidence foundation, one trustworthy end-to-end vertical, policy/bypass breadth, vendor/regional expansion, and mastery certification in that order, with every phase gated on repository-verified reuse boundaries and an explicit, evidence-backed definition of done.
