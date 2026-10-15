# Email Gateway BAS Mastery: Architecture Specification

## Executive Summary

Audspect's Email Gateway (EmailGW) Mastery initiative extends Audspect to validate deployed email security controls — determining whether a client's already-purchased Microsoft Defender for Office 365, Proofpoint, Mimecast, Cisco Secure Email, or FortiMail actually enforces its intended policy, not merely whether a gateway is installed in front of the mailbox. The differentiator is control efficacy with defensible evidence, not phishing-simulation volume: for every tested capability, Audspect must state what the policy was expected to do, what the gateway actually did, whether the expected detection telemetry fired, whether the required response (quarantine, recall, account containment) actually completed, and how much confidence the evidence supports — with prevention, detection, and response always scored independently, never collapsed into one pass/fail.

This specification is a **repository-verified gap analysis plus a six-phase roadmap**, scoped at the architecture level, following the same discipline as `docs/superpowers/specs/2026-10-15-webgw-mastery-architecture-design.md` and `docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md`. It establishes what already exists and must not be rebuilt, what is new, how the new work is structured, and the order of delivery. It does not contain file-by-file designs or task breakdowns — each phase gets its own implementation specification when that phase begins.

Source requirements document: `emailGW.txt` (repo root). That document is a capability vision; this specification reconciles it against what Audspect's codebase actually contains today, and locks the architecture decisions the vision document deliberately left open (package boundary, verdict taxonomy encoding, first-provider choice).

## 1. Repository-Verified Gap Analysis

Every classification below was checked directly against the current repository (a dedicated audit, not inferred from `emailGW.txt`'s own description of what Audspect "should" do).

| Area | Status | Evidence |
|---|---|---|
| A. Sender identity, spoofing, trust (SPF/DKIM/DMARC, impersonation) | **Missing** | No code anywhere tests SPF/DKIM/DMARC enforcement, alignment, lookalike-domain detection, or display-name impersonation. |
| B. Phishing and social engineering (credential harvesting, BEC, pretexts) | **Partial, wrong layer** | `scenarios/outlook-rules-bec.yaml` emulates malicious-inbox-rule BEC via Outlook COM at the **endpoint**, and its own scenario notes explicitly scope out Exchange Online / tenant-level mail-flow detection as future work. `orchestrator/internal/exercise/smtp.go` provides SMTP-send capability usable as an authorized test sender. No gateway-side phishing-control validation (credential-harvesting-page blocking, URL rewriting, pretext detection) exists. |
| C. Attachments and content inspection (macros, sandboxing, MIME) | **Missing** | No executable/macro/archive/MIME-mismatch policy testing exists for any mail-gateway context. |
| D. URL, browser and post-delivery protection (click-time rewriting, recall) | **Missing** | No URL-rewriting, time-of-click, or post-delivery quarantine/recall testing exists. |
| E. Outbound security and data loss (DLP, auto-forwarding, encryption) | **Existing, wrong angle** | `orchestrator/internal/smtpsink` is a real SMTP listener used as a **DLP-exfiltration sink** (receives test messages from BAS agents to prove data left the environment over SMTP) — `scenarios/dlp-exfiltration-smtp.yaml`, `scenarios/dlp-exfiltration-multichannel.yaml` already validate this. This is the data-movement domain's SMTP channel, not a gateway's own outbound-policy verdict (quarantine/block/warn/encrypt on egress), the exact same "existing but wrong angle" relationship WebGW Mastery found for `internal/dnssink` against domain 07. Must not be modified. |
| F. Mailbox, identity and tenant security (delegation, OAuth consent, inbox rules) | **Partial, endpoint-only** | `scenarios/outlook-rules-bec.yaml` (above) covers endpoint-visible malicious inbox rules only. No tenant-level OAuth-app-consent, mailbox-delegation, or Entra conditional-access testing for mail exists. |
| G. Detection, incident response and resilience (telemetry correlation, alert quality) | **Pattern precedent only** | `orchestrator/internal/detectverify.Connector` (`Verify(ctx,req)`, `TestConnection(ctx)`) with 7 real vendor implementations (`crowdstrike.go`, `defenderxdr.go`, `elastic.go`, `qradar.go`, `sentinel.go`, `splunk.go`, `trellix.go`) is the established, proven shape for "call a real vendor API, normalize the response, correlate against an expected test." `defenderxdr.go` already queries Defender alerts — reusable as a *pattern*, not email-specific today. |
| **Provider adapters** | | |
| Microsoft 365 Defender for Office 365 | **Strong reuse available, not email-specific yet** | `orchestrator/internal/vendors/defender/client.go` (+`client_test.go`) is a real OAuth client (via `internal/platform/msauth`) against Microsoft's API, currently used only for Live Response endpoint actions (e.g. `KillProcess`). `orchestrator/internal/detectverify/defenderxdr.go` separately queries Defender alerts. Neither touches mail-flow policy, Safe Links, Safe Attachments, or Exchange Online Protection today — but the OAuth/tenant-client plumbing is the strongest existing asset for any M365 adapter. |
| Proofpoint / Mimecast / Cisco Secure Email / FortiMail | **Missing** | Zero code anywhere references any of these products. |
| **Reporting** | | |
| Email-specific report template | **No plumbing, sample artifact only** | `reports/email_gateway_csv_report.csv` is a standalone sample export (third-party-tool-shaped columns: Template name, Rewritten Link, SHA256, etc.) — grepping `internal/reporting/engine.go` and its ATT&CK enrichment data shows only incidental prose mentions of "email gateway" in generic detection-guidance text, no code path reads or produces this CSV. Treat as a reference artifact, not existing plumbing. |

**No existing `emailgw`, `mailgw`, or `emailefficacy` package exists anywhere.** This is genuinely greenfield at the package level, with two real reusable assets (the Defender OAuth client, the `detectverify` connector pattern) and two existing capabilities that sit adjacent but out of scope (`smtpsink`, `outlook-rules-bec.yaml`).

**Verdict-taxonomy precedent assessment:** three verdict/outcome types already exist in this codebase for other domains — `scenario.ExecutionOutcome` (endpoint-technique execution), `networkefficacy.EfficacyVerdict` (network-flow), and `webgwefficacy.WebGWVerdict` (`Pass/Fail/Inconclusive/Unsupported/NotApplicable`, HTTP-policy). **Unlike `webGW.txt`, which left verdict naming open, `emailGW.txt` §3 fixes its own 5-state taxonomy by name: Confirmed failure, Confirmed success, Inconclusive, Not tested, Not applicable.** Decision: EmailGW gets its own verdict type using **exactly `emailGW.txt`'s own names**, not `webgwefficacy`'s wording, and never unified with any of the four existing taxonomies — the source document itself locked this naming, so this specification does not relitigate it.

**Control-efficacy architecture precedent assessment:** `internal/webgwefficacy` has the right *shape* — an expectation (what should happen) vs. evidence (what a real product's logs say happened) vs. a verdict with an explicit reason — but its matching primitive is an HTTP request (URL, category, user). An email message's matching primitive is different again: a message has a sender identity, a lifecycle (accepted → inspected → delivered/quarantined/rewritten), and — uniquely among Audspect's control-efficacy verticals so far — **two separate evidence legs that must each be established independently: what the authorized test sender actually transmitted, and what the receiving system actually observed** (`emailGW.txt` §3, item 3). Decision: build a new, parallel `orchestrator/internal/emailgwefficacy` package, architecturally independent of `webgwefficacy`, `networkefficacy`, `adefficacy`, and `detectverify` (no import of any of them), reusing only the structural pattern — exactly as `webgwefficacy` itself reused `networkefficacy`'s pattern without importing it.

## 2. Architecture

### 2.1 Package: `orchestrator/internal/emailgwefficacy`

A new, independent leaf package. It imports no other Audspect efficacy/control-validation package by default. `emailGW.txt` §3 is explicit that this vertical must not modify or generalize `internal/controlval` — that instruction is honored the same way WebGW Mastery honored it: zero import, pattern-only reuse.

Core types (names final, field lists indicative — each phase's own implementation spec nails down exact fields and JSON tags):

```go
// ExpectedMailAction is what an email-security policy was declared to
// be expected to do for a message profile -- never inferred from
// observed behavior.
type ExpectedMailAction string
const (
    ExpectedDeliver    ExpectedMailAction = "deliver"
    ExpectedQuarantine ExpectedMailAction = "quarantine"
    ExpectedReject     ExpectedMailAction = "reject"
    ExpectedRewrite    ExpectedMailAction = "rewrite-link"
    ExpectedEncrypt    ExpectedMailAction = "encrypt"
    ExpectedTagWarning ExpectedMailAction = "tag-warning"
)

// MailExpectation is one declared "what should this gateway have
// done" for one message profile (emailGW.txt's taxonomy areas A-F
// each produce these, not a shared generic fixture).
type MailExpectation struct {
    SenderProfile  string             // e.g. "spoofed-exec-display-name"
    Recipient      string
    MessageClass   string             // e.g. "spf-fail", "macro-attachment", "known-bad-url"
    ExpectedAction ExpectedMailAction
    ControlProduct string             // e.g. "m365-defender-o365"
    Note           string
}

// EvidenceSource records how a piece of evidence was obtained --
// synthetic, fixture, or live -- identical discipline to
// webgwefficacy.EvidenceSource, independently defined (no import).
type EvidenceSource string
const (
    SourceSynthetic EvidenceSource = "synthetic"
    SourceFixture   EvidenceSource = "recorded-fixture"
    SourceLive      EvidenceSource = "live"
)

// OriginDeliveryObservation is emailGW.txt's observation-model item 3:
// what the authorized test sender actually transmitted, and what the
// receiving system actually observed -- two independent legs, never
// merged into one "it arrived" boolean.
type OriginDeliveryObservation struct {
    SenderPayloadHash string    // what was actually sent, hashed for reproducibility
    ObservedOutcome   string    // "delivered" | "not-received" | "quarantined" | ...
    DeliveryRoute     string    // internal | external | partner-exception | ...
    Timestamp         time.Time
}

// EnforcementEvidence is observation-model item 1: was the message
// accepted, rejected, quarantined, rewritten, encrypted, or
// remediated, and which control made the decision.
type EnforcementEvidence struct {
    Action      string // the gateway's own observed action
    PolicyRule  string // which rule/policy fired, if attributable
    ControlProduct string
    Timestamp   time.Time
    Source      EvidenceSource
    Provenance  Provenance
    RawEvent    json.RawMessage
}

// DetectionEvidence is observation-model item 2: was the expected
// alert generated, with which product, rule, event, timestamp and
// correlation identifier.
type DetectionEvidence struct {
    AlertGenerated  bool
    Product         string
    Rule            string
    CorrelationID   string
    Timestamp       time.Time
    Source          EvidenceSource
    Provenance      Provenance
}

// ResponseEvidence is observation-model item 4: did quarantine,
// recall, account containment or another required action actually
// complete, and how long did it take. Containment is modeled here,
// not as a fourth independent verdict axis (locked, see EfficacyResult).
type ResponseEvidence struct {
    ActionRequired  string // "quarantine" | "recall" | "account-containment" | ...
    Completed       bool
    DurationToComplete time.Duration
    Timestamp       time.Time
    Source          EvidenceSource
    Provenance      Provenance
}

// Provenance is observation-model item 5, attached to every evidence
// record individually rather than once per result -- distinct
// evidence items in the same result can have different provenance
// (e.g. enforcement observed directly, detection inferred from a
// missing-alert timeout).
type Provenance struct {
    Kind       ProvenanceKind // observed | inferred
    Confidence Confidence     // high | medium | low
    Basis      string         // required whenever Kind is inferred
}
type ProvenanceKind string
const (
    ProvenanceObserved ProvenanceKind = "observed"
    ProvenanceInferred ProvenanceKind = "inferred"
)
type Confidence string
const (
    ConfidenceHigh   Confidence = "high"
    ConfidenceMedium Confidence = "medium"
    ConfidenceLow    Confidence = "low"
)

// EmailGWVerdict uses emailGW.txt's own §3 naming exactly -- locked,
// never renamed to match webgwefficacy's wording, never unified with
// any other domain's taxonomy.
type EmailGWVerdict string
const (
    VerdictConfirmedFailure  EmailGWVerdict = "confirmed-failure"
    VerdictConfirmedSuccess  EmailGWVerdict = "confirmed-success"
    VerdictInconclusive      EmailGWVerdict = "inconclusive"
    VerdictNotTested         EmailGWVerdict = "not-tested"
    VerdictNotApplicable     EmailGWVerdict = "not-applicable"
)

// VerdictDetail is one independently-scored dimension's result.
// Reason is required whenever Verdict is not VerdictConfirmedSuccess.
type VerdictDetail struct {
    Verdict EmailGWVerdict
    Reason  string
}

// EfficacyResult keeps prevention, detection, and response as three
// independently-verdicted dimensions, matching webgwefficacy's own
// precedent. emailGW.txt §7 names "prevention, detection, containment
// and response" as four things findings must distinguish -- locked
// decision: containment is scored inside the Response dimension
// (ResponseEvidence already models quarantine/recall/account
// containment together, per the source document's own observation
// model item 4), not as a fourth independent verdict axis. This
// mirrors exactly how WebGW Mastery's Goal-text-vs-binding-exit-
// criteria distinction was drawn in its own Phase 3-5 amendments.
type EfficacyResult struct {
    Expectation MailExpectation
    Observation OriginDeliveryObservation
    Enforcement []EnforcementEvidence
    Detection   []DetectionEvidence
    Response    []ResponseEvidence
    Prevention  VerdictDetail
    DetectionVerdict VerdictDetail
    ResponseVerdict  VerdictDetail
}
```

**`NotTested` vs. `Inconclusive`, enforced structurally, not by convention:** mirrors `webgwefficacy`'s `Unsupported`/`Inconclusive` split exactly, under `emailGW.txt`'s own names. `NotTested` means prerequisites, access, telemetry, or scenario execution were unavailable for this capability generally (e.g., no tenant-admin consent to query Safe Attachments verdicts, or no adapter exists yet for this product) — determinable once, independent of any single run. `Inconclusive` means the capability exists and ran, but this run's specific evidence is insufficient, contradictory, or ambiguous. A verdict-computation function takes capability availability as an explicit, separate input from this run's evidence, exactly as `webgwefficacy` requires for `Unsupported`.

**Never collapsing a missing downstream signal into a false finding, enforced in the same function:** `emailGW.txt` §3's closing instruction — "Never report missing SIEM telemetry as proof that the gateway failed to block a message. Never claim a finding is false merely because one downstream product did not generate an alert" — is implemented as a structural rule in the verdict-computation function, not left as documentation: an empty `DetectionEvidence` slice can only ever produce `VerdictNotTested` or `VerdictInconclusive` for the `DetectionVerdict` dimension, and is never read as input to the `Prevention` dimension's computation at all. The two dimensions are computed from disjoint evidence slices (`Enforcement` vs. `Detection`) by construction, so there is no code path by which one dimension's absence can lower another's verdict.

### 2.2 Vendor integration: borrowed pattern, not a shared interface

Vendor adapters are **not** `detectverify.Connector` implementations and do not import `internal/detectverify`. They borrow its proven *shape* — a config struct, a method that calls the real vendor API over HTTP, normalizes the response, and returns typed evidence. A `MailEvidenceProvider` interface (mirroring `webgwefficacy.GatewayEvidenceProvider`) is implemented directly by each adapter:

```go
type MailEvidenceProvider interface {
    EnforcementEvidenceFor(msg MessageRef, window TimeWindow) ([]EnforcementEvidence, error)
    DetectionEvidenceFor(msg MessageRef, window TimeWindow) ([]DetectionEvidence, error)
}
```

### 2.3 First live provider: Microsoft 365 Defender for Office 365

**Locked decision:** Microsoft 365 Defender for Office 365 is the first live adapter target, for two reasons neither of which applies to Proofpoint, Mimecast, Cisco Secure Email, or FortiMail:

1. **Existing reusable infrastructure.** `orchestrator/internal/vendors/defender/client.go` already has a working OAuth client against Microsoft's tenant API (via `internal/platform/msauth`), and `orchestrator/internal/detectverify/defenderxdr.go` already queries Defender alerts. No other named vendor has any code in this repository today.
2. **Self-serve account access.** Microsoft's own M365 Developer Program issues free, renewable developer tenants that include Defender for Office 365 Plan 2 (Safe Links, Safe Attachments, anti-phishing policies, Exchange Online Protection) without a sales engagement — the same "genuine self-serve access" bar WebGW Mastery used to rule out Zscaler/Netskope/Forcepoint/Skyhigh/Broadcom/FortiProxy in favor of Cloudflare. Proofpoint, Mimecast, Cisco Secure Email, and FortiMail are all sales/POV-gated enterprise products with no equivalent self-serve developer tier.

This decision carries explicit conditions, carried forward from WebGW Mastery's own §2.3 and binding on Phase 3's implementation spec:

1. **Provider scope.** M365 Defender for Office 365 is the first live adapter. Proofpoint, Mimecast, Cisco Secure Email, and FortiMail remain planned candidates (§5), not supported integrations, until each one's own access/API/evidence/licensing is independently verified — no claim of support without that verification.
2. **API and tenant verification before implementation.** Phase 3's own implementation spec must confirm, against Microsoft's current documentation and a provisioned developer tenant, which specific Graph Security API / Exchange Online PowerShell / reporting endpoints expose mail-flow policy configuration, Safe Links/Safe Attachments verdicts, and quarantine events, and what admin-role/consent is required for each — this document does not freeze those details.
3. **Evidence contract.** Each controlled test message is correlated against both the origin/delivery observation and the gateway's own enforcement/detection evidence. Missing or inaccessible evidence yields `NotTested` or `Inconclusive`, never an assumed `ConfirmedSuccess`.
4. **Synthetic payloads only.** Every attachment, URL, and credential-harvesting page used in testing is an inert, authorized-lab fixture — `emailGW.txt` §1.C's own constraint, identical in spirit to WebGW Mastery's EICAR-only rule for domain 04. A simulated malicious payload is never replaced with a real malicious sample to increase test intensity.
5. **Mock/live parity, never substituted silently.** Deterministic fixtures back unit and regression tests so the suite runs without live tenant access or credentials. The live adapter is exercised only in integration tests explicitly labeled as such.
6. **Fallback is a documented gap, never a silent substitution.** If an essential capability or permission turns out unavailable on the tenant/license tier used, the acceptance criterion depending on it is marked `NotTested` with the specific blocking gap documented — never a silent fallback to a mock reported as success.

**Boundary, stated explicitly so it is never overclaimed later:** validating against M365 Defender for Office 365 proves Audspect's architecture and evidence pipeline work against one real email gateway product. It does not establish universal email-gateway coverage, and does not imply the same behavior exists in Proofpoint, Mimecast, Cisco Secure Email, or FortiMail. Any report citing this work must say so.

## 3. Phase Roadmap

Six phases, following `emailGW.txt` §6's own recommended order (that order is adopted as correct; it already separates "domain model" from "first real vertical" from "attack-vector expansion," the same three-way split Network BAS and WebGW Mastery both used) — each phase gets its own implementation spec when it begins; this document fixes only architecture and boundaries.

### Phase 1 — Repository Audit and Master Specification

**Goal:** this document. Satisfied by §1's repository-verified gap analysis and this specification's lock of the package boundary, verdict taxonomy, and evidence model, per `emailGW.txt`'s own explicit "immediate next step."

**Exit criteria:** this specification exists, is reviewed, and is treated as locked before any `internal/emailgwefficacy` code is written — matching `emailGW.txt`'s own instruction not to start with coding.

### Phase 2 — Domain Model and Evidence Contract

**Goal:** `orchestrator/internal/emailgwefficacy` exists, compiles, and is tested — `MailExpectation`, `EnforcementEvidence`, `DetectionEvidence`, `ResponseEvidence`, `OriginDeliveryObservation`, `Provenance`, `EmailGWVerdict`, `EfficacyResult` (§2.1) all exist with zero live vendor integration. Deterministic, fixture-backed tests only, mirroring exactly how `webgwefficacy` and `networkefficacy` each shipped their fixture providers before any real vendor integration existed.

**Exit criteria:** a fixture-backed `MailEvidenceProvider` implementation proves the expectation → evidence → verdict pipeline end-to-end for at least one delivered case and one quarantined case; `NotTested` and `Inconclusive` are each independently reachable and tested as distinct outcomes; a test proves the structural rule in §2.1 (missing `DetectionEvidence` cannot affect the `Prevention` verdict).

### Phase 3 — First Real End-to-End Vertical

**Goal:** prove sender → gateway → recipient/quarantine → event retrieval → evidence correlation → Audspect finding against the real M365 Defender for Office 365 adapter (§2.3, all 6 conditions), using `orchestrator/internal/exercise/smtp.go` (or an extension of it) as the authorized test sender. Establish a repeatable baseline covering at least sender-identity (SPF/DKIM/DMARC) and one phishing/attachment scenario.

**Exit criteria:** at least one SPF/DKIM/DMARC-alignment scenario and one attachment-or-URL scenario execute end-to-end against the real M365 Defender adapter, each producing an `EfficacyResult` with independently-verdicted Prevention/DetectionVerdict/ResponseVerdict, backed by evidence tagged `SourceLive`. A fixture-backed parallel exists for both so the regression suite never requires live tenant credentials. If tenant access or licensing blocks live execution at the time this phase starts, it is handled exactly as WebGW Mastery's Phase 2 handled the Cloudflare card blocker: split into a fixture-only sub-phase that proceeds immediately and a live sub-phase documented as blocked in a QA log, never silently skipped or claimed done.

### Phase 4 — Attack-Vector Expansion

**Goal:** add the remaining `emailGW.txt` §1 taxonomy areas not yet covered by Phase 3 — phishing/BEC/pretext scenarios beyond Phase 3's seed, attachment/content inspection (macros, archives, sandbox-verdict timing), URL/post-delivery protection (click-time rewriting, message recall), outbound DLP (reusing the evidence-model shape, not `internal/smtpsink` itself, per §1's exclusion), and mailbox/identity/tenant abuse (OAuth consent, inbox rules, mailbox delegation) at the tenant level — a genuinely new capability, since `outlook-rules-bec.yaml` only ever covered the endpoint leg.

**Exit criteria:** each taxonomy area A-F has at least one proven scenario (known-good plus one negative/failure case, per `emailGW.txt`'s own quality bar), executing against either the real M365 Defender adapter or a fixture-backed equivalent with the gap documented.

**Amendment, 2026-10-15 (design locked before any Phase 4 code was written):** areas A (sender identity) and B (phishing/social engineering) already each have a proven known-good/known-bad scenario from Phase 3a (`SPFAlignmentExpectation`/`DKIMAlignmentExpectation`/`DMARCPolicyExpectation`, `CredentialHarvestingURLExpectation`) — this phase's own binding scope is therefore the remaining four areas, C/D/E/F, one scenario pair each, following the same Goal-text-vs-binding-exit-criteria discipline WebGW Mastery's own Phase 3/4/5 used.

- **Area C (attachments/content inspection):** `EICARAttachmentExpectation(caught bool)` reuses `MailExpectation`/`EnforcementEvidence`/`VerifyMailExpectation` unchanged — an attachment-bearing message is still just a message with a declared expected action, the same reasoning WebGW Mastery's own domain 04 used to reuse `HTTPExpectation` rather than invent a new type for its EICAR scenario. The industry-standard EICAR test string is the declared synthetic artifact, never a real malware sample, per `emailGW.txt` §1.C's own named constraint.
- **Area D (URL/post-delivery protection):** `URLRewriteExpectation(knownBad bool)` likewise reuses `MailExpectation` unchanged — `knownBad=true` declares `ExpectedRewrite` (a malicious/unknown-reputation URL should be rewritten for click-time inspection), `knownBad=false` declares `ExpectedDeliver` (a benign URL needs no rewriting, the false-positive/legitimate-mail case). Distinct from area B's `CredentialHarvestingURLExpectation`, which tests whether a social-engineering lure is caught at all, not whether a URL was technically rewritten.
- **Area E (outbound security/DLP):** `OutboundDLPExpectation(sensitive bool)` likewise reuses `MailExpectation` unchanged — `sensitive=true` declares `ExpectedQuarantine` (synthetic sensitive-data marker, non-sensitive and non-real per the same discipline `internal/cloudsink`'s own DLP scenarios already use), `sensitive=false` declares `ExpectedDeliver` (ordinary outbound mail, the false-positive case). Outbound direction is encoded by `MessageClass` and an external `Recipient` domain, not a new struct field — no `Direction` field is added to `MailExpectation` for this one scenario; revisit only if a future phase needs to branch logic on direction, not just label it. Does not modify `internal/smtpsink` or its existing DLP-exfiltration scenarios, per the architecture spec's own exclusion (§7) — this is a gateway-side outbound-policy verdict, a different evidence model entirely from that package's exfiltration-sink role.
- **Area F (mailbox/identity/tenant security):** genuinely new shape, not a `MailExpectation` reuse — unlike C/D/E, which are all still "one message, one declared delivery action," F's own first capability (suspicious inbox/auto-forwarding rule creation, the sub-capability this document's own Phase 3 Goal text already flagged as the new tenant-level work `outlook-rules-bec.yaml` doesn't cover) is a **mailbox configuration state**, not a message. New, parallel type family — `InboxRuleExpectation`/`InboxRuleEvidence`/`InboxRuleEvidenceProvider`/`VerifyInboxRuleExpectation` — mirroring WebGW Mastery's own `dns.go`/`tls.go` precedent (a genuinely different-shaped check gets its own small type family rather than stretching `MailExpectation` to mean something it doesn't). `VerifyInboxRuleExpectation` returns a single `VerdictDetail`, not a full `EfficacyResult` — the check is inherently single-dimensional (was the rule detected or not), the same reasoning WebGW's `VerifyDNSQueryExpectation` used for its own single-`VerdictDetail` return. Reuses `EmailGWVerdict`/`VerdictDetail`/`EvidenceSource`/`Provenance` from `types.go` unchanged — one verdict taxonomy for the whole package, never a second one per sub-file, matching every one of this package's prior decisions.

Mailbox delegation/OAuth-consent, MFA/conditional-access, legacy-auth/SMTP-AUTH exposure, audit-log/configuration-drift, and cross-tenant-trust — the other six sub-capabilities `emailGW.txt` §1.F itself names — remain unbuilt, not silently claimed; `AudspectWebGWCoverageReport`-style living coverage reporting is Phase 6's own job (mutation/coverage, mirroring WebGW Phase 5), not retrofitted here.

### Phase 5 — Provider Breadth and Sector Packs

**Goal:** additional vendor adapters (Proofpoint, Mimecast, Cisco Secure Email, FortiMail) added only after each one's own access/API/evidence/licensing is independently verified against that vendor's current offering — no fixed order locked here. India/UAE regulatory mapping (RBI directions, DPDP, CBUAE requirements, UAE health-data rules) follows `internal/regobligation`'s established *pattern* (immutable evidence snapshots, versioned obligations, applicability by jurisdiction/sector) without importing its types, mirroring WebGW Mastery's own Phase 4. Industry profiles (BFSI/NBFC, healthcare, manufacturing/OT-adjacent, SMB/MSP) are configuration — priorities, data classifications, business-impact weighting — layered onto the Phase 2-4 scenario library, never a second scoring system, per `emailGW.txt` §4's own explicit instruction.

**Exit criteria:** at least one additional vendor adapter is either integrated end-to-end or explicitly, visibly marked `NotTested`/`not-applicable` with the specific blocking gap documented (never silently dropped); at least one regulatory obligation per jurisdiction (India, UAE) is mapped end-to-end from obligation to control to scenario to evidence, matching Network BAS Phase 7C's and WebGW Phase 4's own bar.

### Phase 6 — Mastery Regression and Assurance

**Goal:** reproducible fixtures, known-good and known-bad configurations, false-positive tracking (legitimate-mail regressions, `emailGW.txt` §1.A's own named requirement), failure injection / mutation testing (weaken a policy in a lab, verify the relevant scenario catches the regression, restore, verify recovery), versioned scenarios, evidence-integrity checks, and regression gates for every provider — mirroring WebGW Mastery's own Phase 5 `mutation.go`/`coverage.go` pattern, built fresh for this package rather than imported.

**Exit criteria:** at least one mutation test is proven to catch a deliberately-introduced regression and to confirm recovery after the fix; at least one false-positive (legitimate-mail) regression test exists per provider adapter; coverage reporting cites its denominator and exclusions on every report, never a bare percentage — matching WebGW Mastery's own Phase 5 bar exactly.

## 4. Safety and Quality Contract

Carried forward and adapted from `emailGW.txt` §2-3 and §7, binding on every phase above, not aspirational text:

- **Prevention, detection, and response are always scored independently** (`EfficacyResult.Prevention`/`.DetectionVerdict`/`.ResponseVerdict`, §2.1). A blocked message with no alert and a delivered message with an alert are both material findings, never merged into one verdict.
- **Containment is scored inside Response, not as a fourth axis** — locked in §2.1, so no future phase re-splits this without a fresh architectural decision.
- **Observed evidence is never confused with inferred evidence.** Every evidence record carries an explicit `Provenance` (`observed`/`inferred`, with required `Basis` when inferred) and `Source` (`synthetic`/`recorded-fixture`/`live`) — a mock result is never reported as proof a real product behaved a certain way.
- **`NotTested` and `Inconclusive` are structurally distinct** (§2.1) — a capability that genuinely is not accessible (no admin consent, no adapter) is never reported the same way as a run whose evidence happened to be missing.
- **A missing downstream signal never becomes a false finding elsewhere** (§2.1's disjoint-evidence-slice rule) — `emailGW.txt` §3's own closing instruction, enforced structurally, not by convention.
- **A blocked message is not automatically proof of a healthy posture; a delivered message is not automatically proof of a vulnerability** (`emailGW.txt` §2) — the scenario's intended policy, applicable exception, delivery route, and actual control behavior must all be established before a verdict is assigned.
- **Synthetic, inert payloads only** (§2.3 condition #4) — no real malicious attachment or live credential-harvesting target is ever used, even in an authorized lab.
- **No active probing against production mailboxes, external third parties, or live customer traffic** without a separately-approved test design — the same posture WebGW Mastery and Network BAS both carry for OT-adjacent/production-adjacent targets, applied here to real employee/customer mailboxes.
- **A successful simulation or report is never presented as proof of regulatory compliance without qualified review** (`emailGW.txt` §4's own instruction) — the same non-negotiable every other Audspect mastery vertical carries.
- **No coverage percentage without a defined denominator and explicit exclusions** — matching WebGW Mastery Phase 5's own bar.

## 5. Coverage Matrix

Implemented / Reusable / Planned / Not Tested, per the repository-verified gap analysis in §1. This matrix is the living source of truth for "what can Audspect actually claim about EmailGW" at any point — update it at the end of every phase, never advertise an area's coverage beyond what this table currently says.

| Area | Status (as of this spec) | Notes |
|---|---|---|
| A. Sender identity/spoofing/trust | Planned (Phase 3 seed, Phase 4 breadth) | Zero existing code; first real scenario targeted for Phase 3's end-to-end vertical. |
| B. Phishing/social engineering | Partial — endpoint-only (`outlook-rules-bec.yaml`) | Tenant/gateway-level phishing-control validation planned Phase 3-4. |
| C. Attachments/content inspection | **Fixture-backed coverage added (Phase 4)** | EICAR test-attachment scenario proven end-to-end against the existing `MailExpectation`/`VerifyMailExpectation` pipeline (`scenarios_test.go`), reused unchanged — mirrors WebGW Mastery's own domain-04 EICAR reuse. Download reputation/MIME mismatches, archive inspection, script/macro/PUA policy, and sandbox-detonation timing remain unbuilt. |
| D. URL/browser/post-delivery protection | **Fixture-backed coverage added (Phase 4)** | URL-rewrite-for-click-time-inspection scenario (`URLRewriteExpectation`) proven end-to-end against the existing pipeline, unchanged (`scenarios_test.go`). Time-of-click verdict divergence from initial-delivery inspection and message recall/retroactive remediation remain unbuilt. |
| E. Outbound security/DLP | **Fixture-backed coverage added (Phase 4)** | Outbound synthetic-sensitive-marker scenario (`OutboundDLPExpectation`) proven end-to-end against the existing pipeline, unchanged (`scenarios_test.go`). `internal/smtpsink` remains the data-movement domain's SMTP channel, untouched — this is a separate, gateway-side outbound-policy verdict layer. Auto-forwarding/personal-webmail restrictions and encryption-requirement testing remain unbuilt. |
| F. Mailbox/identity/tenant security | **Fixture-backed coverage added (Phase 4)** | Suspicious auto-forwarding inbox-rule detection (`SuspiciousAutoForwardExpectation`/`inboxrule.go`), a genuinely new type family (declared mailbox-configuration-state expectation vs. detection evidence vs. a single `VerdictDetail`, mirroring `dns.go`/`tls.go`'s own precedent) — the tenant-level leg `outlook-rules-bec.yaml` never covered. Mailbox delegation/OAuth-consent, MFA/conditional-access, legacy-auth/SMTP-AUTH exposure, audit-log/configuration-drift, and cross-tenant-trust remain unbuilt. |
| G. Detection/IR/resilience | Pattern precedent only (`detectverify.defenderxdr.go`) | Borrowed structurally in Phase 3; no email-specific detection correlation exists yet. |
| **Vendors** | | |
| Microsoft 365 Defender for Office 365 | Reusable OAuth client exists, not email-specific yet; first live adapter target (Phase 3) | `internal/vendors/defender/client.go`, `internal/detectverify/defenderxdr.go`. |
| Proofpoint / Mimecast / Cisco Secure Email / FortiMail | Not tested, access unverified | Planned candidates (Phase 5), same sales-gated-pending-verification posture WebGW Mastery used for its five non-Cloudflare vendors. |
| **Industry profiles** | | |
| BFSI/NBFC, Healthcare, Manufacturing, SMB/MSP | Planned (Phase 5) | Configuration layered on the Phase 2-4 scenario library, never a second scoring system. |
| **Regulatory** | | |
| India (RBI, DPDP) / UAE (CBUAE, health-data rules) | Planned (Phase 5) | Follows `regobligation`'s pattern, independent types, matching WebGW Phase 4's own bar. |

## 6. Acceptance Criteria Methodology

Per-phase exit criteria are stated in §3; `emailGW.txt` §7 fixes the initiative-wide acceptance bar, restated here so no phase's implementation spec has to reinvent it:

- **Executable, not descriptive.** Every claimed attack vector maps to a documented test, expected behavior, prerequisites, and evidence requirements, proven by a test that actually runs it — never a written description of intended behavior.
- **Declared capability matrix.** Every supported provider has a declared and tested capability matrix (§5); unsupported capabilities are explicit, never implied.
- **Four-way finding distinction.** Findings distinguish prevention, detection, containment, and response — in this architecture, containment is scored inside the Response dimension (§2.1, §4), satisfying the distinction without a fourth verdict axis.
- **Missing evidence produces `NotTested` or `Inconclusive`, never a fabricated success or failure** (§2.1, §4).
- **Reproducible confirmed findings.** Each confirmed finding (`ConfirmedFailure` or `ConfirmedSuccess`) includes reproducible test inputs, timestamps, correlation identifiers, applicable policy expectations, and supporting evidence.
- **Both directions measured.** Control failures and legitimate-mail regressions (false positives) are both measured — Phase 6's own exit criterion.
- **Existing orchestration paths only.** Scenarios run through Audspect's existing orchestration, authorization, audit, and reporting paths rather than a parallel execution engine — the same reuse discipline as every other mastery vertical.
- **Multi-tenant isolation and evidence integrity are tested**, not assumed, once a multi-tenant deployment model is in scope (Phase 5+).
- **Traceable sector/regional mappings.** Sector and regional mappings have traceable sources and version histories, matching `regobligation`'s own discipline.
- **Mutation-proven regression detection.** Regression tests prove that previously detected gaps remain detectable after provider, policy, and scenario changes — Phase 6's own exit criterion.

## 7. Explicit Exclusions and Dependencies

**Excluded from this initiative, by design:**

- Modifying or generalizing `internal/controlval` for this vertical — `emailGW.txt` §3's own explicit instruction.
- Unifying `emailgwefficacy`'s verdict model with `scenario.ExecutionOutcome`, `networkefficacy.EfficacyVerdict`, or `webgwefficacy.WebGWVerdict`. Locked in §1-2; do not revisit without a fresh architectural decision, not a convenience refactor.
- Claiming any of Proofpoint, Mimecast, Cisco Secure Email, or FortiMail as a "supported" integration before that vendor's own access/API/evidence/licensing has been independently verified (§2.3, §5).
- Modifying `orchestrator/internal/smtpsink` or its existing DLP-exfiltration scenario YAMLs (`dlp-exfiltration-smtp.yaml`, `dlp-exfiltration-multichannel.yaml`) — those remain the data-movement domain's SMTP channel, untouched (§1, §5).
- Modifying `scenarios/outlook-rules-bec.yaml` — remains the endpoint-only BEC emulation; this initiative's tenant-level mailbox/identity work (Phase 4, area F) is new, not an edit to that scenario.
- Replacing a simulated malicious payload with a real malicious sample to increase test intensity, at any phase (`emailGW.txt` §1.C, carried into §2.3 condition #4).
- Presenting a technical finding as a regulatory compliance determination (§4).
- Active probing against production mailboxes, external third parties, or live customer traffic without a separately-approved test design (§4).

**Depends on:**

- `orchestrator/internal/vendors/defender/client.go` and `orchestrator/internal/detectverify/defenderxdr.go` remaining stable in their current form through at least Phase 3; any extension adds new methods rather than altering their existing Live Response / alert-query behavior.
- `orchestrator/internal/exercise/smtp.go` remaining available as (or being extended into) the authorized test-message sender for Phase 3.
- A Microsoft 365 developer tenant with Defender for Office 365 licensing being provisioned before Phase 3 begins, with credentials handled under the same discipline as every other live-integration credential in this codebase (never checked into git, rotated per standard practice).
- `internal/regobligation`'s pattern (not types) remaining a valid structural reference for Phase 5's regulatory-mapping work; if that package's own shape changes materially before Phase 5 begins, Phase 5's implementation spec must re-verify the reference.
- Each phase from Phase 2 onward is gated on the prior phase's own exit criteria (§3, §6) actually passing — no phase begins implementation against an assumed-but-unverified prior phase.

## Conclusion

Email Gateway BAS Mastery extends Audspect into mail-flow-policy-and-control validation by building one new, architecturally independent package (`orchestrator/internal/emailgwefficacy`) that owns email-gateway control-efficacy evidence, using `emailGW.txt`'s own 5-state verdict names and an explicit prevention/detection/response separation (with containment scored inside response, not as a fourth axis) — never unified with the four verdict taxonomies that already exist elsewhere in this codebase for other domains. This vertical is genuinely greenfield: no prior art exists beyond an OAuth client for M365 Defender/Entra, a pattern-only detection connector for Defender alerts, and two adjacent-but-out-of-scope capabilities (the SMTP DLP-exfiltration sink, the endpoint-only BEC scenario) that must not be modified. The first live vendor integration is Microsoft 365 Defender for Office 365, chosen because it is the only named vendor with both existing repository infrastructure and genuine self-serve developer-tenant access, under six explicit conditions that keep the claim honest about what one real integration does and does not prove. The six-phase roadmap delivers the repository audit (this document), the evidence foundation, one trustworthy end-to-end vertical, attack-vector breadth, provider/regional expansion, and mastery regression in that order, with every phase gated on repository-verified reuse boundaries and an explicit, evidence-backed definition of done.
