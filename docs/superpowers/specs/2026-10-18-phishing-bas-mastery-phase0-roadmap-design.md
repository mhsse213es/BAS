# Phishing BAS Mastery — Phase 0: Roadmap & Architecture Approval

Status: **proposed, no implementation changes**. This document is the Phase 0
deliverable requested before any Phishing BAS Mastery code is written: an
inventory of what already exists, a PH-* reuse-and-gap matrix, the
architecture conflicts that need an explicit decision, and the phase gates
for the remaining work.

Source spec: `phishing.txt` (repo root) — both the validation requirements
(§1-8) and the enterprise blueprint upgrade (§1-5 of the second half).

Decision already made and binding on this document: **one Phishing BAS
capability, reusing EmailGW Mastery and `exercise` — not a competing
duplicate engine, and not a rebranding exercise.**

---

## 1. Architecture conflicts requiring an explicit decision

Research surfaced three precedents in the codebase that bear directly on
"reuse `internal/controlval`, don't create a competing taxonomy." Each is a
real conflict, not a style nit — resolving them wrong either breaks a locked
decision from a prior initiative or silently produces a fourth parallel
taxonomy.

### 1.1 `emailgwefficacy` is locked independent of `controlval`

`orchestrator/internal/emailgwefficacy/types.go:1-9` states, locked in
`docs/superpowers/specs/2026-10-15-emailgw-mastery-architecture-design.md`
§1-2:

> "architecturally independent of internal/controlval, internal/webgwefficacy,
> internal/networkefficacy, internal/adefficacy, and internal/detectverify —
> no import of any of them... any cross-package relationship this initiative
> ever takes on borrows a structural pattern, never a shared type."

This is the same precedent `adcontrolval` already demonstrates for AD: a
**one-way bridge package** that imports `controlval` plus the domain package,
while the domain package itself stays untouched and importless.

**Recommendation:** do not touch `emailgwefficacy`. Build a new bridge
package — `phishcontrolval` (name TBD at Phase 1) — that imports `controlval`
and reads the *output* of `emailgwefficacy.EfficacyResult`, `exercise`
evidence events, and (later) the identity adapter, mapping each into
`controlval.Observation`/`Expectation`/`Validation` at the boundary. This
satisfies "reuse `controlval`, don't create a competing taxonomy" for the new
PH-* layer while leaving the locked `emailgwefficacy` decision intact — the
bridge borrows the pattern `adcontrolval` already proved, it doesn't reopen
the lock.

**Needs your sign-off:** this resolves the conflict by *adding* a bridge
rather than *overriding* the lock. If you want the lock itself reopened
instead (e.g. migrating `emailgwefficacy` onto `controlval` directly), say so
explicitly — that is a different, larger change with its own migration cost
for existing EmailGW consumers.

### 1.2 Two verdict taxonomies will coexist

- `controlval.Verdict`: `PASS | FAIL | ERROR | SKIPPED` (+ `SkipReason`)
- `emailgwefficacy.EmailGWVerdict`: `ConfirmedSuccess | ConfirmedFailure |
  Inconclusive` (names locked to emailGW.txt §3 verbatim, never renamed)

**Recommendation:** the PH-* catalog's own verdict type is a **third,
PH-specific enum**, structurally mirroring `controlval` (same four-state
shape) but declared locally — consistent with the "borrow a pattern, never a
shared type" rule already governing `emailgwefficacy`. The bridge package
(§1.1) is the only place that translates `EmailGWVerdict` → PH verdict per
dimension. No consumer ever compares the two enums directly.

### 1.3 Two (arguably three) parallel SIEM-correlation surfaces

- `orchestrator/internal/detectverify/` — 7 real vendor connectors
  (CrowdStrike, Defender XDR, Elastic, QRadar, Sentinel, Splunk, Trellix),
  generic across all BAS domains, not phishing-specific.
- `orchestrator/internal/emailgwefficacy/siemcorrelation.go` — email-specific
  `SIEMEvidence`/`CorrelateWithSIEM`, fixture-only today.
- `orchestrator/internal/siem/` — a third, smaller package
  (`correlator.go`, `qradar.go`, `types.go`) that overlaps both.

**Recommendation:** do not consolidate these as part of Phishing Mastery —
that is pre-existing technical debt outside this initiative's scope, and
collapsing it silently risks breaking whichever initiative owns `internal/siem`
today (not yet identified). Phase 1 should: (a) feed PH-DET-001 from
`detectverify`'s real connectors as the live-evidence source, (b) leave
`emailgwefficacy.siemcorrelation` as-is (it already feeds EmailGW's own
`DetectionVerdict`), and (c) flag `internal/siem` for a **separate**
reconciliation task, not bundled into this roadmap.

---

## 2. PH-* reuse-and-gap matrix

Legend for **Maturity**: `real` = genuine API/SMTP/HTTP call proven to work
against something outside the test process; `fixture` = deterministic local
test double only; `none` = no implementation exists.

### A. Email authentication and sender trust

| PH-ID | Scenario | Existing implementation | Tests | Maturity | Gap |
|---|---|---|---|---|---|
| PH-AUTH-001 | External domain spoofing | `exercise/smtp_spoofing.go` `SpoofableSMTPInjector` (real SMTP dial, envelope-from/HELO/header-From control) | `smtp_spoofing_test.go` | real injection, fixture-tested | wrap with PH-ID; no DKIM signing so only the known-bad case is authentic |
| PH-AUTH-002 | SPF failure handling | `emailgwefficacy/scenarios.go` `SPFAlignmentExpectation` | scenario tests | fixture; real injector exists via `exercise` but not wired for a genuine SPF-pass case | same DKIM/SPF-pass-authoring gap, documented in-code already |
| PH-AUTH-003 | DKIM failure handling | `emailgwefficacy/scenarios.go` `DKIMAlignmentExpectation` | scenario tests | fixture | no signing capability anywhere in the codebase — same gap |
| PH-AUTH-004 | DMARC enforcement | `emailgwefficacy/scenarios.go` `DMARCPolicyExpectation` | scenario tests | fixture | same gap |
| PH-AUTH-005 | Display-name impersonation | `emailgwcampaign` BEC templates set a forged display-name as part of their execution; no standalone scenario | — | fixture | needs its own PH-* wrapper, currently folded into BEC templates only |
| PH-AUTH-006 | Lookalike-domain detection | none found | — | none | genuine gap |
| PH-AUTH-007 | Internal sender spoofing | `SpoofableSMTPInjector` relay/HELO control (real) | `smtp_spoofing_test.go` | real, fixture-tested | needs PH-* wrapper + internal-relay-path assertion |
| PH-AUTH-008 | Trusted-sender exception abuse | `emailgwefficacy/policybaseline.go` (policy precedence/exception modeling — confirm exact coverage at Phase 1 design time) | `policybaseline_test.go` | fixture | needs confirmation this covers allowlist-override specifically, not just baseline policy |
| PH-AUTH-009 | Forwarding/mailing-list behavior | none found | — | none | genuine gap |
| PH-AUTH-010 | Compromised legitimate sender | none found as a distinct scenario (BEC reply-chain hijacking is the closest neighbor, see PH-BEC-006) | — | none | genuine gap, likely shares plumbing with PH-BEC-006 |

### B. Business email compromise and targeted lures

| PH-ID | Scenario | Existing implementation | Tests | Maturity | Gap |
|---|---|---|---|---|---|
| PH-BEC-001 | Executive impersonation | `emailgwcampaign/templates.go` `BECSupplierFraudTemplate` uses exec-display-name spoofing as its lure persona | `templates_test.go` | fixture (real SMTP injection underneath) | needs its own PH-* ID if executive-targeting must be independently assertable from supplier-fraud |
| PH-BEC-002 | Vendor bank-account change | `BECSupplierFraudTemplate` — this is the exact scenario phishing.txt §4 presents as "target design, not a claim it exists." **It already exists.** | `templates_test.go` | fixture + real SMTP injection | rename/wrap only; verify it actually covers the full 6-step execution sequence in phishing.txt §4 (it currently stops at delivery/detection, not business-workflow-challenge or incident assignment — see PH-IR-004) |
| PH-BEC-003 | Invoice and payment diversion | overlaps PH-BEC-002 | — | fixture | needs scope split or explicit "same scenario, different ID" decision |
| PH-BEC-004 | Payroll and HR impersonation | none found | — | none | genuine gap |
| PH-BEC-005 | Procurement/PO fraud | none found | — | none | genuine gap |
| PH-BEC-006 | Reply-chain hijacking | none found | — | none | genuine gap (shares plumbing with PH-AUTH-010) |
| PH-BEC-007 | Urgent wire-transfer request | overlaps PH-BEC-002/003 | — | fixture | needs scope split |
| PH-BEC-008 | Customer/partner impersonation | none found | — | none | genuine gap |

### C. URL, browser, credential and identity attacks

| PH-ID | Scenario | Existing implementation | Tests | Maturity | Gap |
|---|---|---|---|---|---|
| PH-URL-001 | Known malicious URL | `emailgwcampaign/templates.go` `CredentialPhishingURLChainTemplate` (static lure stage) | `templates_test.go` | fixture | wrap only |
| PH-URL-002 | Newly observed domain | none distinct from PH-URL-001 | — | none | genuine gap |
| PH-URL-003 | Redirect-chain phishing | none found | — | none | genuine gap |
| PH-URL-004 | URL shortener | none found | — | none | genuine gap |
| PH-URL-005 | Time-of-click protection | `CredentialPhishingURLChainTemplate`'s "click-time bypass probe" stage is the closest match | `templates_test.go` | fixture | confirm it actually models a verdict change *after* delivery, not just a second static check |
| PH-URL-006 | QR-code phishing | none found anywhere (`exercise`/`tracker` has no QR generation) | — | none | genuine gap |
| PH-URL-007 | Cloud-hosted credential lure | none found | — | none | genuine gap |
| PH-ID-001 | Credential-harvesting simulation | `exercise/tracker/credential.go` `handleCredSubmit` + `landing.go` `defaultCredLandingHTML` — already records only the *fact* of submission (never the credential value), matching phishing.txt's requirement almost verbatim | `tracker_test.go` | real handler, fixture-tested | landing page is generic, not IdP-branded — cosmetic gap only |
| PH-ID-002 | OAuth consent abuse | none found | — | none | genuine gap — needs new Graph `/oauth2PermissionGrants` work against a real tenant |
| PH-ID-003 | Device-code phishing defense | none found (zero hits for `device_code`/`deviceCode`) | — | none | genuine gap |
| PH-ID-004 | MFA fatigue defense | none found (zero hits for `conditionalAccess`) | — | none | genuine gap |
| PH-ID-005 | Session-theft defense | none found | — | none | genuine gap |

Reusable plumbing for PH-ID-002/003/004/005: `platform/msauth/entra.go`
`EntraTokenSource` (shared Entra client-credentials token fetcher, already
used by Sentinel/Defender connectors) and `cloudgraph/azure_discovery.go`'s
proven Graph pagination pattern. Per the existing Azure Real Discovery
Integration project, new Graph calls here will likely hit the **same tenant
permission blocker** (no subscription, no admin role in the test tenant) —
these should be scoped as code-ready-pending-tenant-access, not claimed
complete on code alone.

### D. Attachments and payload delivery

| PH-ID | Scenario | Existing implementation | Tests | Maturity | Gap |
|---|---|---|---|---|---|
| PH-ATT-001 | HTML attachment | `SpoofableSMTPInjector`'s `TestAttachment`/MIME builder (real) | `smtp_spoofing_test.go` | real, fixture-tested | needs PH-* wrapper |
| PH-ATT-002 | PDF with embedded link | same injector, content-type parameterized | `smtp_spoofing_test.go` | real | wrap only |
| PH-ATT-003 | Office doc with external link | same injector | `smtp_spoofing_test.go` | real | wrap only |
| PH-ATT-004 | Macro policy enforcement | none found as a distinct assertion | — | none | genuine gap |
| PH-ATT-005 | Archive/nested archive | none found | — | none | genuine gap |
| PH-ATT-006 | Password-protected archive | none found | — | none | genuine gap |
| PH-ATT-007 | File-type mismatch | none found | — | none | genuine gap |
| PH-ATT-008 | Sandbox timeout/inconclusive verdict | none found | — | none | genuine gap |
| PH-ATT-009 | Cloud-file-sharing lure | none found | — | none | genuine gap |
| PH-ATT-010 | Post-delivery attachment verdict change | `emailgwefficacy` has a general "verdict changes after delivery" concept (same mechanism as PH-URL-005); not attachment-specific today | — | fixture | needs attachment-specific variant |

### E. Collaboration, mobile and cross-channel phishing

All eight (PH-CHN-001..008) came back **none found** across every fork.
Genuine, unbuilt gaps — no Teams/SharePoint/OAuth-app-invitation, mobile, SMS,
voice, or messaging-platform adapter exists anywhere in `orchestrator/internal`.
This is the largest pure-greenfield block in the catalogue and the correct
candidate for Phase 7 (cross-channel), not earlier.

### F. Evasion, detection and incident response

| PH-ID | Scenario | Existing implementation | Tests | Maturity | Gap |
|---|---|---|---|---|---|
| PH-EVA-001 | Allowlist policy bypass | `emailgwefficacy/policybaseline.go` (confirm exact scope) | `policybaseline_test.go` | fixture | overlaps PH-AUTH-008; needs scope split |
| PH-EVA-002 | Inbound relay-path bypass | `SpoofableSMTPInjector` relay control (real) | `smtp_spoofing_test.go` | real | wrap only |
| PH-EVA-003 | Security-filter exclusion | none distinct | — | none | genuine gap |
| PH-EVA-004 | Multilingual targeted lure | none found | — | none | genuine gap (ties to Phase 7 locale work) |
| PH-EVA-005 | Delayed/modified destination | overlaps PH-URL-005 | — | fixture | scope split |
| PH-DET-001 | SIEM ingestion and correlation | `detectverify` (7 real connectors, generic) + `emailgwefficacy/siemcorrelation.go` (email-specific, fixture) + `exercise/detectionbridge.go` (real correlation via `verification.Store`, never fabricates a negative into a positive) | `detectionbridge_test.go` + others | real correlation mechanism, fixture-tested end to end | needs the bridge in §1.1/§1.3 to unify these into one PH-* evidence source |
| PH-DET-002 | User-reported phishing | `exercise/tracker/credential.go` `handleReport` emits a real `"phishing_reported"` event, already wired into `WaitForDetectionConfig` as a chain-gating condition | `tracker_test.go` | real event capture | the *event* is built; actual SOC-side ingestion/triage (ticket creation, assignment) is not — extend `ticketcorrelation.go`'s fixture pattern |
| PH-IR-001 | Retroactive mailbox search and purge | none found. `vendors/defender/client.go` has real `QueryMailAlerts`/`QueryAnalyzedEmails`/`SendMail` Graph calls but no purge/remove method | — | none (real adapter exists to extend) | genuine gap, natural extension point identified |
| PH-IR-002 | Identity containment | none found. No Entra/AAD account-disable or session-revoke client anywhere | — | none | genuine gap. `rwevidence/containment.go`'s `ContainmentObserver` pattern (verify postcondition, not just "API accepted") is the template to mirror |
| PH-IR-003 | Endpoint follow-through | EPP response-action connectors (CrowdStrike/Defender/SentinelOne — real, live-call-capable `Isolate`/`KillProcess`/`QuarantineFile`) + `rwevidence/containment.go` verified-postcondition layer | existing EPP/rwevidence tests | real | least-gapped IR scenario — wiring only |
| PH-IR-004 | Incident escalation | `emailgwefficacy/ticketcorrelation.go` `CorrelateWithTicketing` (ServiceNow/Jira-shaped, non-self-corroborating) | ticketcorrelation tests | fixture-only (`FixtureTicketProvider`) | solid pattern, not live-validated; reusable as-is for Phase 1 |
| PH-MET-001 | Detection and response latency (MTTD/MTTR) | `internal/api/emailgw_metrics.go` `ComputeEmailGWTimeBasedMetrics`, `earliestDetectionLatency`, `earliestResponseLatency` — correct methodology (earliest qualifying observation, not injection-to-completion), minimum-sample gating, median aggregation | existing emailgw_metrics tests | real methodology, scoped to EmailGW's own types today | needs generalizing (or a thin PH-specific wrapper) to run over the new 7-dimension contract |

### Multi-stage chains and orchestration mechanism

`exercise/templates.go`'s existing phishing templates (`builtin-phishing-awareness`,
`builtin-bec`, `builtin-ransomware-response`, `builtin-credential-theft`) and
six later purple-team templates already prove shared-run-ID, per-step
dependency, mixed-detection-domain chain orchestration at 5+ stages. **No new
orchestration primitive is needed** — Phase 4 (multi-stage campaigns) is a
PH-* ID wrapper over this mechanism, not a new engine.

---

## 3. Consolidated new-build scope

Deduplicated across all research, the scenarios/capabilities with **no
existing implementation anywhere**, grouped by what they need:

- **Identity/session (Graph API, new adapter):** PH-ID-002, 003, 004, 005 —
  code-ready-pending-tenant-access at best (reuses `EntraTokenSource` +
  `cloudgraph` pagination pattern); real tenant-permission blocker expected,
  same as the Azure Real Discovery Integration precedent.
- **Email/identity incident-response actions (new adapters):** PH-IR-001
  (mailbox search-and-purge, extends the real `vendors/defender` client),
  PH-IR-002 (identity containment, mirrors `rwevidence.ContainmentObserver`).
- **User-report SOC ingestion/triage:** PH-DET-002's ticketing side (event
  capture already real; triage workflow is not).
- **Cross-channel (all 8):** PH-CHN-001..008 — no adapter of any kind exists.
- **URL/lookalike-domain depth:** PH-URL-002, 003, 004, 006, 007; PH-AUTH-006,
  009, 010; PH-BEC-004, 005, 006, 008; PH-ATT-004 through 009; PH-EVA-003, 004.
- **Cross-cutting framework pieces:** the 7-dimension outcome model itself,
  the variant-matrix abstraction, false-positive/business-continuity pairing,
  sector/locale profiles for phishing specifically, coverage-drift analytics,
  configurable evidence retention (currently hardcoded `"90d"` in
  `exercise/evidence.go`, a real gap against the India/UAE "configurable
  retention" requirement), and DKIM signing capability (missing everywhere,
  blocks authoring a genuine known-good case for any SPF/DKIM/DMARC-pass
  scenario — inherited gap from EmailGW Mastery, not new to this initiative).

---

## 4. Phase roadmap

Adopting the phase structure already agreed, with acceptance criteria
sharpened by the research above.

| Phase | Deliverable | Acceptance gate |
|---|---|---|
| 0 | This document | User approves architecture decisions (§1) and this matrix (§2-3) |
| 1 | Foundation: PH-* catalog schema, versioning, 7-dimension outcome model, evidence provenance, independent verdict evaluator (`phishcontrolval` bridge per §1.1), deterministic fixture harness | A single PH-* scenario (recommend PH-BEC-002, since the underlying template already exists) runs end to end through the new contract with a known-good and known-bad case, both verdicts correct, no import added to `emailgwefficacy` |
| 2 | Email ingress and BEC integration | Every §2 table row marked "wrap only" gets a stable PH-* ID and passes through the Phase 1 contract; no scenario renamed without a mapping entry; overlapping IDs (PH-BEC-002/003/007, PH-AUTH-008/PH-EVA-001, PH-URL-005/PH-EVA-005) get an explicit scope decision, not silent duplication |
| 3 | Provider-specific validation | Real Defender adapter calls proven against policy-exception and impersonation assertions; maturity declared per phishing.txt's "Coverage declaration" (implemented/fixture-tested/integration-tested/live-validated) for each |
| 4 | Multi-stage campaigns and adversarial variants | At least one chain spans email→URL→detection→response using `exercise/templates.go`'s existing orchestration mechanism wrapped in PH-* IDs; variant matrix (external/internal, authenticated/spoofed, pre/post-delivery) shares one scenario definition per phishing.txt §"Adversarial variant engine" acceptance bar |
| 5 | Identity and session attacks | PH-ID-002..005 adapters built against `EntraTokenSource`; explicitly reported as code-ready-pending-tenant-access unless a real/lab tenant with admin consent is available — never claimed live-validated without it |
| 6 | SOC, incident response, containment proof | PH-IR-001/002 built (mailbox purge extends Defender client; identity containment mirrors `rwevidence.ContainmentObserver`); PH-DET-002 triage path built on `ticketcorrelation.go`'s pattern; every containment action distinguishes "accepted" from "confirmed" |
| 7 | Cross-channel and sector-specific coverage | PH-CHN-001..008 adapters (scope per available integrations — do not claim voice/SMS validated without a real adapter); BFSI/healthcare/manufacturing phishing profiles + India/UAE locale (Hindi/Arabic, RTL) |
| 8 | Coverage analytics and release qualification | False-positive/business-continuity pairing; coverage-drift dashboard distinguishing catalogue/executable/evidence-backed/live-validated coverage; regression gates; no scenario marked complete on catalogue existence or unit-test pass alone |

---

## 5. Conditions carried forward into every phase

- **Reuse before rebuild:** no parallel EmailGW or `exercise` engine without a
  documented architectural reason (§1 resolutions are the only sanctioned
  exceptions).
- **Evidence before claims:** fixture-tested, adapter-tested, and
  live-validated stay distinguishable in every report, per existing
  `emailgwefficacy` maturity/coverage precedent.
- **No premature breadth:** each phase needs its own acceptance gate and a
  demonstrable end-to-end result before the next phase starts.
- **No artificial completeness:** a catalog entry is not an executable
  scenario; an executable simulation is not proof a customer control was
  effective.
- **Explicit dependencies:** identity, SOC response, and cross-channel
  capabilities are never marked complete because their schema or fixtures
  exist alone.

---

## 6. What this document is asking you to approve

1. The §1 architecture resolutions (bridge package over `controlval`,
   PH-local verdict enum, `detectverify` as the live-evidence source for
   PH-DET-001 with `internal/siem` reconciliation deferred).
2. The §2-3 reuse-and-gap matrix as the record of what's real vs. fixture vs.
   missing today.
3. Starting Phase 1 (Foundation) next, scoped to PH-BEC-002 as the first
   scenario proven end to end through the new contract.

## 7. Phase 1 status: DONE, with one corrected architecture decision

Phase 1 is complete. Before writing code, further research (reading
`internal/avval`'s own package comment) found that §1.1's proposed
`controlval`-bridge was based on incomplete evidence: `adcontrolval`'s
bridge into `controlval` is the **exception** in this codebase, not the
rule. `avval` independently declares the same lock `emailgwefficacy` does
("does NOT depend on internal/controlval, internal/wafval, or any vendor
type"). That is two domains (AV, Email), not one, choosing full
independence over a shared bridge -- the dominant, repeated pattern.
Phishing BAS Mastery follows that dominant pattern instead: `internal/phishval`
is a fully independent taxonomy (own `Verdict`, own per-dimension outcome
enums), never importing `controlval`. The "borrow a pattern, never a
shared type" rule is honored by shape (phishval's 5-value `Verdict` mirrors
`emailgwefficacy.EmailGWVerdict`'s shape, not `controlval.Verdict`'s
4-value shape or `avval.FindingClassification`'s 3-value shape), not by
import.

Shipped:
- `internal/phishval` -- the 7-dimension outcome model (Delivery,
  Enforcement, Detection, UserInteraction, Response as independently
  verdicted dimensions; Evidence/Confidence as per-dimension fields on
  each `DimensionResult`, not separate top-level verdicts) + the
  independent per-dimension `Evaluate*` functions + composite `Evaluate`.
  Zero imports beyond stdlib.
- `internal/phishcatalog` -- the versioned PH-* scenario schema
  (`Scenario`, `Area`, `CoverageState`) + `ValidateCatalog` (structurally
  rejects a Coverage claim above `CoverageCatalogOnly` with no
  `MappedImplementation` -- phishing.txt's "catalog entry ≠ executable
  scenario" rule enforced in code, not just prose) + the seed catalog
  (PH-BEC-002 only; Phase 2 populates the rest).
- `internal/phishbridge` -- the one-way translation from
  `emailgwefficacy.EfficacyResult` into `phishval.Observation`. Proven
  end to end against PH-BEC-002 using emailgwefficacy's own real
  `SupplierPaymentDiversionExpectation` + `VerifyMailExpectation` +
  `NewFixtureMailEvidenceProvider` -- a known-good case (quarantined,
  detected, remediated) grades Pass on every dimension; a known-bad case
  (delivered uninspected, no detection/response evidence at all) grades
  Fail on Delivery/Enforcement and **NotTested** (never a fabricated
  Fail) on Detection/Response, preserving emailgwefficacy's own
  "absence of evidence is not proof of failure" discipline through the
  bridge.
- Zero changes to `emailgwefficacy`, `emailgwcampaign`, or `exercise` --
  confirmed via `git status` before commit. The lock stays intact.

Next: Phase 2 (email ingress and BEC integration) -- populate the rest of
areas A/B/C's catalog rows per §2's matrix.

## 8. Phase 2 status: DONE

Phase 2 added 26 more catalog entries (27 total with PH-BEC-002):

- **7 CoverageFixtureTested** wraps, each proven end to end (known-good
  Pass + known-bad Fail) through the SAME Phase 1 bridge with zero new
  bridge code: PH-AUTH-002 (SPF), PH-AUTH-003 (DKIM), PH-AUTH-004 (DMARC),
  PH-BEC-001 (executive impersonation), PH-URL-001 (known malicious URL),
  PH-URL-005 (time-of-click/URL-rewrite), PH-ATT-001 (generic malicious
  attachment -- EICAR, not literally HTML-specific, noted honestly).
  `internal/phishbridge/area_ab_test.go`'s table-driven test confirms
  `FromEmailGWEfficacyResult` generalizes across every
  `MailExpectation`-shaped scenario, not just PH-BEC-002.
- **5 explicit overlap decisions** (CoverageCatalogOnly, cross-referencing
  the ID that owns the real evidence, never duplicated):
  PH-AUTH-001→PH-AUTH-004, PH-AUTH-005→PH-BEC-001, PH-BEC-003/007→PH-BEC-002
  (deferred to Phase 4's variant engine), PH-EVA-001→PH-AUTH-008,
  PH-EVA-002→PH-AUTH-007, PH-EVA-005→PH-URL-005.
- **14 genuine, unbuilt gaps**, each named plainly rather than
  force-mapped: PH-AUTH-006/007/008/009/010, PH-BEC-004/005/006/008,
  PH-ATT-002/003, PH-ID-001 (real DB-backed capture exists in
  `exercise/tracker`, but no typed read-side accessor exists yet for an
  I/O-free bridge to consume -- a named plumbing gap, not a missing
  capability).

Zero changes to `emailgwefficacy`/`emailgwcampaign`/`exercise` again.

Next: Phase 3 (provider-specific validation).

## 9. Phase 3 status: DONE

Phase 3's acceptance gate names exactly two assertions: policy-exception
and impersonation, proven against a real adapter. Both land clean:

1. **Corrected a Phase 2 mapping error.** PH-AUTH-008 (trusted-sender
   exception abuse) was wrongly pointed at `EmailPolicyBaselineExpectation`
   (a config-drift shape, deferred). It actually has real, dispatchable
   coverage: `emailgwefficacy.AuthenticationExceptionScopeExpectation`
   (EG-009) tests exactly this -- a documented mail-flow exception
   bypassing inspection for a genuinely verified source vs. one that only
   spoofs the trigger condition. Re-pointed, proven known-good/known-bad
   through the existing bridge, no new code needed. PH-EVA-001's
   cross-reference corrected to match. PH-AUTH-009's limitations text was
   also corrected: `InboxRuleExpectation` (EG-007) does exist for external
   auto-forwarding, just as a different evidence shape (mailbox config
   state) -- it was wrongly described as "no scenario builder exists."
2. **Added PH-ATT-010** (post-delivery retroactive remediation), wrapping
   `PostDeliveryThreatResponseExpectation` (EG-008) -- a Response-only
   scenario (Delivery/Enforcement correctly grade NotApplicable, proven by
   its own test).
3. **Upgraded Coverage from fixture-tested to adapter-tested for all 10
   real wraps** (PH-BEC-002, PH-AUTH-002/003/004/008, PH-BEC-001,
   PH-URL-001/005, PH-ATT-001/010): `emailgwefficacy`'s own
   `TestEmailGWScenarioMaturity_RealRun_AllPreventionScenarios`/
   `_EG008Response` already run every one of their underlying EG-IDs
   through the real, httptest-backed `DefenderMailEvidenceProvider` --
   actual OAuth token exchange, HTTP request, and JSON parsing -- and
   classify them `MaturityVerifiedThroughExecution`. This is proof through
   the real adapter code path, explicitly never a live customer tenant
   (phishcatalog's own CoverageLiveValidated stays unclaimed).

Zero changes to `emailgwefficacy`/`emailgwcampaign`/`exercise` again --
Phase 3 only read their existing, already-passing test suite as evidence.

Next: Phase 4 (multi-stage campaigns and adversarial variants).

## 10. Phase 4 status: DONE

Phase 4's acceptance gate: "at least one chain spans email→URL→detection→
response using exercise/templates.go's existing orchestration mechanism
wrapped in PH-* IDs; variant matrix shares one scenario definition
without duplicating the implementation."

1. **`phishval.Chain`/`ChainStage`** -- an ordered, gated sequence of
   per-stage results sharing one RunID, answering phishing.txt
   capability #1's own acceptance bar ("identify the exact stage and
   control where the attack was stopped") via `Chain.StoppedAtStage()`.
   A blocked stage carries no Outcome, ever (mirrors
   `emailgwcampaign.StageBlockedByPrerequisite`'s "RunID is nil, always"
   guarantee one level down).
2. **`phishbridge.BuildCampaignChain`** replays `emailgwcampaign.CampaignTemplate`'s
   own real gate-condition logic (`GateCondition.PermittedVerdicts`) --
   no new orchestration engine, confirming my own Phase 0 prediction that
   this phase would be "a PH-* ID wrapper, not a new engine." A real bug
   surfaced and was fixed during TDD: the first draft derived a stage's
   *expected* outcome from its own *observed* result, making every stage
   trivially pass -- fixed to read the real declared
   `MailExpectation.ExpectedAction` the result already carries.
3. **Two chains proven end to end**, confirming the mechanism
   generalizes rather than being special-cased to one template:
   - `BECSupplierFraudTemplate` -- known-bad (identity-probe delivered →
     gate permits fraud-payload → caught downstream, `StoppedAtStage()`
     == "fraud-payload") and known-good (identity-probe blocked →
     fraud-payload and both derived stages `ChainStageBlocked`, never
     fabricated, `StoppedAtStage()` == "identity-probe").
   - `CredentialPhishingURLChainTemplate` -- the literal
     email→URL→detection→response chain phishing.txt's own acceptance
     text describes: a static lure missed at the email layer, caught by
     the independent click-time-rewrite layer.
4. **Variant matrix**: added `phishcatalog.Variant`/`VariantAxis` +
   `ValidateCatalog` checks (a variant's `BaseScenarioID` must resolve to
   its owning scenario; a variant ID can never also exist as a
   standalone `Scenario`). PH-BEC-003/PH-BEC-007, previously orphan
   `CoverageCatalogOnly` stubs, are now declared `VariantAxisNarrative`
   variants of PH-BEC-002 -- sharing its implementation per phishing.txt
   capability #3's own acceptance bar, rather than two disconnected IDs
   pointing at identical, unlinked evidence. Their narrative content
   still needs authoring before they are anything more than a declared
   variant -- not claimed otherwise.

Zero changes to `emailgwefficacy`/`emailgwcampaign`/`exercise` again.

Next: Phase 5 (identity and session attacks) -- expect the same
tenant-permission blocker the Azure Real Discovery Integration project
already hit; code-ready-pending-tenant-access is the honest ceiling, not
live-validated.
