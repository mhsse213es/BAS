# Email Gateway Mastery Phase 3: First Real End-to-End Vertical — Implementation Specification

**Parent spec:** `docs/superpowers/specs/2026-10-15-emailgw-mastery-architecture-design.md` (master architecture, §3 Phase 3, §2.3's six live-provider conditions). This document implements that phase's roadmap-level definition at file/interface level. It does not re-derive architecture already locked there — see that document for the package boundary, the 5-state verdict naming, and the M365 Defender for Office 365 provider decision this spec implements.

**Locked decisions carried in from the master spec (binding, not re-litigated here):**
- First live provider is Microsoft 365 Defender for Office 365, chosen for existing repo infrastructure plus genuine self-serve developer-tenant access (§2.3).
- `orchestrator/internal/emailgwefficacy` (Phase 2, shipped `2bbf9903`) already has `MailExpectation`, `EnforcementEvidence`, `DetectionEvidence`, `OriginDeliveryObservation`, `EmailGWVerdict`, `MailEvidenceProvider`, `VerifyMailExpectation` — this phase adds scenario content and a real adapter; it does not change any Phase 2 type's shape.
- Synthetic, inert payloads only (§2.3 condition #4) — every test message uses fabricated identities and non-malicious fixtures, never a real spoofed brand or a real malicious attachment.
- Mock/live parity (§2.3 condition #5) — every live scenario has a fixture-backed parallel; the regression suite never requires live tenant credentials.

## Scope Refinement Since the Master Spec: the Phase 3 Blocking Unknown

The master spec's §2.3 condition #2 requires API/tenant verification "before any code is written" against the real APIs — this section does that verification work and reports what it found, rather than assuming the architecture spec's own illustrative wording.

**What's already confirmed working (reused, not rebuilt):** `orchestrator/internal/vendors/defender.Client.QueryAlerts` calls Microsoft Graph's `security/alerts_v2` endpoint over a client-credentials OAuth token (`internal/platform/msauth.EntraTokenSource`, scope `https://graph.microsoft.com/.default`). This is a real, working REST path for **detection evidence** — anti-phish/malware/impersonation alerts Defender for Office 365 raises are Graph security alerts like any other Defender alert, so `DetectionEvidenceFor` can extend this exact client with a mail-specific alert filter, mirroring `internal/detectverify/defenderxdr.go`'s own host-filtering precedent (filter by sender/recipient/subject-correlation instead of `DeviceDNSName`).

**What is NOT yet confirmed: enforcement evidence and policy configuration.** Three evidence/configuration needs have no verified REST path today:
1. **Was this specific test message delivered, quarantined, or rejected** (message-trace / quarantine-release outcome) — the industry-standard mechanism is Exchange Online's `Get-MessageTrace` / `Get-QuarantineMessage`, which are PowerShell cmdlets (`ExchangeOnlineManagement` module), not a plain Microsoft Graph REST call.
2. **What does the Safe Links / Safe Attachments / anti-phishing policy actually say** (the declared-expectation side, for building realistic `MailExpectation` fixtures against the tenant's real configuration) — likewise exposed through Exchange Online PowerShell cmdlets (`Get-SafeLinksPolicy`, `Get-SafeAttachmentPolicy`, `Get-AntiPhishPolicy`), not a documented Graph REST endpoint as of this writing.
3. **Authentication for #1/#2, if PowerShell is the only path, is certificate-based app-only auth** (`Connect-ExchangeOnline -CertificateThumbprint ... -AppId ...`), a different credential shape than the client-secret `EntraTokenSource` every existing Microsoft-family connector in this codebase already uses — and a PowerShell execution dependency, which is a new kind of external dependency for this codebase's connectors (every existing one is a plain `net/http` call).

A second candidate exists for #1 specifically — the **Office 365 Management Activity API** (`manage.office.com`, Exchange workload audit events), which is a REST API reachable via OAuth2 client-credentials, the same shape every other connector here already uses. Whether it carries the specific quarantine/message-trace granularity this initiative needs is unconfirmed.

**This is treated exactly as WebGW Mastery treated its own Cloudflare Log Explorer/Logpush discovery (see `docs/webgw-mastery-qa-log.md` item #2): an open question to resolve empirically against a real, provisioned tenant, not an assumption this document locks.** A new tracking document, `docs/emailgw-mastery-qa-log.md`, is created alongside this spec (§5) to hold this and future blockers, mirroring that precedent.

**Tenant provisioning status: unconfirmed, separate from the open API question.** `project_azure_real_discovery_integration` (prior-session memory) shows an existing Entra tenant (`ed059a30-...`) already in use for unrelated Azure resource-discovery work, itself blocked there on a missing Azure subscription and a missing admin role. Whether that same tenant carries (or could be licensed with) Defender for Office 365 is a separate, unverified question — not assumed resolved by anything already recorded about that tenant's Azure-side blockers.

**Consequence — Phase 3 splits exactly as WebGW Mastery's Phase 2 split (architecture spec §3, Phase 3's own amendment language):**
- **Phase 3a (this spec's buildable scope, proceeds now):** scenario content, the authorized test-sender extension, and the detection-evidence adapter extension (the one leg already confirmed reachable) — all fixture-backed where live access is unavailable, matching Phase 2's own discipline.
- **Phase 3b (blocked, scaffolded only):** the enforcement-evidence/policy-configuration adapter. Blocked on (1) a provisioned tenant with Defender for Office 365 licensing, (2) hands-on confirmation of which API path (PowerShell cert-auth, or the Management Activity API, or something else) actually carries the needed data on that tenant, and (3) if PowerShell is required, a credential/execution model this codebase doesn't have yet. Not reattempted until the user provisions access or the API question resolves — tracked as QA log item #1.

## 1. Package Layout

No new top-level package. All changes extend `orchestrator/internal/emailgwefficacy` (Phase 2) and `orchestrator/internal/vendors/defender` (existing).

| File | Responsibility |
|---|---|
| `orchestrator/internal/emailgwefficacy/scenarios.go` | Phase 3a. Scenario builders: `SPFAlignmentExpectation`/`DKIMAlignmentExpectation`/`DMARCPolicyExpectation` (area A, one known-good + one known-bad each) and one phishing/attachment scenario (`CredentialHarvestingURLExpectation`, area B — a synthetic, non-functional lookalike-login-page URL, never a real credential-capture page). Pure data builders, no I/O — same shape as `webgwefficacy`'s own per-domain scenario constants. |
| `orchestrator/internal/emailgwefficacy/scenarios_test.go` | End-to-end fixture-backed proof for each scenario above through `VerifyMailExpectation`, per Phase 2's own test pattern. |
| `orchestrator/internal/exercise/smtp_spoofing.go` (new file, existing package) | `SpoofableSMTPInjector` — see §2. Does not modify `smtp.go`'s existing `SMTPInjector`, so Phase 4+ attack-vector work never risks colliding with unrelated phishing-simulation feature changes to that type. |
| `orchestrator/internal/vendors/defender/client.go` (extended) | `QueryMailAlerts(ctx, start, end, correlationHint string) ([]Alert, error)` — Phase 3a. Thin wrapper around the existing `queryRaw`/`QueryAlerts` path; no new OAuth scope, no new host. |
| `orchestrator/internal/emailgwefficacy/providers.go` (extended) | `DefenderDetectionProvider` — Phase 3a. Implements `DetectionEvidenceFor` only (not the full `MailEvidenceProvider`) by calling `defender.Client.QueryMailAlerts` and mapping Graph alerts to `DetectionEvidence`. `EnforcementEvidenceFor` is Phase 3b's deliverable — not stubbed with a fake success path; a caller needing a full `MailEvidenceProvider` composes this with a fixture enforcement provider until Phase 3b ships (§4). |
| `docs/emailgw-mastery-qa-log.md` (new) | Tracks this phase's open blocker (§Scope Refinement above) and future ones, mirroring `docs/webgw-mastery-qa-log.md`'s format exactly. |

## 2. Authorized Test Sender: `SpoofableSMTPInjector`

```go
package exercise

// SpoofableSMTPInjector sends one authorized test message with
// explicit control over envelope-from, HELO domain, and destination
// (direct-to-MX or via a configured relay) -- the control
// SMTPInjector deliberately doesn't expose, because its own job
// (deliver a realistic phishing-simulation email through whatever
// relay the customer's exercise already uses) never needed to
// construct a deliberately SPF-failing or DKIM-misaligned message.
// EmailGW Mastery's sender-identity scenarios (area A) need exactly
// that control, so this is a new, small type rather than a change to
// SMTPInjector's existing call sites or behavior.
type SpoofableSMTPInjector struct {
    EnvelopeFrom string // e.g. "ceo@spoofed-lookalike.test" -- never a real customer or partner domain
    HELODomain   string
    TargetMX     string // direct delivery to the gateway under test; empty uses RelayHost instead
    RelayHost    string
    httpClient   *http.Client // unused; placeholder removed if dial-only, see implementation
}

// SendTestMessage delivers one message and returns the
// OriginDeliveryObservation's sender-side leg (SenderPayloadHash,
// Timestamp) -- it never claims to know the receiving system's
// outcome; that is the evidence provider's job (observation-model
// item 3's two independent legs, emailGW.txt §3).
func (s *SpoofableSMTPInjector) SendTestMessage(ctx context.Context, msg TestMessage) (OriginLeg, error)
```

**Why a new type, not an `SMTPInjector` extension (flag for review):** `SMTPInjector.deliver` always uses `i.cfg.Host` (a configured relay) and never exposes envelope-from independent of `cfg.FromAddr`. Threading spoofing controls through its existing fields risks a future phishing-simulation change (a different feature, same package) silently affecting EmailGW Mastery's sender-identity tests, or vice versa. A new, narrow type avoids that coupling — this mirrors the master spec's own "borrowed pattern, not shared type" discipline (§2.2) applied one level down, to two features inside the same package rather than two packages.

## 3. Detection Evidence Adapter: `DefenderDetectionProvider`

```go
package emailgwefficacy

// DefenderDetectionProvider implements the DetectionEvidenceFor half
// of MailEvidenceProvider against a real Microsoft Defender for
// Office 365 tenant via Graph security alerts. It does not implement
// EnforcementEvidenceFor -- Phase 3b's unresolved blocker (§Scope
// Refinement) -- so it is never passed anywhere a full
// MailEvidenceProvider is required without being paired with a
// separate enforcement provider (fixture, until Phase 3b).
type DefenderDetectionProvider struct {
    client *defender.Client
}

func NewDefenderDetectionProvider(cfg defender.Config) *DefenderDetectionProvider

// DetectionEvidenceFor queries Graph security alerts in window and
// maps each alert whose subject/sender/recipient correlates to msg
// into a DetectionEvidence record with Source: SourceLive and
// Provenance: {Kind: ProvenanceObserved, Confidence: ConfidenceHigh}.
// An alert that exists but can't be correlated to msg at all is
// never included -- silently over-matching here would be exactly the
// "missing telemetry read as something it isn't" failure mode
// emailGW.txt §3 rules out, applied to the opposite direction (a
// false correlation instead of a missing one).
func (p *DefenderDetectionProvider) DetectionEvidenceFor(msg MessageRef, window TimeWindow) ([]DetectionEvidence, error)
```

**Correlation caveat, stated explicitly so it is never overclaimed later:** Graph security alerts for email threats carry subject/sender/recipient metadata, but the exact field names and whether a specific synthetic test message reliably produces a correlatable alert at all is itself unverified against a real tenant — this is Phase 3a's own first thing to confirm once any tenant access exists, independent of Phase 3b's enforcement-evidence blocker. If correlation turns out unreliable, `DetectionEvidenceFor` returns an empty slice rather than a best-guess match, and `VerifyMailExpectation`'s existing Phase 2 behavior (empty evidence → `Inconclusive`, never `ConfirmedFailure`) already handles that correctly with no further code change.

## 4. What Ships Without Live Credentials

Everything in §1-3 except the constructor's actual Graph API call: `DefenderDetectionProvider`'s request-building and alert-to-`DetectionEvidence` mapping proven against `httptest` servers returning Graph's documented `alerts_v2` response shape (the exact same proof style `CloudflareGatewayPolicyProvider` used while blocked on Cloudflare account access — `httptest`, not a live call, until credentials exist). `NewDefenderDetectionProvider` is credential-gated the same way `defender.New` already is; the one test that would call the real Graph API skips, not fails, when tenant env vars are unset.

`SpoofableSMTPInjector` needs no live M365 tenant at all to build and test — it only needs an SMTP endpoint to dial, which can be a local test listener (mirroring how `orchestrator/internal/smtpsink` is already used elsewhere in this codebase for exactly this purpose, reused here only as a test fixture, never as this phase's production code path).

## 5. `docs/emailgw-mastery-qa-log.md`

New file, same structure as `docs/webgw-mastery-qa-log.md`. First entry at creation:

> **1. M365 Defender enforcement-evidence/policy-configuration API path — open, unverified**
> Status: Open, blocked on tenant access and API-path research, not yet an engineering gap with a known fix.
> What's needed: a way to read (a) Safe Links/Safe Attachments/anti-phish policy configuration and (b) per-message delivery/quarantine outcome, for a real M365 Defender for Office 365 tenant.
> What's confirmed: detection evidence (Graph security alerts) has a working REST path, reusing `internal/vendors/defender.Client`. Policy configuration and message-trace/quarantine outcome have no confirmed REST path — the industry-standard mechanism (Exchange Online PowerShell, `Get-SafeLinksPolicy`/`Get-MessageTrace`/`Get-QuarantineMessage`) requires certificate-based app-only auth and a PowerShell execution dependency, neither of which exists in this codebase today. The Office 365 Management Activity API is an unverified alternative with the right auth shape (REST, client-credentials) but unconfirmed data granularity.
> Resolution path: once a tenant with Defender for Office 365 licensing is available, hands-on-verify which path (if any) exposes the needed data without PowerShell; if PowerShell turns out required, design its credential/execution model as its own small decision before writing adapter code against it.

## 6. Exit Criteria

**Phase 3a (this spec, buildable now):**
- At least one SPF/DKIM/DMARC-alignment scenario (known-good plus known-bad) and the credential-harvesting-URL scenario execute end-to-end through `VerifyMailExpectation` against `FixtureMailEvidenceProvider`, exactly as Phase 2's own pattern.
- `DefenderDetectionProvider`'s request-building/response-mapping is proven against `httptest`, with its one real-API test skipping (not failing) without tenant credentials.
- `SpoofableSMTPInjector` delivers a test message to a local test listener with a deliberately misaligned envelope-from, proving the sender-identity control Phase 3a scenarios depend on.

**Phase 3b (blocked, not claimed met until it actually ships):**
- At least one SPF/DKIM/DMARC scenario and the credential-harvesting scenario execute against the real M365 Defender adapter end-to-end (both enforcement and detection legs), producing an `EfficacyResult` with evidence tagged `SourceLive` on both `Enforcement` and `Detection`. Not reattempted until QA log item #1 resolves.

## 7. Explicit Exclusions (this phase)

- `orchestrator/internal/exercise/smtp.go`'s existing `SMTPInjector` is not modified (§2).
- `orchestrator/internal/smtpsink` is referenced only as a local test fixture, never as this phase's production delivery or evidence path (§4, consistent with the architecture spec's own exclusion of modifying that package).
- No PowerShell execution dependency, certificate-based auth model, or Exchange Online Management module integration is added in this phase — that design question is deferred to Phase 3b, to be scoped only once the API-path question (§Scope Refinement, QA log item #1) actually resolves.
