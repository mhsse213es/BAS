# Detection Validation Pack — Sub-project 1 Design

**Status:** approved 2026-07-08. Implementing inline.

**Goal:** Give Audspect an *expected* detection baseline so it can perform gap
analysis — "control X was expected to detect this and did NOT" — on top of the
detection-measurement machinery that already exists (agent event collection →
`classifyDetection` → `DetectionScore` → Detection Validation report page).

**Positioning:** turns Audspect from "we run attacks" into "we validate whether
your security controls actually work." Detection ground-truth for on-host
controls (Defender / Windows-event-log EDRs) is auto-verified from the agent's
`ExecResult.Events`; off-host controls (SIEM/identity/cloud/email) are declared
now and become verifiable in later sub-projects without any schema change.

## Sub-project map (this spec = SP1 only)

- **SP1 (this doc):** schema + detection-profile layer + verification engine +
  gap scoring + report rendering + seed 4 flagships. Backward-compatible.
- **SP2 (later):** interactive manual-verification UI, evidence upload, DB
  persistence, audit export.
- **SP3 (later):** per-vendor API verifier connectors (Sentinel/Splunk/…).

The `Verifier` interface and stable `verification: automatic|manual|api` field
mean SP2/SP3 add verifiers without touching the engine or existing content.

---

## 1. Data model

### 1.1 ExpectedDetection (one expected control response)

Go: new file `orchestrator/internal/scenario/detection.go`.

```go
type ExpectedDetection struct {
    ID           string          `yaml:"id"            json:"id"`
    Provider     string          `yaml:"provider"      json:"provider"`     // registry key, e.g. microsoft_defender
    Type         string          `yaml:"type"          json:"type"`         // domain: endpoint|identity|network|cloud|email|dlp|siem
    Verification string          `yaml:"verification"  json:"verification"` // automatic|manual|api
    Confidence   string          `yaml:"confidence"    json:"confidence"`   // required|recommended|optional
    Evidence     ExpectedEvidence `yaml:"evidence,omitempty" json:"evidence,omitempty"`
    Finding      ExpectedFinding  `yaml:"finding,omitempty"  json:"finding,omitempty"`
}

type ExpectedEvidence struct {
    AlertID       string `yaml:"alertId,omitempty"       json:"alertId,omitempty"`
    Provider      string `yaml:"provider,omitempty"      json:"provider,omitempty"`
    Timestamp     string `yaml:"timestamp,omitempty"     json:"timestamp,omitempty"`
    EvidenceURI   string `yaml:"evidenceUri,omitempty"   json:"evidenceUri,omitempty"`
    ScreenshotURI string `yaml:"screenshotUri,omitempty" json:"screenshotUri,omitempty"`
    Notes         string `yaml:"notes,omitempty"         json:"notes,omitempty"`
}

type ExpectedFinding struct {
    Severity    string `yaml:"severity"    json:"severity"`    // Critical|High|Medium|Low
    Title       string `yaml:"title"       json:"title"`
    Remediation string `yaml:"remediation" json:"remediation"`
    Reference   string `yaml:"reference,omitempty" json:"reference,omitempty"`
}
```

### 1.2 Detection Profile (reusable, behavioral, versioned, inheritable)

Profiles are named by **behavior**, not ATT&CK ID (one behavior → many
techniques; one technique → different detections by implementation). Live at
`scenarios/detection-profiles/*.yaml`.

```yaml
profile: windows_lsass_access
version: 1
extends: [ windows_credential_access ]   # optional; child overrides parent by id
expected_detection:
  - id: defender_lsass_access
    provider: microsoft_defender
    type: endpoint
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "LSASS credential access was not detected"
      remediation: "Enable Defender ASR 'Block credential stealing from LSASS' + behavior monitoring."
      reference: "MITRE T1003.001"
```

Go:

```go
type DetectionProfile struct {
    Profile   string              `yaml:"profile"`
    Version   int                 `yaml:"version"`
    Extends   []string            `yaml:"extends,omitempty"`
    Expected  []ExpectedDetection `yaml:"expected_detection"`
    // Source/verification-of-signature handled by the loader; not persisted.
}
```

### 1.3 Step references

`Step` (in `types.go`) gains:

```go
DetectionProfiles  []string            `yaml:"detection_profiles,omitempty" json:"detectionProfiles,omitempty"`
ExpectedDetections []ExpectedDetection `yaml:"expected_detection,omitempty" json:"expectedDetections,omitempty"`
```

**Resolution** (at load, into a resolved list carried for reporting): for each
step, expand every referenced profile (recursively applying `extends`), then
merge the step's inline `expected_detection`. Merge key = `id`; inline and
more-derived profiles win. A step with neither keeps today's behavior exactly.

Records the resolved `{profileId: version}` set on the step so the run report
can state "Validated against `windows_lsass_access` v1" (auditability).

---

## 2. Provider Registry

New file `orchestrator/internal/scenario/providers.go`. No hardcoded vendor
`if`s anywhere else.

```go
type Provider struct {
    Key         string // microsoft_defender
    DisplayName string // Microsoft Defender
    Category    string // EDR|SIEM|DLP|AV|IDP|CASB
    DefaultDomain string // endpoint|siem|... (fallback if Type omitted)
    Verifier    string // automatic|manual|api  (default verification for this provider)
}

func LookupProvider(key string) (Provider, bool)
func RegisterProvider(p Provider)   // extensibility; seeded with a built-in table
```

Built-in seed table covers: microsoft_defender (EDR), crowdstrike (EDR),
trellix (EDR/DLP), sentinelone (EDR), sophos (EDR), microsoft_sentinel (SIEM),
splunk (SIEM), qradar (SIEM), elastic (SIEM), sigma (SIEM/ruleset). Category
drives verifier selection + the validation-matrix domain default.

---

## 3. Verification engine

New file `orchestrator/internal/scenario/verify.go`.

```go
type StepEvidence struct {
    Events   []string // ExecResult.Events (e.g. "1116:Microsoft-Windows-Windows Defender/Operational")
    Verdict  string   // exec verdict (pass|fail|blocked|...)
    Telemetry []string // step's expected telemetry (for completeness scoring)
}

type VerificationResult struct {
    ExpectedID   string
    Status       string // Detected|NotDetected|NotApplicable|Unknown|Pending
    Source       string // resolved provider display name / detail
    VerifiedBy   string // "automatic" | analyst id (SP2) | connector name (SP3)
    Timestamp    time.Time
    Evidence     ExpectedEvidence
}

type Verifier interface {
    Verify(exp ExpectedDetection, ev StepEvidence) VerificationResult
}
```

- **automaticVerifier** (SP1, real): for `Type == endpoint`, reuses
  `reporting.classifyDetection`-style event inspection (factor the shared logic
  into a small detect helper if needed) to decide Detected/NotDetected per
  provider. For domains it cannot see on-host → `Unknown`.
- **manualVerifier / apiVerifier** (SP1, stubs): return `Pending`.

Engine dispatch: pick the verifier by `exp.Verification` (falling back to the
provider's default). The engine is a pure function of (resolved expectations,
per-step evidence) → []VerificationResult. No I/O, fully unit-testable.

---

## 4. Scoring model

New file `orchestrator/internal/reporting/detection_validation.go`.

Confidence weights: `required = 1.0`, `recommended = 0.7`, `optional =
informational` (never in any denominator; surfaced only).

Metrics (per run and per domain):

- **Detection Coverage** = Σ(weight·detected) / Σ(weight) over
  **resolved + verifiable** required/recommended expectations. `Unknown` and
  `Pending` are excluded from the denominator.
- **Verification Completeness** = verified / expected (required+recommended).
  Reported alongside Coverage so high coverage on few-verified can't masquerade
  as success.
- **False Silence** — a required/recommended expectation with Status=NotDetected
  → emits the expectation's `finding` verbatim (report invents no text).
- **Unexpected Detection** — a provider alert with no matching expectation →
  severity **Info | Review | Warning**, default **Review** (noise / false
  positive / duplicate analytic signal), never scored negatively.
- **Telemetry Completeness** — fraction of a step's expected `telemetry:` EIDs
  present in `Events`.
- **Prevention Score** — unchanged (existing).
- **Per-domain Validation matrix** — Endpoint / Identity / Network / Cloud /
  Email / DLP / SIEM, each its own Coverage + Completeness, plus a weighted
  roll-up **Overall Validation**.

Existing `DetectionScore` retained for backward-compat; new metrics additive.

Report structs (added to `reporting/engine.go` or the new file):

```go
type DetectionValidationSection struct {
    HasData               bool
    Coverage              float64
    VerificationCompleteness float64
    Expected, Verified, Detected int
    ByDomain              []DomainValidationRow
    FalseSilence          []GapFinding
    UnexpectedDetections  []UnexpectedDetectionRow
    Profiles              []ProfileRef   // {name, version} for audit line
}
```

---

## 5. Loading, validation, signing

- **Profile loader** (new `LoadProfiles` in `internal/scenario`): walks
  `scenarios/detection-profiles/*.yaml`, verifies signature via the existing
  `integrity.VerifyScenarioFile` (builtin rule), parses, registers.
- **Scenario loader** (`engine.go` WalkDir): explicitly **skips** the
  `detection-profiles/` subdir so profiles aren't mis-parsed as scenarios.
- **Validation** (at load + as a build `validate` command that fails CI):
  duplicate expectation `id` within a resolved step, unknown provider (not in
  registry), unknown `verification`/`confidence`, missing required fields
  (`id`, `provider`, `finding.severity/title` on required-confidence),
  circular `extends`, duplicate profile names, `version < 1`. Invalid profiles
  are rejected loudly and not half-loaded.
- **Signing:** `build.ps1` already signs `scenarios/**/*.yaml` recursively, so
  profile files are signed with no build change.

---

## 6. Reporting

Extend the existing Detection Validation report page (`reporting/html.go`
section 18, plus PDF `pdf.go`):

- Per-step **Expected vs Observed** columns + status chip
  (Detected / Gap / Unverified / Unexpected).
- **Per-domain validation scorecard** (the matrix).
- **Gap Analysis** block: False Silence (expected platform + confidence +
  finding) and Unexpected Detections (with severity).
- Coverage **and** Verification Completeness shown together, never merged.
- Audit line: "Validated against <profile> v<version>, …".
- Backward-compat: runs of scenarios with no expectations render as today.

---

## 7. Seed content (4 flagships)

Behavioral profiles authored under `scenarios/detection-profiles/`, referenced
from the four flagship scenarios (each exercising a different domain mix):

- **apt29-kill-chain** — encoded PS, run-key, schtasks, DNS beacon (endpoint + siem).
- **volt-typhoon-lotl** — LOTL discovery, netsh portproxy, SAM theft, wevtutil (endpoint-heavy).
- **kerberoasting-ad-drill** — SPN/TGS/AS-REP/LDAP (identity/siem-heavy).
- **collection-staging-exfil** — archive, DNS/HTTP exfil, cloud egress (dlp/network-heavy).

Profiles (behavioral): `windows_powershell_encoded`, `windows_runkey_persistence`,
`windows_schtask_persistence`, `windows_dns_beacon`, `windows_lolbin_discovery`,
`windows_netsh_portproxy`, `windows_sam_theft`, `windows_log_recon`,
`windows_kerberoast`, `windows_asrep_roast`, `windows_ldap_enum`,
`windows_archive_creation`, `windows_dns_exfil`, `windows_http_exfil`,
`windows_cloud_egress`, plus base `windows_credential_access` for inheritance.

---

## 8. Testing

- `verify_test.go` — automatic verifier: event → Detected/NotDetected/Unknown per provider.
- `detection_profile_test.go` — resolution: profile expand, `extends` recursion,
  inline merge by id, circular-extends rejection, validation errors.
- `detection_validation_test.go` — scoring: confidence weights, coverage vs
  completeness, false-silence finding emission, unexpected-detection severity,
  per-domain roll-up, optional excluded.
- Golden report test — extended Detection Validation page renders expected-vs-
  actual + gap analysis for a seeded run.

---

## 9. Backward compatibility & non-goals

- Scenarios/steps without `detection_profiles`/`expected_detection` are
  unchanged in behavior and rendering.
- SP1 does **not** build the manual-verification UI, evidence upload, DB
  persistence, or API connectors. Off-host expectations render as
  "Pending verification" and are excluded from Coverage (counted in the
  Verification Completeness denominator).
