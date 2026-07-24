# DLP Validation Suite — Design (Phase B)

## Context

Phase A (`docs/superpowers/specs/2026-07-24-outcome-validation-framework-design.md`) built a generalized Expected-Outcome vs. Observed-Outcome comparator abstraction but registered zero new outcome families — it proved the extension point using only Detection Validation's existing binary model. This phase is the first real consumer: it registers a `"dlp"` outcome family and ships the first capability of a broader "Data Protection Validation" pillar (DLP first; Insider Risk, Cloud Storage, Email, Browser Upload, USB, Print, and Clipboard become later capabilities under the same pillar, not separate silos, per the user's own framing).

DLP policy responses are richer than "detected or not" — a control can Allow, Block, Warn-and-continue, Justify (require a business reason), Audit-only, Quarantine, Encrypt, or Redact. Different customers run different policy philosophies (a strict bank branch vs. an audit-only rollout), and the *same* attempted exfiltration scenario should be gradeable against whichever policy a customer actually runs — without rewriting scenario content per policy.

## Scope decisions for V1 (settled during brainstorming, not open questions)

- **Verification: local/agent-observed only.** No Trellix (or other) DLP product API connector in this phase — `internal/detectverify`'s existing connectors are themselves binary-shaped (`Detected|NotDetected`) and would need their own Phase-A-sized generalization first. That's an explicit future phase, not bundled here.
- **Data types: India/BFSI compliance set** — PAN, Aadhaar, SWIFT/IBAN, UPI/bank account number, credit card. Matches the existing scenario library's compliance focus (`upi-fraud-killchain.yaml`, `cscrf-mii-drill.yaml`).
- **Channels: agent-native, locally observable only** — USB-mounted-path copy, clipboard, print spool, password-protected ZIP staging, local-temp-equivalent write. No real cloud API upload (would require provisioning test credentials, out of scope) and no cloud-sync-folder write (deferred).
- **Deliverable shape: one multi-type synthetic file × 5 channels = 5 scenario steps.** A single fabricated file embeds all 5 data-type patterns together (a realistic-looking customer-records export), attempted through each channel independently. Keeps V1 lean while still proving DLP classification recognizes multiple regulated types in one document.
- **Expected outcome: `Block` for all 5 V1 steps.** These are classic exfiltration actions; a mature preventive DLP policy is expected to block them outright, and `Block` (alongside `Allow`) is the only outcome pair a local observer can honestly distinguish (see below). `Warn`/`Justify`/`Audit`/etc. stay in the registered catalog for later policy profiles once a product connector exists, but no V1 content declares them.
- **Platform: Windows only.** Matches every existing custom-step scenario's convention (`apt29-kill-chain.yaml` etc.) and the registered DLP providers (`trellix_dlp`, `microsoft_purview`) are both Windows-endpoint products.

## The core design principle: separate what can be *represented* from what can be *proven*

A local verifier that only sees "the file copy succeeded" cannot honestly conclude the policy was `Allow` — a Warn-and-continue or Audit-only policy would produce the identical local symptom (operation succeeds). Claiming otherwise overstates what was actually observed. So the local verifier never emits a member of the DLP outcome catalog directly. It emits a **primitive observation** — `OperationSucceeded | OperationBlocked | OperationUnknown` — a fact about what happened at the OS level, nothing more. A `Comparator` then judges that primitive against whatever richer outcome the profile expected. This keeps "what the framework can represent" (the full 8-value catalog) and "what a given verifier can prove" (in V1's case, only Block vs. Allow) as two genuinely separate concerns — exactly the shape Phase A's `Comparator` interface was built to support (`observedOutcome` was never required to be a member of the same catalog as `expectedOutcome`; Phase A's own `detectionComparator` already treats the empty-string sentinel as a value outside that catalog).

## Architecture

### 1. Register the `"dlp"` outcome catalog (`internal/scenario/outcome_catalog.go`)

Add one more `RegisterOutcomeCatalog` call to that file's existing `init()` (alongside the `"detection"` family Phase A already registered):

```go
RegisterOutcomeCatalog(OutcomeCatalog{
    Family:           "dlp",
    Values:           []string{"Allow", "Block", "Warn", "Justify", "Audit", "Quarantine", "Encrypt", "Redact"},
    ImplicitExpected: "Block",
})
```

No other change to that file. `ResolveOutcomeFamily`/`ResolveExpectedOutcome`/`ValidOutcome`/`familyKnown` all work unmodified — this is exactly the extension point Phase A built.

### 2. `StepEvidence` gains a `RawOutput` field (`internal/reporting/detection_validation.go`)

```go
type StepEvidence struct {
    // ...existing fields unchanged...
    RawOutput string // full step output text — needed by verifiers that parse a self-reported marker, e.g. dlpVerifier
}
```

`evidenceByTechnique` (same file) gains one line copying `r.RawOutput` into the built `StepEvidence`. Additive only — `automaticVerifier` never reads this field, so Detection Validation's behavior is unaffected.

### 3. Primitive observation vocabulary + `dlpComparator` (`internal/reporting/dlp.go`, new file)

```go
const (
    ObservationSucceeded string = "OperationSucceeded"
    ObservationBlocked   string = "OperationBlocked"
    ObservationUnknown   string = "OperationUnknown"
)

type dlpComparator struct{}

func (dlpComparator) Compare(expected, observed string) ComparisonResult {
    switch observed {
    case ObservationBlocked:
        if expected == "Block" {
            return Match
        }
        return Mismatch // a block occurred regardless of what softer policy was expected — informative either way
    case ObservationSucceeded:
        switch expected {
        case "Allow":
            return Match
        case "Block":
            return Mismatch
        default: // Warn/Justify/Audit/Quarantine/Encrypt/Redact — success alone can't confirm any of these fired
            return MissingEvidence
        }
    default: // ObservationUnknown, or anything unrecognized
        return MissingEvidence
    }
}

func init() {
    RegisterComparator("dlp", dlpComparator{})
}
```

This is the exact truth table agreed during brainstorming. The asymmetry is deliberate: an observed block is conclusive against *any* expectation (something clearly intervened, even if a softer policy was expected — that's real policy drift, not missing evidence), but an observed success is only conclusive against `Allow`/`Block` — every softer expected outcome stays honestly `MissingEvidence` → `Unknown`.

### 4. `dlpVerifier` (`internal/reporting/dlp.go`, same new file)

```go
var dlpMarkerRe = regexp.MustCompile(`(?m)^DLP_OBSERVATION:\s*(\S+)$`)

// dlpVerifier resolves DLP expectations from a step's self-reported outcome
// marker — the trusted, first-party script itself does the post-condition
// check (did the file land on the USB path, does Get-Clipboard now match,
// etc.) and prints a single deterministic line; this verifier only parses it.
// It never re-derives observations from vendor-specific error text — that
// would be exactly the fragile heuristic classifySkipReason's own doc comment
// warns against for third-party output.
type dlpVerifier struct{}

func (dlpVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
    r := baseResult(exp, ev, "automatic")
    r.ExpectedOutcome = scenario.ResolveExpectedOutcome(exp)

    observed := ObservationUnknown
    if m := dlpMarkerRe.FindStringSubmatch(ev.RawOutput); m != nil {
        switch m[1] {
        case ObservationSucceeded, ObservationBlocked:
            observed = m[1]
        }
    }
    r.ObservedOutcome = observed
    r.Comparison = comparatorFor("dlp").Compare(r.ExpectedOutcome, r.ObservedOutcome)
    r.Status = collapseToStatus(r.Comparison)
    return r
}
```

### 5. Dispatch: one new branch in `verifyExpectation` (`internal/reporting/detection_validation.go`)

```go
func verifyExpectation(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
    switch scenario.ResolveVerification(exp) {
    case scenario.VerificationAutomatic:
        if scenario.ResolveOutcomeFamily(exp) == "dlp" {
            return dlpVerifier{}.Verify(exp, ev)
        }
        return automaticVerifier{}.Verify(exp, ev)
    case scenario.VerificationAPI:
        return apiVerifier{}.Verify(exp, ev)
    default: // manual
        return manualVerifier{}.Verify(exp, ev)
    }
}
```

`automaticVerifier` itself is untouched — this only changes which verifier the `automatic` case routes to, keyed on `OutcomeFamily`, the axis Phase A built specifically for "which vocabulary/comparison semantics apply." Every existing `"detection"`-family expectation (the only family that existed before this phase) keeps routing to `automaticVerifier` exactly as before — this branch is additive, not a behavior change for anything that predates it.

### 6. Content: scenario + detection profile

New builtin scenario `scenarios/dlp-exfiltration-validation.yaml`: `executable: true`, `supported_os: [windows]`, 5 custom steps (no ART/Caldera framework — `technique_id` + `executor: powershell` + `command:`, the same pattern `apt29-kill-chain.yaml` already uses), one per channel:

1. USB-mounted-path copy (`T1052.001` — Exfiltration over USB)
2. Clipboard write (`T1115` — Clipboard Data)
3. Print spool send (`T1052` — Exfiltration Over Physical Medium, parent technique; ATT&CK has no dedicated printing sub-technique, and T1052 is the parent T1052.001 already uses for USB, so both physical-exfiltration steps stay under the same parent/child pair rather than inventing a non-ATT&CK ID)
4. Password-protected ZIP staging (`T1560.001` — Archive via Utility)
5. Local-temp-equivalent write (`T1074.001` — Local Data Staging)

Each step's script: embeds the synthetic multi-type file inline (`[BAS-SIM]`-tagged, fabricated PAN/Aadhaar/SWIFT/UPI/credit-card patterns — never real data), attempts the channel operation, does its own post-condition check, prints exactly one `DLP_OBSERVATION: <token>` line, and cleans up whatever it created (matching every existing scenario's self-cleaning convention).

New detection profile(s) under `scenarios/detection-profiles/` (naming and count — one profile with 5 expected_detection entries, or 5 small per-channel profiles — decided during plan-writing, following whichever existing profile grouped multiple related expectations, e.g. `windows_credential_access.yaml`'s pattern of one profile per behavioral family). Each `expected_detection` entry:

```yaml
- id: dlp-usb-block
  provider: trellix_dlp
  type: dlp
  outcome_family: dlp
  expected_outcome: Block
  verification: automatic
  confidence: required
  finding:
    severity: High
    title: "DLP did not block USB exfiltration of regulated data"
    remediation: >-
      Confirm the DLP policy covers removable-media file-copy events for
      PAN/Aadhaar/SWIFT/UPI/credit-card patterns and is set to Block, not
      Audit-only, on this endpoint group.
    reference: "MITRE ATT&CK T1052.001 — Exfiltration Over USB"
```

`verification: automatic` is set explicitly on every entry — `trellix_dlp`'s provider-registry default (`VerificationManual`) stays unchanged, since off-host/product-side verification is still the correct *default* assumption; V1's profiles are the ones opting into local observation, not the framework's baseline.

## Non-goals (explicitly deferred)

- Any DLP product API connector (Trellix or otherwise) — requires generalizing `internal/detectverify`'s binary `Verdict` first, a separate future phase.
- `Warn`/`Justify`/`Audit`/`Quarantine`/`Encrypt`/`Redact` expected-outcome content — the catalog supports them; no V1 scenario declares them, since a local verifier can't honestly confirm them.
- Non-Windows platforms.
- Data types beyond the 5 India/BFSI-compliance ones (source code, IP, HR records, healthcare data, custom classifiers).
- Channels beyond the 5 agent-native ones (real cloud API upload, cloud-sync-folder write, browser upload, Outlook/Teams/Slack, SMB shares, RDP clipboard, screenshot/OCR).
- `microsoft_purview` as an authored alternative provider — V1 content targets `trellix_dlp` only; a Purview variant is a straightforward content-only fast-follow (register a second profile/provider pairing, no engine change) once wanted.
- Any change to `internal/detectverify` itself.

## Testing approach

1. **`dlpComparator.Compare`** — table-driven, covering the full truth table above (all combinations of the 3 expected-outcome buckets × 3 observed primitives), plus an unrecognized/garbage `observed` string → `MissingEvidence`.
2. **`dlpVerifier.Verify`** — covers: marker present and `OperationBlocked` with `expected=Block` → `Match`/`StatusDetected`; marker present and `OperationSucceeded` with `expected=Block` → `Mismatch`/`StatusNotDetected`; no marker in output at all → `MissingEvidence`/`StatusUnknown`; marker present but with an unrecognized token → `MissingEvidence`/`StatusUnknown` (never silently treated as a known primitive); multi-line output where the marker isn't the last line (confirms the regex anchors correctly regardless of surrounding output).
3. **Dispatch test** — an expectation with `outcome_family: dlp` + `verification: automatic` routes to `dlpVerifier`, not `automaticVerifier`; an expectation with no `outcome_family` set (the `"detection"` default) continues routing to `automaticVerifier` unchanged — the regression proof that this dispatch change doesn't alter Phase A's behavior.
4. **Full existing `internal/reporting` and `internal/scenario` suites** — including Phase A's golden-output test — must still pass with zero changes, the same non-negotiable bar Phase A established.
5. **Scenario content validation** — `scenario.ParseYAML` against the new scenario file and detection profile(s), following the same pattern `TestParseYAML_UbuntuHardeningValidation` established. Each embedded PowerShell block gets a manual sanity pass with PowerShell's own parser (`[System.Management.Automation.Language.Parser]::ParseInput()`) before committing — there is no automated Go-side PowerShell AST tool in this repo today, so this is a manual authoring-time check, not a `go test` target.
6. Signing: new builtin scenario + profile files must be signed via the existing `scripts/signer.go sign` pipeline before the engine will load them (unsigned builtin content is refused, per `TestLoad_UnsignedBuiltinRefused`).
