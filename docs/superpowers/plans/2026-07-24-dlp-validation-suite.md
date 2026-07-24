# DLP Validation Suite (Phase B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Register the first real outcome family ("dlp") on the Outcome Validation Framework (Phase A), ship a local-observation-only DLP verifier that never claims more than a primitive OS-level fact proves, and author the first Data Protection Validation scenario content: 5 exfiltration-channel steps testing whether DLP blocks a synthetic multi-type sensitive file.

**Architecture:** Three small, additive Go changes (outcome catalog registration, a new `dlpComparator`/`dlpVerifier` pair in a new file, one new dispatch branch keyed on `OutcomeFamily`) plus one new builtin scenario and one new detection profile. `automaticVerifier` and every `"detection"`-family code path from Phase A stay untouched.

**Tech Stack:** Go (existing orchestrator backend), PowerShell 5.1 (Windows-native cmdlets only, no external tooling), no new Go dependencies, no database migration.

## Global Constraints

- Zero database schema changes.
- `automaticVerifier`, `detectionComparator`, and every Phase A file/behavior stay unmodified — this phase is purely additive.
- `Verifier` and `Comparator` interface signatures (both defined in Phase A) must not change.
- The `dlpComparator`/`dlpVerifier` never claim `Warn`/`Justify`/`Audit`/`Quarantine`/`Encrypt`/`Redact` were observed — only `Block` vs `Allow` are locally provable; everything else resolves to `MissingEvidence`.
- Every existing test in `internal/reporting` and `internal/scenario` — including Phase A's `TestBuildDetectionValidationGoldenOutput` — must pass with **zero changes to any expected value**.
- All PowerShell content: self-cleaning, `[BAS-SIM-DLP-*]`-tagged, fabricated data only (no real PAN/Aadhaar/SWIFT/UPI/credit-card values), Windows-native cmdlets only (no bundled/external tooling assumed present).
- New builtin scenario + detection profile files must be signed (`go run scripts/signer.go sign private_key.pem <path>`, run from `orchestrator/`) before the engine will load them.

---

### Task 1: Register the `"dlp"` outcome catalog

**Files:**
- Modify: `orchestrator/internal/scenario/outcome_catalog.go` (the existing `init()`, lines ~69-75)
- Test: `orchestrator/internal/scenario/outcome_catalog_test.go` (extend)

**Interfaces:**
- Consumes: nothing new — reuses Phase A's `RegisterOutcomeCatalog`/`ValidOutcome`/`familyKnown`/`ResolveExpectedOutcome` exactly as they exist today.
- Produces: the `"dlp"` family becomes queryable via those same Phase A functions — `ValidOutcome("dlp", "Block")` etc. Nothing else in this task is new surface area.

- [ ] **Step 1: Write the failing test**

In `orchestrator/internal/scenario/outcome_catalog_test.go`, add:

```go
func TestDLPOutcomeCatalogRegistered(t *testing.T) {
	for _, v := range []string{"Allow", "Block", "Warn", "Justify", "Audit", "Quarantine", "Encrypt", "Redact"} {
		if !ValidOutcome("dlp", v) {
			t.Errorf("dlp catalog missing value %q", v)
		}
	}
	if ValidOutcome("dlp", "NotARealValue") {
		t.Error("dlp catalog should not validate an unregistered value")
	}
	if !familyKnown("dlp") {
		t.Error("dlp family should be known once registered")
	}
	if got := ResolveExpectedOutcome(ExpectedDetection{OutcomeFamily: "dlp"}); got != "Block" {
		t.Errorf("dlp family's implicit expected outcome: got %q want Block", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/scenario/... -run TestDLPOutcomeCatalogRegistered -v`
Expected: FAIL — `ValidOutcome("dlp", ...)` returns false for every value since the family isn't registered yet.

- [ ] **Step 3: Register the `"dlp"` catalog**

In `orchestrator/internal/scenario/outcome_catalog.go`, find the existing `init()` function:

```go
func init() {
	RegisterOutcomeCatalog(OutcomeCatalog{
		Family:           "detection",
		Values:           []string{"Detected", "NotDetected"},
		ImplicitExpected: "Detected",
	})
}
```

Replace it with:

```go
func init() {
	RegisterOutcomeCatalog(OutcomeCatalog{
		Family:           "detection",
		Values:           []string{"Detected", "NotDetected"},
		ImplicitExpected: "Detected",
	})
	// "dlp" — Phase B (Data Protection Validation, DLP capability). The full
	// catalog is richer than any current verifier can prove: only Block/Allow
	// are locally observable (see internal/reporting/dlp.go's dlpComparator).
	// Warn/Justify/Audit/Quarantine/Encrypt/Redact exist so a future DLP
	// product connector can populate profiles that declare them, without a
	// catalog change.
	RegisterOutcomeCatalog(OutcomeCatalog{
		Family:           "dlp",
		Values:           []string{"Allow", "Block", "Warn", "Justify", "Audit", "Quarantine", "Encrypt", "Redact"},
		ImplicitExpected: "Block",
	})
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/scenario/... -run TestDLPOutcomeCatalogRegistered -v`
Expected: PASS.

- [ ] **Step 5: Run the full scenario package test suite**

Run: `go test ./internal/scenario/... -v -count=1`
Expected: PASS, every test including the new one and every pre-existing test (in particular `TestResolveOutcomeFamily`/`TestResolveExpectedOutcome`/`TestValidOutcome`/`TestRegisterOutcomeCatalog`/`TestFamilyKnown` from Phase A) unchanged.

- [ ] **Step 6: Build check**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/scenario/outcome_catalog.go orchestrator/internal/scenario/outcome_catalog_test.go
git commit -m "feat(scenario): register dlp outcome catalog (Phase B) — Allow/Block/Warn/Justify/Audit/Quarantine/Encrypt/Redact"
```

---

### Task 2: `dlpComparator` — the local-observation truth table

**Files:**
- Create: `orchestrator/internal/reporting/dlp.go`
- Test: `orchestrator/internal/reporting/dlp_test.go` (new)

**Interfaces:**
- Consumes: Phase A's `ComparisonResult`/`Match`/`Mismatch`/`MissingEvidence`/`Comparator`/`RegisterComparator`/`comparatorFor` — all exist unchanged in `internal/reporting/outcome.go`.
- Produces (for Task 3 to consume):
  - `ObservationSucceeded`, `ObservationBlocked`, `ObservationUnknown` string constants.
  - `dlpComparator` (unexported type implementing `Comparator`), registered under family `"dlp"` via `init()`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/reporting/dlp_test.go`:

```go
package reporting

import "testing"

func TestDLPComparator(t *testing.T) {
	c := dlpComparator{}
	cases := []struct {
		name, expected, observed string
		want                     ComparisonResult
	}{
		{"expect Block, observe Blocked", "Block", ObservationBlocked, Match},
		{"expect Block, observe Succeeded", "Block", ObservationSucceeded, Mismatch},
		{"expect Block, observe Unknown", "Block", ObservationUnknown, MissingEvidence},
		{"expect Allow, observe Succeeded", "Allow", ObservationSucceeded, Match},
		{"expect Allow, observe Blocked", "Allow", ObservationBlocked, Mismatch},
		{"expect Allow, observe Unknown", "Allow", ObservationUnknown, MissingEvidence},
		{"expect Warn, observe Blocked", "Warn", ObservationBlocked, Mismatch},
		{"expect Warn, observe Succeeded", "Warn", ObservationSucceeded, MissingEvidence},
		{"expect Warn, observe Unknown", "Warn", ObservationUnknown, MissingEvidence},
		{"expect Justify, observe Succeeded", "Justify", ObservationSucceeded, MissingEvidence},
		{"expect Audit, observe Succeeded", "Audit", ObservationSucceeded, MissingEvidence},
		{"expect Quarantine, observe Blocked", "Quarantine", ObservationBlocked, Mismatch},
		{"garbage observed value", "Block", "not-a-real-token", MissingEvidence},
	}
	for _, c2 := range cases {
		t.Run(c2.name, func(t *testing.T) {
			if got := c.Compare(c2.expected, c2.observed); got != c2.want {
				t.Errorf("Compare(%q,%q) = %v want %v", c2.expected, c2.observed, got, c2.want)
			}
		})
	}
}

func TestDLPComparatorRegistered(t *testing.T) {
	if _, ok := comparatorFor("dlp").(dlpComparator); !ok {
		t.Error("comparatorFor(\"dlp\") should return the registered dlpComparator")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/reporting/... -run "TestDLPComparator|TestDLPComparatorRegistered" -v`
Expected: FAIL — `dlpComparator`, `ObservationBlocked`, `ObservationSucceeded`, `ObservationUnknown` undefined.

- [ ] **Step 3: Create `orchestrator/internal/reporting/dlp.go`**

```go
package reporting

// DLP Validation Suite — Phase B, the first real consumer of the Outcome
// Validation Framework (Phase A). Registers the "dlp" outcome family's
// comparator and a local-observation verifier that never claims more than an
// OS-level fact proves.
//
// A local script can only observe whether the file operation it attempted
// (USB copy, clipboard write, print, archive, local staging) succeeded or was
// prevented — a primitive fact, not a policy verdict. A Warn-and-continue
// policy produces the identical local symptom as no policy at all (the
// operation succeeds either way), so a local observer that concluded
// "Allow" from a bare success would be claiming evidence it doesn't have.
// dlpComparator keeps that distinction explicit: it compares the DLP outcome
// catalog's richer vocabulary (Allow/Block/Warn/Justify/Audit/Quarantine/
// Encrypt/Redact) against one of three primitive observations, not against
// itself.

// Primitive observations a local verifier can honestly report.
const (
	ObservationSucceeded = "OperationSucceeded"
	ObservationBlocked   = "OperationBlocked"
	ObservationUnknown   = "OperationUnknown"
)

// dlpComparator is the "dlp" family's Comparator. The asymmetry is
// deliberate: an observed block is informative regardless of what was
// expected — something clearly intervened, which is real policy drift even
// against a softer expected outcome, not missing evidence. An observed
// success is only conclusive against Allow/Block; every softer expected
// outcome (Warn/Justify/Audit/Quarantine/Encrypt/Redact) stays honestly
// MissingEvidence, since success alone can't confirm which of those fired.
type dlpComparator struct{}

func (dlpComparator) Compare(expected, observed string) ComparisonResult {
	switch observed {
	case ObservationBlocked:
		if expected == "Block" {
			return Match
		}
		return Mismatch
	case ObservationSucceeded:
		switch expected {
		case "Allow":
			return Match
		case "Block":
			return Mismatch
		default:
			return MissingEvidence
		}
	default: // ObservationUnknown, or any unrecognized token
		return MissingEvidence
	}
}

func init() {
	RegisterComparator("dlp", dlpComparator{})
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/reporting/... -run "TestDLPComparator|TestDLPComparatorRegistered" -v`
Expected: PASS (all subtests).

- [ ] **Step 5: Run the full reporting package test suite**

Run: `go test ./internal/reporting/... -v -count=1`
Expected: PASS — this task adds a new standalone file with no callers yet, so every pre-existing test (including `TestBuildDetectionValidationGoldenOutput`) must still pass completely unchanged.

- [ ] **Step 6: Build check**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/reporting/dlp.go orchestrator/internal/reporting/dlp_test.go
git commit -m "feat(reporting): dlpComparator — local-observation truth table for the dlp outcome family"
```

---

### Task 3: `dlpVerifier` + `StepEvidence.RawOutput` + dispatch wiring

**Files:**
- Modify: `orchestrator/internal/reporting/detection_validation.go` (`StepEvidence` struct, `evidenceByTechnique`, `verifyExpectation`)
- Modify: `orchestrator/internal/reporting/dlp.go` (add `dlpVerifier`)
- Test: `orchestrator/internal/reporting/dlp_test.go` (extend)
- Test: `orchestrator/internal/reporting/detection_validation_test.go` (extend, dispatch regression test)

**Interfaces:**
- Consumes:
  - From Task 2: `dlpComparator`, `ObservationSucceeded`/`ObservationBlocked`/`ObservationUnknown`, `comparatorFor("dlp")`.
  - From Phase A: `baseResult`, `collapseToStatus`, `scenario.ResolveOutcomeFamily`, `scenario.ResolveExpectedOutcome`.
- Produces: `StepEvidence.RawOutput string` (new field, consumed by `dlpVerifier`), `dlpVerifier` type implementing `Verifier` — nothing downstream of this task consumes these; this is the terminal task for the Go-side changes.

- [ ] **Step 1: Write the failing tests for `dlpVerifier`**

In `orchestrator/internal/reporting/dlp_test.go`, add:

```go
func dlpExp(id, expectedOutcome string) scenario.ExpectedDetection {
	return scenario.ExpectedDetection{
		ID:              id,
		Provider:        "trellix_dlp",
		Type:            scenario.DomainDLP,
		OutcomeFamily:   "dlp",
		ExpectedOutcome: expectedOutcome,
		Verification:    scenario.VerificationAutomatic,
		Confidence:      scenario.ConfidenceRequired,
		Finding:         scenario.ExpectedFinding{Title: "t", Severity: "High"},
	}
}

func TestDLPVerifier(t *testing.T) {
	exp := dlpExp("dlp-usb-block", "Block")

	// marker present, blocked, matches expected Block → Detected
	r := dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "some output\nDLP_OBSERVATION: OperationBlocked\n"})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("blocked-match: got status=%s comparison=%v", r.Status, r.Comparison)
	}

	// marker present, succeeded, mismatches expected Block → NotDetected
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "some output\nDLP_OBSERVATION: OperationSucceeded\n"})
	if r.Status != StatusNotDetected || r.Comparison != Mismatch {
		t.Errorf("succeeded-mismatch: got status=%s comparison=%v", r.Status, r.Comparison)
	}

	// no marker at all → Unknown, never a false Detected/NotDetected
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "some output with no marker at all"})
	if r.Status != StatusUnknown || r.Comparison != MissingEvidence {
		t.Errorf("no-marker: got status=%s comparison=%v", r.Status, r.Comparison)
	}

	// marker present but with an unrecognized token → Unknown, never guessed
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: SomeGarbageToken"})
	if r.Status != StatusUnknown || r.Comparison != MissingEvidence {
		t.Errorf("garbage-token: got status=%s comparison=%v", r.Status, r.Comparison)
	}

	// marker not on the last line — must still be found
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked\nsome trailing cleanup line"})
	if r.Status != StatusDetected {
		t.Errorf("marker-not-last-line: got status=%s want Detected", r.Status)
	}

	// ExpectedOutcome/ObservedOutcome are populated for diagnostics
	r = dlpVerifier{}.Verify(exp, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.ExpectedOutcome != "Block" || r.ObservedOutcome != ObservationBlocked {
		t.Errorf("outcome fields: got expected=%q observed=%q", r.ExpectedOutcome, r.ObservedOutcome)
	}
}
```

Add `"github.com/audspect/bas/internal/scenario"` to `dlp_test.go`'s import block if not already present (it will be, from `dlpExp`'s use of `scenario.ExpectedDetection`).

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/reporting/... -run TestDLPVerifier -v`
Expected: FAIL — `dlpVerifier` undefined, `StepEvidence` has no field `RawOutput`, `scenario.DomainDLP` may need confirming it exists (it does, from the existing Provider Registry — `internal/scenario/detection.go`).

- [ ] **Step 3: Add `RawOutput` to `StepEvidence`**

In `orchestrator/internal/reporting/detection_validation.go`, find the `StepEvidence` struct:

```go
type StepEvidence struct {
	TechniqueID       string
	DetectionVerdict  string   // prevented | detected | undetected | ""
	AlertProvider     string   // DetectionAlert.Provider when detected
	BlockingControl   string   // BlockingControl.Name when prevented
	Events            []string // raw Windows event tokens ("1116:...Defender/Operational")
	ExpectedTelemetry []string // step's expected telemetry lines (for completeness)
}
```

Add one field:

```go
type StepEvidence struct {
	TechniqueID       string
	DetectionVerdict  string   // prevented | detected | undetected | ""
	AlertProvider     string   // DetectionAlert.Provider when detected
	BlockingControl   string   // BlockingControl.Name when prevented
	Events            []string // raw Windows event tokens ("1116:...Defender/Operational")
	ExpectedTelemetry []string // step's expected telemetry lines (for completeness)
	RawOutput         string   // full step output text; read by verifiers that parse a self-reported marker, e.g. dlpVerifier
}
```

- [ ] **Step 4: Populate `RawOutput` in `evidenceByTechnique`**

In the same file, find `evidenceByTechnique`:

```go
func evidenceByTechnique(results []models.SimulationResult) map[string]StepEvidence {
	out := map[string]StepEvidence{}
	for _, r := range results {
		ev := StepEvidence{
			TechniqueID:      r.ID,
			DetectionVerdict: r.DetectionVerdict,
			Events:           r.Events,
		}
```

Add one line so it reads:

```go
func evidenceByTechnique(results []models.SimulationResult) map[string]StepEvidence {
	out := map[string]StepEvidence{}
	for _, r := range results {
		ev := StepEvidence{
			TechniqueID:      r.ID,
			DetectionVerdict: r.DetectionVerdict,
			Events:           r.Events,
			RawOutput:        r.RawOutput,
		}
```

- [ ] **Step 5: Add `dlpVerifier` to `orchestrator/internal/reporting/dlp.go`**

The file currently starts with `package reporting` and no import block (Task 2 needed none). Change the top of the file to:

```go
package reporting

import "regexp"
```

Then append the following to the end of the file, after `dlpComparator`'s `init()`:

```go
var dlpMarkerRe = regexp.MustCompile(`(?m)^DLP_OBSERVATION:\s*(\S+)$`)

// dlpVerifier resolves DLP expectations from a step's self-reported outcome
// marker. The script itself does the post-condition check (did the file land
// on the USB path, does Get-Clipboard now match, etc.) and prints exactly
// one deterministic line; this verifier only parses it. It never re-derives
// observations from vendor-specific error text — that would be exactly the
// fragile heuristic classifySkipReason's own doc comment warns against for
// third-party output. An absent or unrecognized marker always resolves to
// ObservationUnknown — never guessed as a known primitive.
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

Move the `import "regexp"` line into the file's existing top-level `import` block instead of leaving a second inline `import` statement — `dlp.go` currently has no import block (Task 2 only needed the `reporting` package's own symbols), so add one:

```go
package reporting

import "regexp"
```

as the file's only import line, and delete the standalone `import "regexp"` shown above (it was written inline for clarity in this step; the real edit adds it once, at the top of the file).

- [ ] **Step 6: Wire the dispatch branch in `verifyExpectation`**

In `orchestrator/internal/reporting/detection_validation.go`, find:

```go
func verifyExpectation(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	switch scenario.ResolveVerification(exp) {
	case scenario.VerificationAutomatic:
		return automaticVerifier{}.Verify(exp, ev)
	case scenario.VerificationAPI:
		return apiVerifier{}.Verify(exp, ev)
	default: // manual
		return manualVerifier{}.Verify(exp, ev)
	}
}
```

Replace with:

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

- [ ] **Step 7: Run the `dlpVerifier` test to verify it passes**

Run: `go test ./internal/reporting/... -run TestDLPVerifier -v`
Expected: PASS.

- [ ] **Step 8: Write and run the dispatch regression test**

In `orchestrator/internal/reporting/detection_validation_test.go`, add:

```go
func TestVerifyExpectationDispatchesByOutcomeFamily(t *testing.T) {
	// outcome_family: dlp routes to dlpVerifier.
	dlpExpDetection := scenario.ExpectedDetection{
		ID: "d", Provider: "trellix_dlp", Type: scenario.DomainDLP,
		OutcomeFamily: "dlp", ExpectedOutcome: "Block",
		Verification: scenario.VerificationAutomatic, Confidence: scenario.ConfidenceRequired,
		Finding: scenario.ExpectedFinding{Title: "t", Severity: "High"},
	}
	r := verifyExpectation(dlpExpDetection, StepEvidence{RawOutput: "DLP_OBSERVATION: OperationBlocked"})
	if r.Comparison != Match {
		t.Errorf("dlp-family expectation: got comparison=%v want Match (should have routed to dlpVerifier)", r.Comparison)
	}

	// no outcome_family (the "detection" default) keeps routing to automaticVerifier, unchanged.
	detExp := endpointExp("e", "microsoft_defender", scenario.ConfidenceRequired)
	r = verifyExpectation(detExp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "Microsoft Defender"})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("detection-family expectation: got status=%s comparison=%v — Phase A dispatch must be unaffected", r.Status, r.Comparison)
	}
}
```

Run: `go test ./internal/reporting/... -run TestVerifyExpectationDispatchesByOutcomeFamily -v`
Expected: PASS.

- [ ] **Step 9: Run the full reporting package test suite — the acceptance gate**

Run: `go test ./internal/reporting/... -v -count=1`
Expected: PASS, every single test unchanged, including `TestBuildDetectionValidationGoldenOutput` (byte-identical), `TestAutomaticVerifier`, and every other pre-existing test. A changed value anywhere is a regression and must be root-caused before proceeding.

- [ ] **Step 10: Run the full scenario package test suite**

Run: `go test ./internal/scenario/... -v -count=1`
Expected: PASS.

- [ ] **Step 11: Build check**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 12: Commit**

```bash
git add orchestrator/internal/reporting/dlp.go orchestrator/internal/reporting/dlp_test.go orchestrator/internal/reporting/detection_validation.go orchestrator/internal/reporting/detection_validation_test.go
git commit -m "feat(reporting): dlpVerifier + StepEvidence.RawOutput + outcome_family dispatch wiring"
```

---

### Task 4: Scenario content — `dlp-exfiltration-validation.yaml` + detection profile

**Files:**
- Create: `scenarios/dlp-exfiltration-validation.yaml` (+ `.sig`)
- Create: `scenarios/detection-profiles/windows_dlp_exfiltration.yaml` (+ `.sig`)
- Test: `orchestrator/internal/scenario/engine_test.go` (extend)

**Interfaces:**
- Consumes: `outcome_family`/`expected_outcome` fields on `ExpectedDetection` (Task 1), the `"dlp"` catalog (Task 1), `trellix_dlp` provider (already registered, unchanged).
- Produces: nothing consumed by other tasks — this is the final deliverable.

- [ ] **Step 1: Write the detection profile**

Create `scenarios/detection-profiles/windows_dlp_exfiltration.yaml`:

```yaml
# Detection Validation Profile — DLP exfiltration-channel behavioral family.
# One profile, five expected_detection entries (one per channel), matching
# windows_credential_access.yaml's precedent of grouping related expectations
# under a single behavioral profile rather than one profile per technique.
#
# Every entry declares outcome_family: dlp + expected_outcome: Block — the
# only outcome pair a local/automatic verifier can honestly distinguish (see
# internal/reporting/dlp.go's dlpComparator). Warn/Justify/Audit/etc. remain
# valid catalog values for a future policy profile once a DLP product
# connector exists to verify them — this profile intentionally declares none.
profile: windows_dlp_exfiltration
version: 1
expected_detection:
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
  - id: dlp-clipboard-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP did not block clipboard exposure of regulated data"
      remediation: >-
        Confirm clipboard monitoring/DLP policy covers regulated-data
        patterns (PAN/Aadhaar/SWIFT/UPI/credit-card) and blocks or clears the
        clipboard rather than allowing the copy silently.
      reference: "MITRE ATT&CK T1115 — Clipboard Data"
  - id: dlp-print-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: Medium
      title: "DLP did not block print exfiltration of regulated data"
      remediation: >-
        Confirm print-job DLP inspection covers regulated-data patterns and
        blocks submission to the spooler rather than allowing it silently.
      reference: "MITRE ATT&CK T1052 — Exfiltration Over Physical Medium"
  - id: dlp-archive-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP did not block archive-based staging of regulated data"
      remediation: >-
        Confirm DLP content inspection runs before archive creation
        completes (not only on already-compressed files) and blocks
        archiving of regulated-data patterns.
      reference: "MITRE ATT&CK T1560.001 — Archive via Utility"
  - id: dlp-local-stage-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: Medium
      title: "DLP did not block staging of regulated data to a shared local path"
      remediation: >-
        Confirm DLP endpoint policy inspects writes to shared/public local
        paths (e.g. C:\Users\Public) for regulated-data patterns, not only
        removable-media and network egress.
      reference: "MITRE ATT&CK T1074.001 — Local Data Staging"
```

- [ ] **Step 2: Write the scenario**

Create `scenarios/dlp-exfiltration-validation.yaml`:

```yaml
id: dlp-exfiltration-validation
name: DLP Exfiltration Validation — Regulated Data Channel Coverage
description: >
  Attempts to exfiltrate a single synthetic multi-type sensitive record
  (fabricated PAN, Aadhaar, SWIFT/BIC, UPI VPA, and credit-card patterns
  embedded together, like a realistic customer-records export) through five
  agent-native channels: USB-mounted-drive copy, clipboard, print spool,
  archive staging, and a shared local path. Tests whether DLP recognizes
  regulated Indian-BFSI data types and blocks the exfiltration attempt,
  independent of which channel carries it.

  First capability of the Data Protection Validation pillar (DLP first;
  Insider Risk, Cloud Storage, Email, and other channels follow as later,
  separate scenarios under the same pillar).

  Verification is local/agent-observed only in this version: each step's
  script performs its own post-condition check (did the file actually land
  on the target, does the clipboard now hold it, etc.) and reports exactly
  one of two primitive facts — the operation succeeded, or it was blocked —
  never a full DLP policy verdict. A Warn-and-continue policy produces the
  same local symptom as no policy at all (the operation still succeeds), so
  this scenario's expected outcome for every step is Block: the only outcome
  a local observer can honestly confirm. Richer policy verdicts (Warn,
  Justify, Audit, Quarantine, Encrypt, Redact) require a DLP product API
  connector, not yet built — see the design spec for the roadmap.

  Known scope limitation: the archive-staging step creates a standard ZIP
  via PowerShell's built-in Compress-Archive, which has no native password
  option in PowerShell 5.1 and no external archiver is bundled with the
  agent. It validates archive-based staging generally (still MITRE ATT&CK
  T1560.001), not the password-protected variant specifically.

  Preconditions: the USB-copy step requires a removable drive attached to
  the endpoint (mounted virtual media is sufficient) and the print step
  requires a configured default printer (a virtual/PDF printer is
  sufficient) — either step reports SKIP, not FAIL, if its precondition
  isn't met on a given host.

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. Every step is self-cleaning — no residual files, clipboard content,
  print jobs, or archives are left behind. Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration

steps:

  # ---------------------------------------------------------------------------
  # Channel 1 — USB-mounted-drive copy (T1052.001)
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — USB Exfiltration of Regulated Data (T1052.001)"
    technique_id: T1052.001
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Copies a synthetic multi-type sensitive record file to a removable drive if one is attached, then deletes it immediately. No persistence, no real regulated data."
    reversible: true
    telemetry:
      - "Sysmon EID 11: file creation on removable-media drive letter"
      - "Security EID 4663: object access on removable-media volume"
    detection:
      - "DLP: file-copy to removable-media volume matching regulated-data patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $usbDrive = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | Select-Object -First 1
      if (-not $usbDrive) {
        Write-Output "SKIP: no removable USB drive present on this host - DLP USB-copy validation requires physical or virtual removable media attached."
      } else {
        $srcFile = Join-Path $env:TEMP "bas_sim_dlp_records_$runId.csv"
        $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-$runId,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
        Set-Content -Path $srcFile -Value $csvContent -Encoding utf8
        $dest = "$($usbDrive.DriveLetter):\bas_sim_dlp_records_$runId.csv"
        Copy-Item -Path $srcFile -Destination $dest -ErrorAction SilentlyContinue
        if (Test-Path $dest) {
          Write-Output "EXEC T1052.001: multi-type sensitive record file copied to removable drive $($usbDrive.DriveLetter): unimpeded. [BAS-SIM-DLP-USB]"
          Write-Output "FAIL: sensitive record file (PAN/Aadhaar/SWIFT/UPI/credit-card patterns) copied to USB without being blocked."
          Remove-Item -Path $dest -ErrorAction SilentlyContinue
          Write-Output "DLP_OBSERVATION: OperationSucceeded"
        } else {
          Write-Output "EXEC T1052.001: copy to removable drive $($usbDrive.DriveLetter): was blocked or failed. [BAS-SIM-DLP-USB]"
          Write-Output "DLP_OBSERVATION: OperationBlocked"
        }
        Remove-Item -Path $srcFile -ErrorAction SilentlyContinue
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Channel 2 — Clipboard (T1115)
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Clipboard Exposure of Regulated Data (T1115)"
    technique_id: T1115
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Writes a synthetic multi-type sensitive record to the clipboard, checks whether it landed, then restores the original clipboard content. No persistence, no real regulated data."
    reversible: true
    telemetry:
      - "Clipboard User Service activity (no dedicated Windows event ID; DLP clipboard-hook telemetry is vendor-specific)"
    detection:
      - "DLP: clipboard-monitoring hook matching regulated-data patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-$runId,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $originalClip = $null
      try { $originalClip = Get-Clipboard -Raw -ErrorAction SilentlyContinue } catch {}
      Set-Clipboard -Value $csvContent -ErrorAction SilentlyContinue
      Start-Sleep -Milliseconds 300
      $nowClip = $null
      try { $nowClip = Get-Clipboard -Raw -ErrorAction SilentlyContinue } catch {}
      if ($nowClip -and $nowClip.Contains('ABCDE1234F')) {
        Write-Output "EXEC T1115: multi-type sensitive record content set to clipboard unimpeded. [BAS-SIM-DLP-CLIP]"
        Write-Output "FAIL: sensitive record content (PAN/Aadhaar/SWIFT/UPI/credit-card patterns) was placed on the clipboard without being blocked or cleared."
        Write-Output "DLP_OBSERVATION: OperationSucceeded"
      } else {
        Write-Output "EXEC T1115: clipboard write of sensitive content was blocked or cleared. [BAS-SIM-DLP-CLIP]"
        Write-Output "DLP_OBSERVATION: OperationBlocked"
      }
      if ($null -ne $originalClip) { Set-Clipboard -Value $originalClip -ErrorAction SilentlyContinue } else { Set-Clipboard -Value '' -ErrorAction SilentlyContinue }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Channel 3 — Print spool (T1052)
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Print Exfiltration of Regulated Data (T1052)"
    technique_id: T1052
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Submits a synthetic multi-type sensitive record to the default printer's spool queue if one is configured, then removes the job immediately. No persistence, no real regulated data."
    reversible: true
    telemetry:
      - "Print spooler EID 307/347: print job submitted/completed"
    detection:
      - "DLP: print-job content inspection matching regulated-data patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $printer = Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue | Where-Object { $_.Default -eq $true } | Select-Object -First 1
      if (-not $printer) {
        Write-Output "SKIP: no default printer configured on this host - DLP print-exfiltration validation requires a configured printer (physical or virtual/PDF)."
      } else {
        $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-$runId,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
        $srcFile = Join-Path $env:TEMP "bas_sim_dlp_print_$runId.txt"
        Set-Content -Path $srcFile -Value $csvContent -Encoding utf8
        try {
          Get-Content -Path $srcFile | Out-Printer -Name $printer.Name -ErrorAction Stop
          Start-Sleep -Milliseconds 500
          $job = Get-PrintJob -PrinterName $printer.Name -ErrorAction SilentlyContinue | Where-Object { $_.DocumentName -match 'bas_sim_dlp_print' -or $_.JobStatus -match 'Printing|Spooling|Normal' } | Select-Object -First 1
          if ($job) {
            Write-Output "EXEC T1052: sensitive record content submitted to print spooler ($($printer.Name)) unimpeded. [BAS-SIM-DLP-PRINT]"
            Write-Output "FAIL: sensitive record content (PAN/Aadhaar/SWIFT/UPI/credit-card patterns) reached the print spooler without being blocked."
            Remove-PrintJob -PrinterName $printer.Name -ID $job.ID -ErrorAction SilentlyContinue
            Write-Output "DLP_OBSERVATION: OperationSucceeded"
          } else {
            Write-Output "EXEC T1052: print submission did not appear in the spool queue - blocked or intercepted. [BAS-SIM-DLP-PRINT]"
            Write-Output "DLP_OBSERVATION: OperationBlocked"
          }
        } catch {
          Write-Output "EXEC T1052: print submission threw an error - treated as blocked. [BAS-SIM-DLP-PRINT]"
          Write-Output "DLP_OBSERVATION: OperationBlocked"
        }
        Remove-Item -Path $srcFile -ErrorAction SilentlyContinue
      }
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Channel 4 — Archive staging (T1560.001)
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Archive Staging of Regulated Data (T1560.001)"
    technique_id: T1560.001
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Compresses a synthetic multi-type sensitive record into a standard ZIP archive via Compress-Archive, then deletes both files immediately. No password protection (no external archiver bundled with the agent); no persistence, no real regulated data."
    reversible: true
    telemetry:
      - "Sysmon EID 11: .zip file creation in %TEMP%"
    detection:
      - "DLP: archive-creation content inspection matching regulated-data patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-$runId,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $srcFile = Join-Path $env:TEMP "bas_sim_dlp_archive_src_$runId.csv"
      $zipFile = Join-Path $env:TEMP "bas_sim_dlp_archive_$runId.zip"
      Set-Content -Path $srcFile -Value $csvContent -Encoding utf8
      try {
        Compress-Archive -Path $srcFile -DestinationPath $zipFile -ErrorAction Stop
      } catch {}
      if (Test-Path $zipFile) {
        Write-Output "EXEC T1560.001: sensitive record file archived to $zipFile unimpeded. [BAS-SIM-DLP-ZIP]"
        Write-Output "FAIL: sensitive record content (PAN/Aadhaar/SWIFT/UPI/credit-card patterns) was compressed into an archive without being blocked."
        Write-Output "DLP_OBSERVATION: OperationSucceeded"
      } else {
        Write-Output "EXEC T1560.001: archive creation was blocked or failed. [BAS-SIM-DLP-ZIP]"
        Write-Output "DLP_OBSERVATION: OperationBlocked"
      }
      Remove-Item -Path $srcFile,$zipFile -ErrorAction SilentlyContinue
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Channel 5 — Local staging to a shared path (T1074.001)
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Local Staging of Regulated Data to a Shared Path (T1074.001)"
    technique_id: T1074.001
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 20
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Writes a synthetic multi-type sensitive record to C:\\Users\\Public (a shared/world-readable local path), then deletes it immediately. No persistence, no real regulated data."
    reversible: true
    telemetry:
      - "Sysmon EID 11: file creation under C:\\Users\\Public"
    detection:
      - "DLP: endpoint file-write inspection on shared/public local paths matching regulated-data patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $runId = if ($env:BAS_RUN_ID) { $env:BAS_RUN_ID.Substring(0,[Math]::Min(8,$env:BAS_RUN_ID.Length)) } else { '{0:x8}' -f (Get-Random -Maximum 0x7FFFFFFF) }
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-$runId,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $stagingDir = 'C:\Users\Public\bas_sim_dlp_staging'
      $dest = Join-Path $stagingDir "records_$runId.csv"
      try {
        New-Item -Path $stagingDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Set-Content -Path $dest -Value $csvContent -Encoding utf8 -ErrorAction Stop
      } catch {}
      if (Test-Path $dest) {
        Write-Output "EXEC T1074.001: sensitive record file staged to a shared local path ($stagingDir) unimpeded. [BAS-SIM-DLP-STAGE]"
        Write-Output "FAIL: sensitive record content (PAN/Aadhaar/SWIFT/UPI/credit-card patterns) was written to a shared local staging path without being blocked."
        Write-Output "DLP_OBSERVATION: OperationSucceeded"
      } else {
        Write-Output "EXEC T1074.001: staging write to shared local path was blocked or failed. [BAS-SIM-DLP-STAGE]"
        Write-Output "DLP_OBSERVATION: OperationBlocked"
      }
      Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    cleanup: ""
```

- [ ] **Step 3: Write the `ParseYAML` validation test**

In `orchestrator/internal/scenario/engine_test.go`, add:

```go
func TestParseYAML_DLPExfiltrationValidation(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", "dlp-exfiltration-validation.yaml"))
	if err != nil {
		t.Fatalf("read scenario file: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sc.ID != "dlp-exfiltration-validation" {
		t.Fatalf("id = %q, want dlp-exfiltration-validation", sc.ID)
	}
	if !sc.Executable {
		t.Fatalf("expected executable: true")
	}
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "windows" {
		t.Fatalf("supported_os = %v, want [windows]", sc.SupportedOS)
	}
	if len(sc.Steps) != 5 {
		t.Fatalf("steps = %d, want 5", len(sc.Steps))
	}
	wantTechniques := []string{"T1052.001", "T1115", "T1052", "T1560.001", "T1074.001"}
	for i, want := range wantTechniques {
		if sc.Steps[i].TechniqueID != want {
			t.Errorf("step %d technique_id = %q, want %q", i, sc.Steps[i].TechniqueID, want)
		}
		if len(sc.Steps[i].DetectionProfiles) != 1 || sc.Steps[i].DetectionProfiles[0] != "windows_dlp_exfiltration" {
			t.Errorf("step %d detection_profiles = %v, want [windows_dlp_exfiltration]", i, sc.Steps[i].DetectionProfiles)
		}
	}
}
```

Check the top of `engine_test.go` already imports `"os"` and `"path/filepath"` (it does — `TestParseYAML_UbuntuHardeningValidation` uses both already).

- [ ] **Step 4: Run the test to verify it fails**

Run: `go test ./internal/scenario/... -run TestParseYAML_DLPExfiltrationValidation -v -count=1`
Expected: FAIL — `read scenario file` error, since the file doesn't exist yet if Step 2 wasn't done first. (If Step 2 was already completed, this instead validates real content — confirm it fails only because Step 2 hasn't landed yet, not for a different reason.)

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/scenario/... -run TestParseYAML_DLPExfiltrationValidation -v -count=1`
Expected: PASS.

- [ ] **Step 6: Manual PowerShell syntax sanity check**

For each of the 5 `command:` blocks in `scenarios/dlp-exfiltration-validation.yaml`, extract the script text and run it through PowerShell's own parser (does not execute the script, only validates syntax):

```powershell
$script = Get-Content -Raw -Path "path\to\extracted\step1.ps1"
[System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$null, [ref]$errors) | Out-Null
if ($errors) { $errors }
```

Expected: no parse errors for any of the 5 blocks. There is no automated Go-side tool for this in the repo — this is a manual authoring-time check per the design spec.

- [ ] **Step 7: Run the full scenario package test suite**

Run: `go test ./internal/scenario/... -v -count=1`
Expected: PASS, all tests including the new one.

- [ ] **Step 8: Sign both new content files**

From `orchestrator/`:

```bash
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-validation.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml
```

Expected: both commands exit 0 and produce `scenarios/dlp-exfiltration-validation.yaml.sig` and `scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig`.

- [ ] **Step 9: Build check**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 10: Commit**

```bash
git add scenarios/dlp-exfiltration-validation.yaml scenarios/dlp-exfiltration-validation.yaml.sig scenarios/detection-profiles/windows_dlp_exfiltration.yaml scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig orchestrator/internal/scenario/engine_test.go
git commit -m "feat(scenarios): DLP Exfiltration Validation — 5-channel regulated-data coverage (Phase B content)"
```

---

## Plan-level acceptance criteria (verify after Task 4)

- [ ] `go build ./...` clean.
- [ ] `go test ./internal/scenario/... ./internal/reporting/... -v -count=1` — 100% pass, zero changed expected values in any pre-existing test (Phase A's golden output byte-identical).
- [ ] `go vet ./...` clean.
- [ ] `automaticVerifier`, `detectionComparator`, and every Phase A file are unmodified except the two additive, deliberate changes in Task 3 (the `StepEvidence.RawOutput` field and the one new dispatch branch) — confirm via `git diff cc74a3c..HEAD -- orchestrator/internal/reporting/detection_validation.go` that no other lines changed.
- [ ] Both new content files have a corresponding `.sig` file.
