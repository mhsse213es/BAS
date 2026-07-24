# Outcome Validation Framework — Design (Phase A)

## Context

Detection Validation today compares one thing: did an expected control fire or not. `ExpectedDetection` (what a step declares it expects) and `StepEvidence` (what the agent actually observed) feed a `Verifier`, which produces a `VerificationResult` whose `Status` is one of `Detected | NotDetected | NotApplicable | Unknown | Pending`. That binary shape is baked into `automaticVerifier.Verify` (`internal/reporting/detection_validation.go`), which inlines evidence-inspection and match-decision in one function.

Several validation domains this platform will eventually need — anything that produces a *policy decision* rather than a *detection event* — don't fit a binary model. A control might respond with one of several distinct outcomes (e.g. allow, block, warn-with-override, encrypt, quarantine, audit-only), and "the control acted, but with a different outcome than expected" is a meaningfully different finding from either "acted as expected" or "stayed silent" — it's policy drift, not a plain pass/fail.

This phase builds the generalized abstraction that lets a future validation domain declare its own outcome vocabulary and comparison semantics, without the core engine needing to know what any of those values mean. It ships **zero new domains** — the only concrete outcome family it registers is `"detection"`, implemented as a byte-for-byte extraction of today's existing logic. The deliverable is the extension point itself, proven correct by making the one real consumer that exists today (Detection Validation) run through it unchanged.

## Principle

> Binary detection becomes a specialization of outcome validation, not a separate system running alongside it.

Concretely: `Status` (the field every existing scoring/report code path already consumes) stops being computed directly from evidence. It becomes *derived* from a new, richer comparison result. If it were instead computed independently and left to happen to agree with the new pipeline, that would be two systems coincidentally producing the same numbers — fragile, and not what "specialization" means here.

## Architecture

### 1. New vocabulary type: outcome families (`internal/scenario/outcome.go`, new file)

Two new optional fields on `ExpectedDetection` (`internal/scenario/detection.go`):

```go
// OutcomeFamily selects which outcome vocabulary and comparison semantics this
// expectation uses. Empty defaults to "detection" — today's implicit binary
// model — so every existing scenario and detection profile is unaffected.
OutcomeFamily string `yaml:"outcome_family,omitempty" json:"outcomeFamily,omitempty"`

// ExpectedOutcome is the outcome value this expectation requires, drawn from
// its family's catalog (e.g. "Detected" for the "detection" family). Empty
// defaults to the family's implicit expectation — "Detected" for "detection".
ExpectedOutcome string `yaml:"expected_outcome,omitempty" json:"expectedOutcome,omitempty"`
```

Both are additive struct fields — no existing YAML sets them, so `ResolveOutcomeFamily`/`ResolveExpectedOutcome` (new resolver functions mirroring the existing `ResolveDomain`/`ResolveVerification` pattern) always fall back to `"detection"` / `"Detected"` for current content, identically to how an unset `Type` today falls back to the provider's `DefaultDomain`.

`OutcomeFamily` is a field **distinct from `Type`/`Domain`** (`endpoint | identity | network | cloud | email | dlp | siem`). Domain answers *where in the report matrix a finding groups*; outcome family answers *what shape its expected/observed values take*. They aren't 1:1 — two families with incompatible vocabularies could both belong to the same domain (e.g. a future "device control" family and a future "SOAR response" family could both report under the endpoint domain but need entirely different outcome catalogs). Keeping them orthogonal avoids that collision without this phase needing to anticipate every future family.

A small load-time registry validates that a declared `outcome_family`/`expected_outcome` pair is known, the same way `detection_profiles.go` already validates `Confidence`/`Verification`/`Type` enums today:

```go
// OutcomeCatalog is the set of valid outcome values for one family, plus its
// implicit default expectation when a step doesn't declare one explicitly.
type OutcomeCatalog struct {
    Family          string
    Values          []string
    ImplicitExpected string
}

func RegisterOutcomeCatalog(c OutcomeCatalog)
func ValidOutcome(family, value string) bool
```

Phase A registers exactly one catalog: `{Family: "detection", Values: []string{"Detected", "NotDetected"}, ImplicitExpected: "Detected"}`.

### 2. New comparison type and registry (`internal/reporting/outcome.go`, new file)

```go
// ComparisonResult is the richer internal verdict a Comparator produces,
// before it is collapsed to a Status for existing scoring/reporting code.
type ComparisonResult string

const (
    Match           ComparisonResult = "Match"
    Mismatch        ComparisonResult = "Mismatch"
    MissingEvidence ComparisonResult = "MissingEvidence"
    NotApplicable   ComparisonResult = "NotApplicable"
    Unknown         ComparisonResult = "Unknown"
)

// Comparator encapsulates one outcome family's comparison semantics. The core
// engine never interprets outcome values itself — it only ever asks the
// family's registered Comparator to compare them.
type Comparator interface {
    Compare(expectedOutcome, observedOutcome string) ComparisonResult
}

func RegisterComparator(family string, c Comparator)
func comparatorFor(family string) Comparator // falls back to a no-op Unknown comparator if unregistered
```

Phase A registers exactly one comparator, `detectionComparator`, under family `"detection"`. Its `Compare` body is the *extraction, not rewrite* of today's `providerMatches`/`DetectionVerdict` logic currently inlined in `automaticVerifier.Verify` — same branches, same outcomes, moved verbatim into a standalone, independently testable type.

### 3. `VerificationResult` gains additive, internal-only fields

```go
type VerificationResult struct {
    // ...existing fields unchanged...
    ExpectedOutcome string
    ObservedOutcome string
    Comparison      ComparisonResult
}
```

These are new fields on an existing Go struct — not part of any JSON-serialized report type (`ExpectationRow`, `DetectionValidationSection`). `VerificationResult` is purely an intermediate computation value consumed inside `BuildDetectionValidationWithStore`, which already extracts only `Status`/`Source`/`Domain`/etc. into the report-facing `ExpectationRow`. Adding fields here cannot change any report's JSON or HTML output.

### 4. `automaticVerifier.Verify` becomes comparator-driven

This is the one place precision matters: today's code has a subtlety that a naive extraction would silently break. The non-endpoint-domain early return (`Status = StatusUnknown`) and the endpoint-domain-but-no-match case (`Status = StatusNotDetected`) are *different* outcomes today — "couldn't observe this at all" vs. "observed it, and it didn't match." Both must stay distinguishable after the refactor, or the byte-identical acceptance test will (correctly) fail.

The fix: the observed-outcome token has a third possible value — an empty-string sentinel meaning "not observable by this verifier" — distinct from the `"NotDetected"` token, which means "observable, and no matching control responded":

```go
func (automaticVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
    r := baseResult(exp, ev, "automatic")
    r.ExpectedOutcome = scenario.ResolveExpectedOutcome(exp)
    r.ObservedOutcome, r.Source = observeDetectionOutcome(exp, ev)
    r.Comparison = comparatorFor(scenario.ResolveOutcomeFamily(exp)).Compare(r.ExpectedOutcome, r.ObservedOutcome)
    r.Status = collapseToStatus(r.Comparison)
    return r
}

// observeDetectionOutcome is today's automaticVerifier switch, extracted
// verbatim, translated into a (token, source) pair instead of setting
// Status/Source directly. Returns ("", "") when this verifier cannot observe
// the expectation's domain at all — the sentinel MissingEvidence maps to.
func observeDetectionOutcome(exp scenario.ExpectedDetection, ev StepEvidence) (outcome, source string) {
    if scenario.ResolveDomain(exp) != scenario.DomainEndpoint {
        return "", ""
    }
    switch ev.DetectionVerdict {
    case "detected":
        src := ev.AlertProvider
        if src == "" {
            src = classifyDetection(ev.Events).Source
        }
        if providerMatches(exp.Provider, src) {
            return "Detected", src
        }
        return "NotDetected", ""
    case "prevented":
        if providerMatches(exp.Provider, ev.BlockingControl) {
            return "Detected", ev.BlockingControl
        }
        return "NotDetected", ""
    default: // undetected / empty
        return "NotDetected", ""
    }
}

// detectionComparator is the "detection" family's registered Comparator.
type detectionComparator struct{}

func (detectionComparator) Compare(expected, observed string) ComparisonResult {
    switch {
    case observed == "":
        return MissingEvidence
    case observed == expected:
        return Match
    default:
        return Mismatch
    }
}

func collapseToStatus(c ComparisonResult) string {
    switch c {
    case Match:
        return StatusDetected
    case Mismatch:
        return StatusNotDetected
    case NotApplicable:
        return StatusNotApplicable
    default: // MissingEvidence, Unknown
        return StatusUnknown
    }
}
```

Traced against every original branch: non-endpoint domain → `("", "")` → `MissingEvidence` → `StatusUnknown`, matching today's early return exactly. Endpoint + matched detected/prevented → `("Detected", src)` → `Match` → `StatusDetected` + `Source=src`, matching today. Endpoint + mismatched, or undetected/empty → `("NotDetected", "")` → `Mismatch` → `StatusNotDetected` + `Source=""`, matching today (today's mismatch branches never set `Source` either — it stays the zero value). `NotApplicable`/`Unknown` `ComparisonResult` values are never produced by `automaticVerifier` itself — `NotApplicable` stays exclusively an `applyOverride` (manual/API attestation) outcome, entirely untouched by this refactor — but both are included in `collapseToStatus` for completeness, since a future family's comparator may legitimately produce either.

`manualVerifier`, `apiVerifier`, and `applyOverride` are **not touched**. The first two are SP2/SP3 stubs that unconditionally return `Pending` without inspecting evidence — there is no match-decision logic in them to generalize. `applyOverride` sets `Status` directly from a stored attestation's `Result`/`WorkflowState`, a separate code path from `Verifier.Verify` entirely. `Pending` itself is a workflow state (tracked via `verification.WorkflowState`), not a comparison outcome, and is out of scope for this phase.

## What does not change

- `Verifier` interface signature — unchanged.
- The scoring loop in `BuildDetectionValidationWithStore` (`covNum`/`covDen` weighting, `sec.Detected++`, Coverage/VerificationCompleteness math, False Silence detection) — untouched, still keyed on `vr.Status` exactly as today.
- Every field of `ExpectationRow` and `DetectionValidationSection` — no new fields, no renamed fields.
- `html.go`, `engine.go` rendering — untouched.
- `manualVerifier`, `apiVerifier`, `applyOverride`, the Verification Store, and every existing connector (SP3 API verifiers) — untouched.
- Database schema — no migration. `verification_history.result` is already a free-text column (`internal/db/postgres.go:804`), so a future family's richer outcome strings need no schema change when it eventually arrives.

## Non-goals (explicitly deferred)

- Registering any outcome family besides `"detection"`. This phase proves the extension point; it does not use it for anything new.
- Any UI/report surface for `ExpectedOutcome`/`ObservedOutcome`/`Comparison` — they're computed but not yet rendered anywhere, since no family besides the legacy one exists to populate them meaningfully.
- Changing `manualVerifier`/`apiVerifier` to be comparator-driven — revisit only if/when a manual or API-verified family needs richer-than-Pending semantics.
- A UI-facing PASS/FAIL collapse of `ComparisonResult` — not needed until a consumer exists that wants it.

## Testing approach

1. **Unit tests for the new package pieces**: `detectionComparator.Compare` table-driven over every branch `automaticVerifier.Verify`'s old inline switch had (detected+matching-provider, detected+mismatched-provider, prevented+matching, prevented+mismatched, non-endpoint domain, empty/undetected evidence). `collapseToStatus` table-driven over all five `ComparisonResult` values. `ResolveOutcomeFamily`/`ResolveExpectedOutcome` table-driven over unset/set fields.
2. **Regression proof — the non-negotiable gate**: the full existing `internal/reporting` test suite (`engine_test.go`, `insights_test.go`, `html_test.go`, and the detection-validation-specific tests) must pass with zero changes to any expected value.
3. **Golden-output characterization test** (new): `internal/reporting/detection_validation_test.go`'s existing tests build their inputs as synthetic, inline `StepDetectionSpec`/`models.SimulationResult` fixtures (there is no scenario-YAML-backed fixture data to snapshot — confirmed no `testdata/` directory and no test references any scenario file by name). The golden-output test follows that same established pattern rather than loading real scenario files: construct fixture sets representative of each of the 4 flagship kill chains' detection-profile shapes (endpoint-domain Detected, endpoint-domain NotDetected, non-endpoint Unknown, NotApplicable, mixed required/recommended/optional confidence), capture `BuildDetectionValidationWithStore`'s full output (every field of `DetectionValidationSection`, not just `Status`) before the refactor, and assert byte-identical output after. This is the automated form of the "byte-identical existing reports" acceptance criterion, not just "tests still pass."
4. `go build ./...` clean; no `go vet` regressions.
