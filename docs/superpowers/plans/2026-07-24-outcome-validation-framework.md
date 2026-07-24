# Outcome Validation Framework (Phase A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generalize Detection Validation's binary detected/not-detected verifier logic into a pluggable Expected-Outcome vs. Observed-Outcome comparator model, registering exactly one concrete outcome family (`"detection"`, today's exact behavior) so future validation domains can plug in later without touching this engine again.

**Architecture:** Two new files add the vocabulary layer (`internal/scenario/outcome.go`: outcome catalogs, `OutcomeFamily`/`ExpectedOutcome` fields, resolvers) and the comparison layer (`internal/reporting/outcome.go`: `ComparisonResult` enum, `Comparator` interface + registry, the `"detection"` family's comparator). `automaticVerifier.Verify` (`internal/reporting/detection_validation.go`) is refactored to route through both, with `Status` now *derived* from the comparator's result rather than computed independently.

**Tech Stack:** Go (existing orchestrator backend), no new dependencies, no database migration.

## Global Constraints

- Zero database schema changes — `verification_history.result` is already a free-text column (`internal/db/postgres.go:804`).
- `Verifier` interface signature (`internal/reporting/detection_validation.go:68`) must not change.
- `manualVerifier`, `apiVerifier`, and `applyOverride` must not be modified.
- No new/changed/renamed fields on `ExpectationRow` or `DetectionValidationSection` — the new `VerificationResult` fields (`ExpectedOutcome`/`ObservedOutcome`/`Comparison`) are internal-only, never surfaced in report JSON.
- Every existing test in `internal/reporting` and `internal/scenario` must pass with **zero changes to any expected value** — this is the acceptance gate, not a nice-to-have.
- Phase A registers exactly one outcome family (`"detection"`) and exactly one comparator (`detectionComparator`). Do not add any DLP-, response-, or other-domain-specific code — that's explicitly out of scope (see spec's Non-goals).

---

### Task 1: Outcome catalog vocabulary in `internal/scenario`

**Files:**
- Create: `orchestrator/internal/scenario/outcome.go`
- Modify: `orchestrator/internal/scenario/detection.go` (add two fields to `ExpectedDetection`, lines 18-59)
- Modify: `orchestrator/internal/scenario/detection_profiles.go` (extend `validateExpectation`, lines 105-133)
- Test: `orchestrator/internal/scenario/outcome_test.go` (new)
- Test: `orchestrator/internal/scenario/detection_profiles_test.go` (extend `TestValidateExpectation`, lines 20-38)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first task).
- Produces (for Task 2 and Task 3 to consume):
  - `scenario.ExpectedDetection.OutcomeFamily string` (new field)
  - `scenario.ExpectedDetection.ExpectedOutcome string` (new field)
  - `scenario.ResolveOutcomeFamily(exp ExpectedDetection) string` — returns `exp.OutcomeFamily`, or `"detection"` if empty.
  - `scenario.ResolveExpectedOutcome(exp ExpectedDetection) string` — returns `exp.ExpectedOutcome`, or the resolved family's `ImplicitExpected` if empty.
  - `scenario.RegisterOutcomeCatalog(c OutcomeCatalog)`, `scenario.ValidOutcome(family, value string) bool`
  - `scenario.OutcomeCatalog{Family, Values []string, ImplicitExpected string}`
  - The `"detection"` catalog pre-registered via `init()`: `{Family: "detection", Values: []string{"Detected", "NotDetected"}, ImplicitExpected: "Detected"}`.

- [ ] **Step 1: Write the failing tests for the catalog registry**

Create `orchestrator/internal/scenario/outcome_test.go`:

```go
package scenario

import "testing"

func TestResolveOutcomeFamily(t *testing.T) {
	if got := ResolveOutcomeFamily(ExpectedDetection{}); got != "detection" {
		t.Errorf("empty OutcomeFamily: got %q want detection", got)
	}
	if got := ResolveOutcomeFamily(ExpectedDetection{OutcomeFamily: "custom"}); got != "custom" {
		t.Errorf("explicit OutcomeFamily: got %q want custom", got)
	}
}

func TestResolveExpectedOutcome(t *testing.T) {
	if got := ResolveExpectedOutcome(ExpectedDetection{}); got != "Detected" {
		t.Errorf("empty ExpectedOutcome falls back to detection family's implicit default: got %q want Detected", got)
	}
	if got := ResolveExpectedOutcome(ExpectedDetection{ExpectedOutcome: "NotDetected"}); got != "NotDetected" {
		t.Errorf("explicit ExpectedOutcome: got %q want NotDetected", got)
	}
}

func TestValidOutcome(t *testing.T) {
	if !ValidOutcome("detection", "Detected") {
		t.Error("Detected should be valid for the detection family")
	}
	if !ValidOutcome("detection", "NotDetected") {
		t.Error("NotDetected should be valid for the detection family")
	}
	if ValidOutcome("detection", "Warn") {
		t.Error("Warn should not be valid for the detection family")
	}
	if ValidOutcome("nonexistent-family", "anything") {
		t.Error("an unregistered family should never validate any value")
	}
}

func TestRegisterOutcomeCatalog(t *testing.T) {
	RegisterOutcomeCatalog(OutcomeCatalog{Family: "test-only", Values: []string{"A", "B"}, ImplicitExpected: "A"})
	if !ValidOutcome("test-only", "A") {
		t.Error("newly registered family's value should validate")
	}
	if ValidOutcome("test-only", "C") {
		t.Error("value outside the registered catalog should not validate")
	}
}

func TestFamilyKnown(t *testing.T) {
	if !familyKnown("detection") {
		t.Error("detection family should be known — it's registered by this package's own init()")
	}
	if familyKnown("nonexistent-family") {
		t.Error("an unregistered family should not be known")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/scenario/... -run "TestResolveOutcomeFamily|TestResolveExpectedOutcome|TestValidOutcome|TestRegisterOutcomeCatalog|TestFamilyKnown" -v`
Expected: FAIL — `ResolveOutcomeFamily`, `ResolveExpectedOutcome`, `ValidOutcome`, `RegisterOutcomeCatalog`, `OutcomeCatalog`, `familyKnown` undefined.

- [ ] **Step 3: Add the two new fields to `ExpectedDetection`**

In `orchestrator/internal/scenario/detection.go`, add after the existing `RuleIDs` field (before the closing `}` of the `ExpectedDetection` struct, i.e. after line 58):

```go
	// OutcomeFamily selects which outcome vocabulary and comparison semantics
	// this expectation uses. Empty defaults to "detection" — today's implicit
	// binary detected/not-detected model — so every existing scenario and
	// detection profile is unaffected. Distinct from Type/domain: domain
	// answers where a finding groups in the report matrix, OutcomeFamily
	// answers what shape its expected/observed values take. They are not 1:1
	// — two incompatible outcome vocabularies could share one domain.
	OutcomeFamily string `yaml:"outcome_family,omitempty" json:"outcomeFamily,omitempty"`

	// ExpectedOutcome is the outcome value this expectation requires, drawn
	// from its family's catalog. Empty defaults to the family's implicit
	// expectation ("Detected" for the "detection" family).
	ExpectedOutcome string `yaml:"expected_outcome,omitempty" json:"expectedOutcome,omitempty"`
```

- [ ] **Step 4: Create `orchestrator/internal/scenario/outcome.go`**

```go
package scenario

import "sync"

// Outcome Validation Framework — Phase A vocabulary layer.
//
// A validation domain (Detection Validation today; future domains like device
// control or SOAR response later) declares an OutcomeCatalog: the set of
// values an expectation may name as its ExpectedOutcome, plus the implicit
// default when a step doesn't declare one. This package only holds the
// vocabulary — comparison semantics (how two outcome values are judged to
// match) live in internal/reporting, which is where evidence is evaluated.

// OutcomeCatalog is the set of valid outcome values for one outcome family.
type OutcomeCatalog struct {
	Family           string
	Values           []string
	ImplicitExpected string
}

var (
	outcomeMu       sync.RWMutex
	outcomeRegistry = map[string]OutcomeCatalog{}
)

// RegisterOutcomeCatalog adds or replaces a family's catalog.
func RegisterOutcomeCatalog(c OutcomeCatalog) {
	outcomeMu.Lock()
	defer outcomeMu.Unlock()
	outcomeRegistry[c.Family] = c
}

// ValidOutcome reports whether value is a recognized outcome for family. An
// unregistered family never validates anything — content referencing an
// unknown family is rejected at load time, not silently accepted.
func ValidOutcome(family, value string) bool {
	outcomeMu.RLock()
	defer outcomeMu.RUnlock()
	c, ok := outcomeRegistry[family]
	if !ok {
		return false
	}
	for _, v := range c.Values {
		if v == value {
			return true
		}
	}
	return false
}

// implicitExpected returns the family's default ExpectedOutcome, or "" if the
// family is unregistered.
func implicitExpected(family string) string {
	outcomeMu.RLock()
	defer outcomeMu.RUnlock()
	return outcomeRegistry[family].ImplicitExpected
}

// familyKnown reports whether family has a registered catalog. Used at
// load-time validation to reject content naming an unknown family — a direct
// registry check, not inferred from ImplicitExpected being non-empty (a
// future family could legitimately have no implicit default).
func familyKnown(family string) bool {
	outcomeMu.RLock()
	defer outcomeMu.RUnlock()
	_, ok := outcomeRegistry[family]
	return ok
}

func init() {
	RegisterOutcomeCatalog(OutcomeCatalog{
		Family:           "detection",
		Values:           []string{"Detected", "NotDetected"},
		ImplicitExpected: "Detected",
	})
}

// ResolveOutcomeFamily returns the outcome family for an expectation: its
// explicit OutcomeFamily, else "detection" — the implicit family every
// existing expectation belongs to today.
func ResolveOutcomeFamily(exp ExpectedDetection) string {
	if exp.OutcomeFamily != "" {
		return exp.OutcomeFamily
	}
	return "detection"
}

// ResolveExpectedOutcome returns the outcome value an expectation requires:
// its explicit ExpectedOutcome, else its resolved family's implicit default.
func ResolveExpectedOutcome(exp ExpectedDetection) string {
	if exp.ExpectedOutcome != "" {
		return exp.ExpectedOutcome
	}
	return implicitExpected(ResolveOutcomeFamily(exp))
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/scenario/... -run "TestResolveOutcomeFamily|TestResolveExpectedOutcome|TestValidOutcome|TestRegisterOutcomeCatalog|TestFamilyKnown" -v`
Expected: PASS (all 5 tests).

- [ ] **Step 6: Wire load-time validation for the two new fields**

In `orchestrator/internal/scenario/detection_profiles.go`, in `validateExpectation` (after the existing `Type` domain check, i.e. after the block ending at line 124, before the `ConfidenceRequired` finding check at line 127), add:

```go
	family := ResolveOutcomeFamily(exp)
	if exp.OutcomeFamily != "" && !familyKnown(family) {
		return fmt.Errorf("id %q: unknown outcome_family %q", exp.ID, exp.OutcomeFamily)
	}
	if exp.ExpectedOutcome != "" && !ValidOutcome(family, exp.ExpectedOutcome) {
		return fmt.Errorf("id %q: invalid expected_outcome %q for family %q", exp.ID, exp.ExpectedOutcome, family)
	}
```

- [ ] **Step 7: Add validation test cases**

In `orchestrator/internal/scenario/detection_profiles_test.go`, add two entries to the `cases` map in `TestValidateExpectation` (after `"bad domain"`, before `"required no find"`):

```go
		"bad outcome family": {ID: "a", Provider: "microsoft_defender", Confidence: ConfidenceOptional, OutcomeFamily: "nope"},
		"bad expected outcome": {ID: "a", Provider: "microsoft_defender", Confidence: ConfidenceOptional, ExpectedOutcome: "Warn"},
```

- [ ] **Step 8: Run the full scenario package test suite**

Run: `go test ./internal/scenario/... -v -count=1`
Expected: PASS, all tests including the two new validation cases and every pre-existing test in the package unchanged.

- [ ] **Step 9: Build check**

Run: `go build ./...`
Expected: clean build, no errors.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/scenario/outcome.go orchestrator/internal/scenario/outcome_test.go orchestrator/internal/scenario/detection.go orchestrator/internal/scenario/detection_profiles.go orchestrator/internal/scenario/detection_profiles_test.go
git commit -m "feat(scenario): outcome catalog vocabulary — OutcomeFamily/ExpectedOutcome fields, registry, resolvers"
```

---

### Task 2: Comparator abstraction in `internal/reporting`

**Files:**
- Create: `orchestrator/internal/reporting/outcome.go`
- Test: `orchestrator/internal/reporting/outcome_test.go` (new)

**Interfaces:**
- Consumes: nothing from Task 1 directly (this task's comparator registry and `ComparisonResult` type are standalone; Task 3 is what wires Task 1's resolvers to Task 2's comparator).
- Produces (for Task 3 to consume):
  - `reporting.ComparisonResult` (string type) with constants `Match`, `Mismatch`, `MissingEvidence`, `NotApplicable`, `Unknown`.
  - `reporting.Comparator` interface: `Compare(expectedOutcome, observedOutcome string) ComparisonResult`.
  - `reporting.RegisterComparator(family string, c Comparator)`, `reporting.comparatorFor(family string) Comparator` (unexported — package-internal use only, by Task 3).
  - `reporting.detectionComparator{}` (unexported type implementing `Comparator`), pre-registered under family `"detection"` via `init()`.
  - `reporting.collapseToStatus(c ComparisonResult) string` — maps `Match→StatusDetected`, `Mismatch→StatusNotDetected`, `NotApplicable→StatusNotApplicable`, else `StatusUnknown`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/reporting/outcome_test.go`:

```go
package reporting

import "testing"

func TestDetectionComparator(t *testing.T) {
	c := detectionComparator{}
	cases := []struct {
		name, expected, observed string
		want                     ComparisonResult
	}{
		{"match", "Detected", "Detected", Match},
		{"mismatch", "Detected", "NotDetected", Mismatch},
		{"missing evidence", "Detected", "", MissingEvidence},
	}
	for _, c2 := range cases {
		if got := c.Compare(c2.expected, c2.observed); got != c2.want {
			t.Errorf("%s: Compare(%q,%q) = %v want %v", c2.name, c2.expected, c2.observed, got, c2.want)
		}
	}
}

func TestComparatorForRegistry(t *testing.T) {
	if _, ok := comparatorFor("detection").(detectionComparator); !ok {
		t.Error("comparatorFor(\"detection\") should return the registered detectionComparator")
	}
	// An unregistered family falls back to a no-op comparator that always
	// reports Unknown — never silently treated as a match or mismatch.
	if got := comparatorFor("nonexistent-family").Compare("X", "X"); got != Unknown {
		t.Errorf("unregistered family: got %v want Unknown", got)
	}
}

func TestRegisterComparator(t *testing.T) {
	RegisterComparator("test-only", detectionComparator{})
	if _, ok := comparatorFor("test-only").(detectionComparator); !ok {
		t.Error("newly registered comparator should be retrievable")
	}
}

func TestCollapseToStatus(t *testing.T) {
	cases := []struct {
		in   ComparisonResult
		want string
	}{
		{Match, StatusDetected},
		{Mismatch, StatusNotDetected},
		{NotApplicable, StatusNotApplicable},
		{MissingEvidence, StatusUnknown},
		{Unknown, StatusUnknown},
	}
	for _, c := range cases {
		if got := collapseToStatus(c.in); got != c.want {
			t.Errorf("collapseToStatus(%v) = %q want %q", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/reporting/... -run "TestDetectionComparator|TestComparatorForRegistry|TestRegisterComparator|TestCollapseToStatus" -v`
Expected: FAIL — `ComparisonResult`, `Comparator`, `detectionComparator`, `comparatorFor`, `RegisterComparator`, `collapseToStatus`, `Match`/`Mismatch`/etc. undefined.

- [ ] **Step 3: Create `orchestrator/internal/reporting/outcome.go`**

```go
package reporting

import "sync"

// Outcome Validation Framework — Phase A comparison layer.
//
// A Comparator encapsulates one outcome family's comparison semantics: given
// an expected outcome value and an observed outcome value (both opaque
// strings from the family's own vocabulary — see internal/scenario/outcome.go),
// it produces a ComparisonResult. This package never interprets what any
// outcome value means; it only ever asks the family's registered Comparator.
//
// Phase A registers exactly one family, "detection" — the extraction (not
// rewrite) of automaticVerifier's pre-existing binary detected/not-detected
// logic. Status, the field every existing scoring/report code path consumes,
// becomes derived from ComparisonResult via collapseToStatus rather than
// computed independently — binary detection is a specialization of outcome
// validation, not a system running alongside it.

// ComparisonResult is the richer internal verdict a Comparator produces,
// before collapseToStatus reduces it to a Status for existing report code.
type ComparisonResult string

const (
	Match           ComparisonResult = "Match"
	Mismatch        ComparisonResult = "Mismatch"
	MissingEvidence ComparisonResult = "MissingEvidence"
	NotApplicable   ComparisonResult = "NotApplicable"
	Unknown         ComparisonResult = "Unknown"
)

// Comparator compares one outcome family's expected and observed values.
type Comparator interface {
	Compare(expectedOutcome, observedOutcome string) ComparisonResult
}

var (
	comparatorMu       sync.RWMutex
	comparatorRegistry = map[string]Comparator{}
)

// RegisterComparator adds or replaces a family's comparator.
func RegisterComparator(family string, c Comparator) {
	comparatorMu.Lock()
	defer comparatorMu.Unlock()
	comparatorRegistry[family] = c
}

// noopComparator is the fallback for an unregistered family: it never treats
// an unrecognized family as a match or mismatch, only Unknown.
type noopComparator struct{}

func (noopComparator) Compare(string, string) ComparisonResult { return Unknown }

// comparatorFor returns the registered Comparator for family, or a no-op
// Unknown-only comparator if none is registered.
func comparatorFor(family string) Comparator {
	comparatorMu.RLock()
	defer comparatorMu.RUnlock()
	if c, ok := comparatorRegistry[family]; ok {
		return c
	}
	return noopComparator{}
}

// detectionComparator is the "detection" family's Comparator — the binary
// detected/not-detected model every expectation used before this phase.
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

func init() {
	RegisterComparator("detection", detectionComparator{})
}

// collapseToStatus reduces a ComparisonResult to the legacy Status string
// every existing scoring/report code path consumes.
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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/reporting/... -run "TestDetectionComparator|TestComparatorForRegistry|TestRegisterComparator|TestCollapseToStatus" -v`
Expected: PASS (all 4 tests).

- [ ] **Step 5: Run the full reporting package test suite**

Run: `go test ./internal/reporting/... -v -count=1`
Expected: PASS — this task adds a new standalone file with no callers yet, so every pre-existing test must still pass completely unchanged.

- [ ] **Step 6: Build check**

Run: `go build ./...`
Expected: clean build, no errors.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/reporting/outcome.go orchestrator/internal/reporting/outcome_test.go
git commit -m "feat(reporting): ComparisonResult/Comparator abstraction + detection family comparator"
```

---

### Task 3: Refactor `automaticVerifier` to be comparator-driven

**Files:**
- Modify: `orchestrator/internal/reporting/detection_validation.go` (`VerificationResult` struct lines 52-63; `automaticVerifier.Verify` lines 104-131)
- Test: `orchestrator/internal/reporting/detection_validation_test.go` (new `TestBuildDetectionValidationGoldenOutput`; extend `TestAutomaticVerifier`, currently lines 40-69; add `"reflect"` import)

**Interfaces:**
- Consumes:
  - From Task 1: `scenario.ResolveOutcomeFamily`, `scenario.ResolveExpectedOutcome`.
  - From Task 2: `ComparisonResult`, `Match`, `Mismatch`, `comparatorFor`, `collapseToStatus`.
- Produces: `VerificationResult.ExpectedOutcome/ObservedOutcome/Comparison` (new fields), `observeDetectionOutcome(exp, ev) (outcome, source string)` (new unexported function) — nothing downstream of this task consumes these; this is the terminal task of Phase A.

- [ ] **Step 1: Add a golden-output regression test capturing CURRENT behavior, before touching any refactor code**

This is the automated form of the spec's "byte-identical existing reports" acceptance criterion — a full-section snapshot, not just a few spot-checked fields. It must be added and confirmed passing *before* Step 7's `automaticVerifier.Verify` refactor below, so it proves it captures real pre-refactor truth rather than being written to match whatever the new code happens to produce.

In `orchestrator/internal/reporting/detection_validation_test.go`, add (e.g. after `TestUnexpectedDetection`):

```go
func TestBuildDetectionValidationGoldenOutput(t *testing.T) {
	specs := []StepDetectionSpec{
		{
			TechniqueID: "T1003.002",
			ProfileRefs: []scenario.ProfileRef{{Profile: "windows_credential_access", Version: 2}},
			Expected: []scenario.ExpectedDetection{
				endpointExp("ep-match", "microsoft_defender", scenario.ConfidenceRequired),
			},
		},
		{
			TechniqueID: "T1562.001",
			Expected: []scenario.ExpectedDetection{
				endpointExp("ep-mismatch", "microsoft_defender", scenario.ConfidenceRequired),
			},
		},
		{
			TechniqueID: "T1090.001",
			Expected: []scenario.ExpectedDetection{
				{ID: "net-unknown", Provider: "microsoft_sentinel", Type: scenario.DomainNetwork, Verification: scenario.VerificationAutomatic, Confidence: scenario.ConfidenceRequired, Finding: scenario.ExpectedFinding{Title: "t", Severity: "High"}},
			},
		},
		{
			TechniqueID: "T1055",
			Expected: []scenario.ExpectedDetection{
				endpointExp("ep-optional", "crowdstrike", scenario.ConfidenceOptional),
			},
		},
	}
	results := []models.SimulationResult{
		{ID: "T1003.002", DetectionVerdict: "detected", DetectionAlert: &models.DetectionAlert{Provider: "Microsoft Defender"}},
		{ID: "T1562.001", DetectionVerdict: "detected", DetectionAlert: &models.DetectionAlert{Provider: "CrowdStrike Falcon"}},
		{ID: "T1090.001", DetectionVerdict: "detected", DetectionAlert: &models.DetectionAlert{Provider: "Microsoft Sentinel"}},
		{ID: "T1055", DetectionVerdict: "undetected"},
	}

	got := BuildDetectionValidation(specs, results)
	want := DetectionValidationSection{
		HasData:                  true,
		Coverage:                 50,
		VerificationCompleteness: 66.7,
		Overall:                  50,
		TelemetryCompleteness:    0,
		Expected:                 3,
		Verified:                 2,
		Detected:                 1,
		ByDomain: []DomainValidationRow{
			{Domain: "endpoint", Expected: 2, Verified: 2, Detected: 1, Coverage: 50, VerificationCompleteness: 100},
			{Domain: "network", Expected: 1, Verified: 0, Detected: 0, Coverage: 0, VerificationCompleteness: 0},
		},
		Rows: []ExpectationRow{
			{TechniqueID: "T1003.002", ExpectedID: "ep-match", Provider: "Microsoft Defender", Domain: "endpoint", Confidence: "required", Verification: "automatic", Status: "Detected", Source: "Microsoft Defender", WorkflowState: "Approved"},
			{TechniqueID: "T1562.001", ExpectedID: "ep-mismatch", Provider: "Microsoft Defender", Domain: "endpoint", Confidence: "required", Verification: "automatic", Status: "NotDetected", WorkflowState: "Approved"},
			{TechniqueID: "T1090.001", ExpectedID: "net-unknown", Provider: "Microsoft Sentinel", Domain: "network", Confidence: "required", Verification: "automatic", Status: "Unknown", WorkflowState: "Approved"},
			{TechniqueID: "T1055", ExpectedID: "ep-optional", Provider: "CrowdStrike Falcon", Domain: "endpoint", Confidence: "optional", Verification: "automatic", Status: "NotDetected", WorkflowState: "Approved"},
		},
		FalseSilence: []GapFinding{
			{TechniqueID: "T1562.001", Provider: "Microsoft Defender", Domain: "endpoint", Confidence: "required", Severity: "High", Title: "gap: ep-mismatch", Remediation: "fix it"},
		},
		UnexpectedDetections: []UnexpectedDetectionRow{
			{TechniqueID: "T1562.001", Provider: "CrowdStrike Falcon", Severity: "Review", Detail: "A control alerted with no matching expectation for this step — confirm it is intended coverage, not a noisy or duplicate rule."},
		},
		Profiles: []scenario.ProfileRef{
			{Profile: "windows_credential_access", Version: 2},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("golden output changed.\ngot:  %+v\nwant: %+v", got, want)
	}
}
```

Add `"reflect"` to the file's import block (`orchestrator/internal/reporting/detection_validation_test.go`, alongside the existing `testing`/`time`/`models`/`scenario`/`verification` imports).

- [ ] **Step 2: Run the golden test against CURRENT (pre-refactor) code to confirm it's real ground truth**

Run: `go test ./internal/reporting/... -run TestBuildDetectionValidationGoldenOutput -v -count=1`
Expected: PASS. (These exact literal values were derived by actually running this fixture against the current codebase before writing this plan — not hand-calculated — so this should pass immediately. If it doesn't, stop and re-derive the correct values from the actual current output before proceeding; do not adjust the plan's refactor to match a guess.)

- [ ] **Step 3: Commit the golden test on its own, before any refactor code changes**

```bash
git add orchestrator/internal/reporting/detection_validation_test.go
git commit -m "test(reporting): golden-output snapshot of DetectionValidationSection before Outcome Validation Framework refactor"
```

- [ ] **Step 4: Write the new failing test assertions for the outcome fields**

In `orchestrator/internal/reporting/detection_validation_test.go`, replace `TestAutomaticVerifier` (lines 40-69) with the same test plus new assertions on the new fields for every existing case:

```go
func TestAutomaticVerifier(t *testing.T) {
	exp := endpointExp("e1", "microsoft_defender", scenario.ConfidenceRequired)

	// detected by the expected provider → Detected
	r := automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "Microsoft Defender"})
	if r.Status != StatusDetected {
		t.Errorf("detected-match: got %s want Detected", r.Status)
	}
	if r.ExpectedOutcome != "Detected" || r.ObservedOutcome != "Detected" || r.Comparison != Match {
		t.Errorf("detected-match outcome fields: got expected=%q observed=%q comparison=%v", r.ExpectedOutcome, r.ObservedOutcome, r.Comparison)
	}

	// detected by a different provider → NotDetected (the expected one stayed silent)
	r = automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "CrowdStrike Falcon"})
	if r.Status != StatusNotDetected {
		t.Errorf("detected-mismatch: got %s want NotDetected", r.Status)
	}
	if r.ObservedOutcome != "NotDetected" || r.Comparison != Mismatch {
		t.Errorf("detected-mismatch outcome fields: got observed=%q comparison=%v", r.ObservedOutcome, r.Comparison)
	}

	// prevented by the expected control → Detected
	r = automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "prevented", BlockingControl: "Defender ASR"})
	if r.Status != StatusDetected {
		t.Errorf("prevented-match: got %s want Detected", r.Status)
	}
	if r.Comparison != Match {
		t.Errorf("prevented-match comparison: got %v want Match", r.Comparison)
	}

	// undetected → NotDetected
	r = automaticVerifier{}.Verify(exp, StepEvidence{DetectionVerdict: "undetected"})
	if r.Status != StatusNotDetected {
		t.Errorf("undetected: got %s want NotDetected", r.Status)
	}
	if r.ObservedOutcome != "NotDetected" || r.Comparison != Mismatch {
		t.Errorf("undetected outcome fields: got observed=%q comparison=%v", r.ObservedOutcome, r.Comparison)
	}

	// non-endpoint domain is not on-host observable → Unknown
	netExp := scenario.ExpectedDetection{ID: "n", Provider: "microsoft_sentinel", Type: scenario.DomainNetwork, Confidence: scenario.ConfidenceRequired, Finding: scenario.ExpectedFinding{Title: "t", Severity: "High"}}
	r = automaticVerifier{}.Verify(netExp, StepEvidence{DetectionVerdict: "detected", AlertProvider: "Microsoft Defender"})
	if r.Status != StatusUnknown {
		t.Errorf("non-endpoint: got %s want Unknown", r.Status)
	}
	if r.ObservedOutcome != "" || r.Comparison != MissingEvidence {
		t.Errorf("non-endpoint outcome fields: got observed=%q comparison=%v want empty/MissingEvidence", r.ObservedOutcome, r.Comparison)
	}
}
```

- [ ] **Step 5: Run the test to verify it fails**

Run: `go test ./internal/reporting/... -run TestAutomaticVerifier -v`
Expected: FAIL — `VerificationResult` has no field `ExpectedOutcome`/`ObservedOutcome`/`Comparison` yet (compile error).

- [ ] **Step 6: Add the three new fields to `VerificationResult`**

In `orchestrator/internal/reporting/detection_validation.go`, add to the `VerificationResult` struct (after `TechniqueID string`, i.e. after line 62):

```go
	// ExpectedOutcome/ObservedOutcome/Comparison are the Outcome Validation
	// Framework's richer internal computation — not surfaced in any report
	// JSON (ExpectationRow has no equivalent fields). Status remains the only
	// field existing scoring/report code consumes, now derived from Comparison.
	ExpectedOutcome string
	ObservedOutcome string
	Comparison      ComparisonResult
```

- [ ] **Step 7: Replace `automaticVerifier.Verify`'s body**

In `orchestrator/internal/reporting/detection_validation.go`, replace the entire `automaticVerifier.Verify` method (lines 104-131):

```go
func (automaticVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "automatic")
	r.ExpectedOutcome = scenario.ResolveExpectedOutcome(exp)
	r.ObservedOutcome, r.Source = observeDetectionOutcome(exp, ev)
	r.Comparison = comparatorFor(scenario.ResolveOutcomeFamily(exp)).Compare(r.ExpectedOutcome, r.ObservedOutcome)
	r.Status = collapseToStatus(r.Comparison)
	return r
}

// observeDetectionOutcome is automaticVerifier's pre-existing evidence switch,
// extracted verbatim and translated into a (token, source) pair instead of
// setting Status/Source directly. The empty-string token means "not
// observable by this verifier at all" (non-endpoint domain) — distinct from
// the "NotDetected" token, which means "observable, but no matching control
// responded." Collapsing both to the same empty signal would make MissingEvidence
// and Mismatch indistinguishable, breaking today's Unknown-vs-NotDetected split.
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
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `go test ./internal/reporting/... -run TestAutomaticVerifier -v`
Expected: PASS.

- [ ] **Step 9: Run the full reporting package test suite — the acceptance gate**

Run: `go test ./internal/reporting/... -v -count=1`
Expected: PASS, every single test unchanged, including (at minimum) `TestBuildDetectionValidationGoldenOutput` (byte-identical to Step 2's pre-refactor run), `TestBuildDetectionValidationScoring`, `TestBuildDetectionValidationNoExpectations`, `TestBuildDetectionValidationStoreOverlay`, `TestUnexpectedDetection`, and any `html_test.go`/`engine_test.go` tests touching Detection Validation report rendering. A single changed value anywhere in this run is a Phase A regression and must be root-caused before proceeding — do not adjust an existing test's expected value to make it pass; that would mean the refactor changed real behavior, which violates the plan's Global Constraints.

- [ ] **Step 10: Run the full scenario package test suite (confirms Task 1 + Task 3 integrate correctly)**

Run: `go test ./internal/scenario/... -v -count=1`
Expected: PASS.

- [ ] **Step 11: Build check**

Run: `go build ./...`
Expected: clean build, no errors.

- [ ] **Step 12: Commit**

```bash
git add orchestrator/internal/reporting/detection_validation.go orchestrator/internal/reporting/detection_validation_test.go
git commit -m "refactor(reporting): automaticVerifier becomes comparator-driven — binary detection as a specialization of outcome validation"
```

---

## Plan-level acceptance criteria (verify after Task 3)

- [ ] `go build ./...` clean.
- [ ] `go test ./internal/scenario/... ./internal/reporting/... -v -count=1` — 100% pass, zero changed expected values anywhere in either package (the automated form of "byte-identical existing reports").
- [ ] `go vet ./...` clean.
- [ ] Grep confirms no other file references `automaticVerifier`'s old inline switch logic or expects the old (pre-refactor) internal shape — `grep -rn "DetectionVerdict" internal/reporting/detection_validation.go` should show usage only inside `observeDetectionOutcome`.
