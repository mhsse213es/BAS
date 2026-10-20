# Family Content Metadata & Validation Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three structured threat-intelligence-provenance fields to `scenario.Step`, and extend TCF's existing `contentregistry.structuralCheck` with universal validation rules for them — the infrastructure sub-project #10 needs before any new ransomware family content can be onboarded with real provenance metadata, with zero changes to database schema, lifecycle/intake logic, or any existing scenario.

**Architecture:** Three new optional fields (`ThreatIntelSources`, `LastReviewed`, `FamilyAttributionConfidence`) land on `scenario.Step` in `orchestrator/internal/scenario/types.go`. `contentregistry.structuralCheck` (`orchestrator/internal/contentregistry/analyze.go`) gains a new per-step validation helper that is purely a function of `[]scenario.Step` — it never references a scenario ID, a family name, or any specific content set, keeping the package generic. These rules are additive to `problems []string`, exactly how every existing structural rule in that function already works, so content setting none of these fields (every one of the 9 existing scenarios) produces zero new problems and nothing about intake, lifecycle, or execution changes.

**Tech Stack:** Go, `gopkg.in/yaml.v3`, existing `contentregistry`/`scenario` packages — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-12-family-content-metadata-design.md`

## Global Constraints

- No new database columns, no new registry table, no second publication mechanism alongside TCF's existing one.
- No dependency on TCF Phase 2A (unmerged branch, actor/threat identity resolution) — nothing in this plan touches it or requires it.
- None of the 9 existing scenario YAML files on disk are modified by this plan.
- The new validation rules in `structuralCheck` are universal: they apply to any scenario that sets these fields, regardless of content set, and must never contain a hardcoded scenario ID, filename, or family name anywhere in `internal/contentregistry`'s non-test code.
- Passing the new structural checks must never become a runtime gate on intake, registration, or execution. `analysis.structural` stays exactly as diagnostic-only as it is today (written to `content_validations` rows, never read back by `Intake`'s lifecycle decision) — this plan makes **no changes** to `intake.go`'s `SourceBuiltin` branch or any other lifecycle-deciding code.
- The closed-list mandatory-enforcement test for the four future family scenario files (spec section E) is **not written in this plan** — those files don't exist yet, and a test asserting properties of nonexistent files is not real verification. This is a deliberate, correct omission, not a missed task.

## Review Focus

- A step with `family_attribution_confidence: unsourced` but `threat_intel_sources` **non-empty** must NOT be rejected — only the reverse direction (non-`unsourced` with zero sources) is invalid. This is the easiest rule to implement backwards by accident. (Task 2)
- `confirmed` must reject exactly 1 source, not just 0 — the boundary, not just "has none". (Task 2)
- A step that sets **none** of the three new fields — every step in all 9 existing scenarios today — must trigger zero new structural problems. This is the core backward-compatibility guarantee; it gets its own explicit unit test in Task 2, not just reliance on Task 3's real-corpus test. (Task 2, reinforced by Task 3)
- An unrecognized `family_attribution_confidence` string must be rejected even when `threat_intel_sources` is well-formed and numerically sufficient — the enum-membership check must fire independently of (and before) the count-based checks. (Task 2)
- `last_reviewed` must accept a well-formed `YYYY-MM-DD` date and reject both a non-date string and a wrong-format date (e.g. `10/12/2026`, which is syntactically plausible but not the chosen layout). (Task 2)

---

### Task 1: `scenario.Step` schema — three new fields, `ThreatIntelSource` type, confidence constants

**Files:**
- Modify: `orchestrator/internal/scenario/types.go:186-187` (end of the `Step` struct, right after the existing `ExpectedDetections` field)
- Test: `orchestrator/internal/scenario/types_test.go`

**Interfaces:**
- Consumes: nothing from another task.
- Produces: `scenario.Step.ThreatIntelSources []scenario.ThreatIntelSource`, `scenario.Step.LastReviewed string`, `scenario.Step.FamilyAttributionConfidence string`; `scenario.ThreatIntelSource{Reference, URL string}`; the four string constants `scenario.FamilyAttributionUnsourced = "unsourced"`, `scenario.FamilyAttributionInferred = "inferred"`, `scenario.FamilyAttributionReported = "reported"`, `scenario.FamilyAttributionConfirmed = "confirmed"`. Task 2 imports and uses all of these from the `scenario` package.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/scenario/types_test.go` (same package `scenario`, same file that already holds `TestExecutionPolicyJSONRoundTrip`):

```go
func TestStep_ThreatIntelProvenanceFields_YAMLRoundTrip(t *testing.T) {
	sc, err := ParseYAML([]byte(`id: x
name: X
steps:
  - name: s
    technique_id: T1486
    framework: custom
    command: whoami
    threat_intel_sources:
      - reference: "CISA AA23-158A"
        url: "https://www.cisa.gov/example"
      - reference: "Vendor Report X"
    last_reviewed: "2026-10-12"
    family_attribution_confidence: reported
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sc.Steps) != 1 {
		t.Fatalf("got %d steps, want 1", len(sc.Steps))
	}
	step := sc.Steps[0]
	if len(step.ThreatIntelSources) != 2 {
		t.Fatalf("got %d threat_intel_sources, want 2", len(step.ThreatIntelSources))
	}
	if step.ThreatIntelSources[0].Reference != "CISA AA23-158A" || step.ThreatIntelSources[0].URL != "https://www.cisa.gov/example" {
		t.Errorf("source[0] = %+v", step.ThreatIntelSources[0])
	}
	if step.ThreatIntelSources[1].Reference != "Vendor Report X" || step.ThreatIntelSources[1].URL != "" {
		t.Errorf("source[1] = %+v", step.ThreatIntelSources[1])
	}
	if step.LastReviewed != "2026-10-12" {
		t.Errorf("last_reviewed = %q, want 2026-10-12", step.LastReviewed)
	}
	if step.FamilyAttributionConfidence != FamilyAttributionReported {
		t.Errorf("family_attribution_confidence = %q, want %q", step.FamilyAttributionConfidence, FamilyAttributionReported)
	}
}

// TestStep_ThreatIntelProvenanceFields_ZeroValueWhenAbsent is the
// backward-compatibility guarantee at the parse layer: every step in every
// scenario that predates this change sets none of these three fields, and
// must continue to parse to their zero values exactly as before.
func TestStep_ThreatIntelProvenanceFields_ZeroValueWhenAbsent(t *testing.T) {
	sc, err := ParseYAML([]byte(`id: y
name: Y
steps:
  - name: s2
    technique_id: T1486
    framework: custom
    command: whoami
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	legacy := sc.Steps[0]
	if len(legacy.ThreatIntelSources) != 0 || legacy.LastReviewed != "" || legacy.FamilyAttributionConfidence != "" {
		t.Errorf("legacy step got non-zero provenance fields: %+v", legacy)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/scenario/ -run TestStep_ThreatIntelProvenanceFields -v`
Expected: FAIL — compile error, `Step` has no field `ThreatIntelSources` (and `FamilyAttributionReported`/`FamilyAttributionUnsourced` undefined).

- [ ] **Step 3: Write minimal implementation**

In `orchestrator/internal/scenario/types.go`, replace the end of the `Step` struct:

```go
	DetectionProfiles  []string            `yaml:"detection_profiles,omitempty" json:"detectionProfiles,omitempty"`
	ExpectedDetections []ExpectedDetection `yaml:"expected_detection,omitempty" json:"expectedDetections,omitempty"`
}
```

with:

```go
	DetectionProfiles  []string            `yaml:"detection_profiles,omitempty" json:"detectionProfiles,omitempty"`
	ExpectedDetections []ExpectedDetection `yaml:"expected_detection,omitempty" json:"expectedDetections,omitempty"`

	// ── Threat-intelligence provenance (optional) ────────────────────────────
	// ThreatIntelSources cites the source(s) this step's claimed behavior is
	// based on. A step may be based on several sources, and not every source
	// need support every claim -- hence a collection, never a single string.
	// The existing free-text Scenario.Description stays for human narrative;
	// this is the structured, validated counterpart. Mandatory-for-specific-
	// content-sets enforcement (e.g. new ransomware family content) lives
	// outside this package entirely, in whichever test owns that content set.
	ThreatIntelSources []ThreatIntelSource `yaml:"threat_intel_sources,omitempty" json:"threatIntelSources,omitempty"`

	// LastReviewed is an explicit date (YYYY-MM-DD) this step's claimed
	// behavior was last checked against current threat intelligence --
	// distinct from the YAML file's own publication or last-modified time,
	// which reflect editing activity, not intelligence freshness.
	LastReviewed string `yaml:"last_reviewed,omitempty" json:"lastReviewed,omitempty"`

	// FamilyAttributionConfidence is how strongly ThreatIntelSources link
	// THIS SPECIFIC BEHAVIOR to the family this scenario models -- not
	// confidence that the behavior occurs at all, and not confidence that
	// some ransomware family exhibits it generally. One of the
	// FamilyAttribution* constants below.
	FamilyAttributionConfidence string `yaml:"family_attribution_confidence,omitempty" json:"familyAttributionConfidence,omitempty"`
}

// ThreatIntelSource is one citation backing a step's claimed behavior: an
// advisory/report identifier (mandatory) and an optional URL.
type ThreatIntelSource struct {
	Reference string `yaml:"reference"     json:"reference"`
	URL       string `yaml:"url,omitempty" json:"url,omitempty"`
}

// FamilyAttributionConfidence's closed vocabulary: how strongly evidence
// links a step's specific behavior to the family a scenario models.
const (
	// FamilyAttributionUnsourced: author assertion, no citation.
	FamilyAttributionUnsourced = "unsourced"
	// FamilyAttributionInferred: consistent with the family's documented
	// toolset/TTPs generally, but the cited source(s) don't specifically
	// tie this behavior to this family.
	FamilyAttributionInferred = "inferred"
	// FamilyAttributionReported: at least one credible source specifically
	// attributes this behavior to this family.
	FamilyAttributionReported = "reported"
	// FamilyAttributionConfirmed: multiple sources, or a definitive
	// government advisory, specifically attribute this behavior to this
	// family. Structural validation enforces only a minimum citation COUNT
	// (>=2) as a floor -- it cannot verify sources are genuinely independent
	// or credible; that judgment belongs to the human authoring/review step
	// of each family's later content pass.
	FamilyAttributionConfirmed = "confirmed"
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/scenario/ -run TestStep_ThreatIntelProvenanceFields -v`
Expected: PASS (both `TestStep_ThreatIntelProvenanceFields_YAMLRoundTrip` and `TestStep_ThreatIntelProvenanceFields_ZeroValueWhenAbsent`).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/types.go orchestrator/internal/scenario/types_test.go
git commit -m "feat(scenario): add threat-intel provenance fields to Step"
```

---

### Task 2: `contentregistry.structuralCheck` — five new universal validation rules

**Files:**
- Modify: `orchestrator/internal/contentregistry/analyze.go:147-170` (the `structuralCheck` function and its imports)
- Test: `orchestrator/internal/contentregistry/analyze_test.go`

**Interfaces:**
- Consumes: `scenario.Step.ThreatIntelSources`, `.LastReviewed`, `.FamilyAttributionConfidence`, and the four `scenario.FamilyAttribution*` constants from Task 1.
- Produces: `structuralCheck`'s `problems []string` now includes, when triggered: `"invalid family_attribution_confidence value"`, `"non-unsourced family_attribution_confidence requires at least one threat_intel_sources entry"`, `"confirmed family_attribution_confidence requires at least 2 threat_intel_sources entries"`, `"threat_intel_sources entry missing reference"`, `"last_reviewed is not a valid date"`. Task 3's compatibility test relies on none of these ever firing for any of the 9 real scenario files.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/contentregistry/analyze_test.go` (same package `contentregistry`, same direct-call style as the existing `TestAnalyze_*` functions — `analyzeArtifact([]byte(yaml))` then inspect `a.structural`):

```go
func TestAnalyze_FamilyAttributionAllFourValuesValidWhenProperlySourced(t *testing.T) {
	cases := []struct {
		name       string
		confidence string
		sources    string
	}{
		{"unsourced needs none", "unsourced", ""},
		{"inferred needs one", "inferred", `
    threat_intel_sources:
      - reference: "Vendor Report A"`},
		{"reported needs one", "reported", `
    threat_intel_sources:
      - reference: "Vendor Report A"`},
		{"confirmed needs two", "confirmed", `
    threat_intel_sources:
      - reference: "Vendor Report A"
      - reference: "CISA AA23-158A"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yaml := "id: x\nname: X\nsteps:\n  - name: s\n    technique_id: T1486\n    framework: custom\n    command: whoami\n    family_attribution_confidence: " + c.confidence + c.sources + "\n"
			a, err := analyzeArtifact([]byte(yaml))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if a.structural.outcome != "PASS" {
				t.Fatalf("structural = %+v, want PASS", a.structural)
			}
		})
	}
}

func TestAnalyze_FamilyAttributionInvalidValueRejectedRegardlessOfSourceCount(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: x
name: X
steps:
  - name: s
    technique_id: T1486
    framework: custom
    command: whoami
    family_attribution_confidence: definitely
    threat_intel_sources:
      - reference: "Vendor Report A"
      - reference: "CISA AA23-158A"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.structural.outcome != "FAIL" {
		t.Fatalf("structural = %+v, want FAIL", a.structural)
	}
	if !containsProblem(a.structural, "invalid family_attribution_confidence value") {
		t.Errorf("problems = %v, want to contain the invalid-value message", a.structural.detail["problems"])
	}
}

func TestAnalyze_FamilyAttributionNonUnsourcedRequiresAtLeastOneSource(t *testing.T) {
	for _, confidence := range []string{"inferred", "reported", "confirmed"} {
		t.Run(confidence, func(t *testing.T) {
			a, err := analyzeArtifact([]byte("id: x\nname: X\nsteps:\n  - name: s\n    technique_id: T1486\n    framework: custom\n    command: whoami\n    family_attribution_confidence: " + confidence + "\n"))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if a.structural.outcome != "FAIL" {
				t.Fatalf("structural = %+v, want FAIL (zero sources)", a.structural)
			}
			if !containsProblem(a.structural, "non-unsourced family_attribution_confidence requires at least one threat_intel_sources entry") {
				t.Errorf("problems = %v, want to contain the missing-source message", a.structural.detail["problems"])
			}
		})
	}
}

func TestAnalyze_FamilyAttributionConfirmedRejectsExactlyOneSource(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: x
name: X
steps:
  - name: s
    technique_id: T1486
    framework: custom
    command: whoami
    family_attribution_confidence: confirmed
    threat_intel_sources:
      - reference: "Vendor Report A"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.structural.outcome != "FAIL" {
		t.Fatalf("structural = %+v, want FAIL (confirmed with only 1 source)", a.structural)
	}
	if !containsProblem(a.structural, "confirmed family_attribution_confidence requires at least 2 threat_intel_sources entries") {
		t.Errorf("problems = %v, want to contain the confirmed-count message", a.structural.detail["problems"])
	}
}

// TestAnalyze_FamilyAttributionUnsourcedAllowsSourcesToStillBePresent proves
// the rule is one-directional: a step may cite sources for other reasons
// while still rating its OWN family attribution as unsourced. Citing a
// source does not by itself establish family attribution.
func TestAnalyze_FamilyAttributionUnsourcedAllowsSourcesToStillBePresent(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: x
name: X
steps:
  - name: s
    technique_id: T1486
    framework: custom
    command: whoami
    family_attribution_confidence: unsourced
    threat_intel_sources:
      - reference: "Vendor Report A"
      - reference: "CISA AA23-158A"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.structural.outcome != "PASS" {
		t.Fatalf("structural = %+v, want PASS -- unsourced with sources present must not be rejected", a.structural)
	}
}

func TestAnalyze_ThreatIntelSourceEmptyReferenceRejected(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: x
name: X
steps:
  - name: s
    technique_id: T1486
    framework: custom
    command: whoami
    threat_intel_sources:
      - reference: ""
        url: "https://example.com"
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.structural.outcome != "FAIL" {
		t.Fatalf("structural = %+v, want FAIL", a.structural)
	}
	if !containsProblem(a.structural, "threat_intel_sources entry missing reference") {
		t.Errorf("problems = %v, want to contain the missing-reference message", a.structural.detail["problems"])
	}
}

func TestAnalyze_LastReviewedValidation(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"well-formed date accepted", "2026-10-12", false},
		{"non-date string rejected", "not-a-date", true},
		{"wrong-format date rejected", "10/12/2026", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := analyzeArtifact([]byte("id: x\nname: X\nsteps:\n  - name: s\n    technique_id: T1486\n    framework: custom\n    command: whoami\n    last_reviewed: \"" + c.value + "\"\n"))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			wantOutcome := "PASS"
			if c.wantErr {
				wantOutcome = "FAIL"
			}
			if a.structural.outcome != wantOutcome {
				t.Fatalf("structural = %+v, want %s", a.structural, wantOutcome)
			}
			if c.wantErr && !containsProblem(a.structural, "last_reviewed is not a valid date") {
				t.Errorf("problems = %v, want to contain the invalid-date message", a.structural.detail["problems"])
			}
		})
	}
}

// TestAnalyze_StepProvenanceFieldsAllAbsentProducesNoNewProblems is the
// backward-compatibility guarantee at the structural-check layer: a step
// setting none of the three provenance fields -- exactly what every step in
// every one of the 9 real scenarios does today -- must add zero new
// problems, verified directly rather than only through Task 3's real-corpus
// test.
func TestAnalyze_StepProvenanceFieldsAllAbsentProducesNoNewProblems(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: x
name: X
steps:
  - name: s
    technique_id: T1486
    framework: custom
    command: whoami
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.structural.outcome != "PASS" {
		t.Fatalf("structural = %+v, want PASS", a.structural)
	}
	if problems, _ := a.structural.detail["problems"].([]string); len(problems) != 0 {
		t.Errorf("problems = %v, want empty", problems)
	}
}

// containsProblem is a small test helper shared by this file's new cases --
// checkResult.detail["problems"] is a []string by construction (see
// structuralCheck), never anything else.
func containsProblem(cr checkResult, want string) bool {
	problems, _ := cr.detail["problems"].([]string)
	for _, p := range problems {
		if p == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/contentregistry/ -run TestAnalyze_FamilyAttribution -v`
Expected: Every new test using `family_attribution_confidence`/`threat_intel_sources`/`last_reviewed` currently FAILS, because those YAML keys are silently ignored by `yaml.Unmarshal` (no error) and `structuralCheck` has no rule for them yet — so `a.structural.outcome` is `"PASS"` where the test expects `"FAIL"` (the rejection tests), and `containsProblem` returns `false` where the test expects `true`. `TestAnalyze_FamilyAttributionAllFourValuesValidWhenProperlySourced` and `TestAnalyze_FamilyAttributionUnsourcedAllowsSourcesToStillBePresent` and `TestAnalyze_StepProvenanceFieldsAllAbsentProducesNoNewProblems` already pass at this point (they expect PASS, which is already true) — confirm this is the case, then focus on watching the FAIL-expecting tests fail correctly.

- [ ] **Step 3: Write minimal implementation**

In `orchestrator/internal/contentregistry/analyze.go`, add `"time"` to the import block (alongside the existing `crypto/sha256`, `encoding/hex`, `errors`, `fmt`, `regexp`, `sort`, `strings`), then replace `structuralCheck`:

```go
func structuralCheck(sc *scenario.Scenario, techniqueIDs []string) checkResult {
	problems := []string{}
	if !contentIDPattern.MatchString(sc.ID) {
		problems = append(problems, "id is not a valid content id")
	}
	if strings.TrimSpace(sc.Name) == "" {
		problems = append(problems, "name is required")
	}
	for _, id := range techniqueIDs {
		if !techniquePattern.MatchString(id) {
			problems = append(problems, "malformed technique id "+id)
		}
	}
	if !hasExecutionMode(sc) {
		problems = append(problems, "no execution mode")
	}
	out := "PASS"
	if len(problems) > 0 {
		out = "FAIL"
	}
	return checkResult{outcome: out, detail: map[string]any{
		"problems": problems, "technique_ids_checked_against_catalog": false,
	}}
}
```

with:

```go
func structuralCheck(sc *scenario.Scenario, techniqueIDs []string) checkResult {
	problems := []string{}
	if !contentIDPattern.MatchString(sc.ID) {
		problems = append(problems, "id is not a valid content id")
	}
	if strings.TrimSpace(sc.Name) == "" {
		problems = append(problems, "name is required")
	}
	for _, id := range techniqueIDs {
		if !techniquePattern.MatchString(id) {
			problems = append(problems, "malformed technique id "+id)
		}
	}
	if !hasExecutionMode(sc) {
		problems = append(problems, "no execution mode")
	}
	problems = append(problems, stepProvenanceProblems(sc.Steps)...)
	out := "PASS"
	if len(problems) > 0 {
		out = "FAIL"
	}
	return checkResult{outcome: out, detail: map[string]any{
		"problems": problems, "technique_ids_checked_against_catalog": false,
	}}
}

var validFamilyAttributionConfidence = map[string]bool{
	scenario.FamilyAttributionUnsourced: true,
	scenario.FamilyAttributionInferred:  true,
	scenario.FamilyAttributionReported:  true,
	scenario.FamilyAttributionConfirmed: true,
}

// stepProvenanceProblems validates each step's optional threat-intel
// provenance fields. These rules are universal: they apply to any scenario
// using these fields, regardless of content set, and never reference a
// specific scenario id or family name. Whether a given content set is
// REQUIRED to set these fields is enforced by a separate test outside this
// package, scoped to that content set -- never here.
func stepProvenanceProblems(steps []scenario.Step) []string {
	problems := []string{}
	for _, st := range steps {
		for _, src := range st.ThreatIntelSources {
			if strings.TrimSpace(src.Reference) == "" {
				problems = append(problems, "threat_intel_sources entry missing reference")
			}
		}
		if st.LastReviewed != "" {
			if _, err := time.Parse("2006-01-02", st.LastReviewed); err != nil {
				problems = append(problems, "last_reviewed is not a valid date")
			}
		}
		if st.FamilyAttributionConfidence == "" {
			continue
		}
		if !validFamilyAttributionConfidence[st.FamilyAttributionConfidence] {
			problems = append(problems, "invalid family_attribution_confidence value")
			continue
		}
		if st.FamilyAttributionConfidence != scenario.FamilyAttributionUnsourced && len(st.ThreatIntelSources) == 0 {
			problems = append(problems, "non-unsourced family_attribution_confidence requires at least one threat_intel_sources entry")
		}
		if st.FamilyAttributionConfidence == scenario.FamilyAttributionConfirmed && len(st.ThreatIntelSources) < 2 {
			problems = append(problems, "confirmed family_attribution_confidence requires at least 2 threat_intel_sources entries")
		}
	}
	return problems
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/contentregistry/ -run TestAnalyze_ -v`
Expected: PASS — every `TestAnalyze_*` test in the package, old and new.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/contentregistry/analyze.go orchestrator/internal/contentregistry/analyze_test.go
git commit -m "feat(contentregistry): validate threat-intel provenance fields in structuralCheck"
```

---

### Task 3: Real-corpus compatibility test — the 9 existing scenarios are unaffected

**Files:**
- Create: `orchestrator/internal/contentregistry/realcorpus_test.go`

**Interfaces:**
- Consumes: `analyzeArtifact` (package-internal, from `analyze.go`) and `checkResult` (from Task 2).
- Produces: nothing a later task consumes — this is the plan's final content-level proof.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/internal/contentregistry/realcorpus_test.go`:

```go
package contentregistry

import (
	"os"
	"path/filepath"
	"testing"
)

// ransomwareScenarioFiles is the same 9-file list sub-project #9 already
// finalized across five other packages this session (internal/rwdetect,
// internal/rwevidence, internal/rwtaxonomy, internal/api, web/ransomware.js).
// Kept as its own small copy here per that same established convention --
// each package that needs a real-corpus check owns its own list.
var ransomwareScenarioFiles = []string{
	"akira-kill-chain.yaml", "blackcat-kill-chain.yaml", "clop-kill-chain.yaml",
	"lockbit-kill-chain.yaml", "play-kill-chain.yaml", "ransomhub-kill-chain.yaml",
	"ransomware-drill.yaml", "endpoint-mastery/em-07-ransomware-readiness.yaml",
	"linux-ransomware-drill.yaml",
}

func repoScenariosDir(t *testing.T) string {
	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scenarios dir not found at %s: %v", dir, err)
	}
	return dir
}

// TestRealRansomwareCorpus_StillParsesAndStructurallyPasses is this plan's
// compatibility proof: none of the 9 real ransomware scenarios set any of
// the new threat-intel provenance fields, so stepProvenanceProblems (Task 2)
// must add zero new structural problems for any of them -- the existing
// content is completely unaffected by this change.
func TestRealRansomwareCorpus_StillParsesAndStructurallyPasses(t *testing.T) {
	dir := repoScenariosDir(t)
	for _, file := range ransomwareScenarioFiles {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		a, err := analyzeArtifact(b)
		if err != nil {
			t.Fatalf("%s: analyze: %v", file, err)
		}
		if a.structural.outcome != "PASS" {
			t.Errorf("%s: structural = %+v, want PASS", file, a.structural)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails first on a clean baseline, then confirm it passes**

Run: `go test ./internal/contentregistry/ -run TestRealRansomwareCorpus -v`
Expected: PASS immediately — this test does not depend on any code written in this task (Tasks 1-2 are already in place by this point), so there is no RED phase here; it is a pure regression proof over already-correct code. Run it anyway and read the output: a `PASS` for all 9 files is the deliverable. If any file reports `FAIL`, that is a real finding — stop and use `superpowers:systematic-debugging` to find which of Task 2's five rules is firing on real, unrelated content (a false positive in the new validation logic) before proceeding.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/contentregistry/realcorpus_test.go
git commit -m "test(contentregistry): confirm real ransomware corpus unaffected by provenance validation"
```

---

### Task 4: Final regression

**Files:** none (verification only).

**Interfaces:**
- Consumes: everything from Tasks 1-3.
- Produces: nothing — this is the plan's final gate before review.

- [ ] **Step 1: Run the full regression**

`internal/contentregistry`'s `testmain_test.go` calls `testutil.MustSharedTestDB()` in `TestMain`, so that package spins up one Postgres testcontainer regardless of which test runs. `internal/scenario` has no `TestMain` and no DB dependency at all (confirmed by grep: no `sharedDB`/`testcontainers` reference anywhere in that package). Running the two together is therefore only ONE testcontainer total, not two — safe without `-p 1` under this session's host-RAM discipline (that rule applies when 2+ *testcontainer-backed* packages would run concurrently; only one of these two is).

Run: `go test ./internal/scenario/ ./internal/contentregistry/ -v`
Expected: `ok` for both packages, 0 FAIL. Read the full output, not just the final line — confirm every existing test in both packages (not only the new ones from Tasks 1-3) is still green.

- [ ] **Step 2: gofmt check**

Run: `gofmt -l orchestrator/internal/scenario/types.go orchestrator/internal/scenario/types_test.go orchestrator/internal/contentregistry/analyze.go orchestrator/internal/contentregistry/analyze_test.go orchestrator/internal/contentregistry/realcorpus_test.go`
Expected: empty output (no files listed means all are already correctly formatted).

No commit for this task — it is pure verification over Tasks 1-3's already-committed code.
