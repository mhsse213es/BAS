package contentregistry

import "testing"

func TestAnalyze_TechniquesSortedDedupedUpper(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: x
name: X
art_techniques: [t1082, T1059.001]
steps:
  - name: s
    technique_id: T1082
    framework: custom
    command: whoami
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.techniqueIDs; len(got) != 2 || got[0] != "T1059.001" || got[1] != "T1082" {
		t.Fatalf("technique ids = %v", got)
	}
	if a.structural.outcome != "PASS" {
		t.Fatalf("structural = %+v", a.structural)
	}
}

func TestAnalyze_DynamicScopeAndStructuralFailures(t *testing.T) {
	a, err := analyzeArtifact([]byte("id: sweep\nname: S\nart_all_platform: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.dynamicScope != "art_all_platform" || len(a.techniqueIDs) != 0 {
		t.Fatalf("scope=%q ids=%v", a.dynamicScope, a.techniqueIDs)
	}
	if a.structural.outcome != "PASS" {
		t.Fatalf("art_all_platform is a real execution mode: %+v", a.structural)
	}
	bad, err := analyzeArtifact([]byte("id: bad\nart_techniques: [T10]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if bad.structural.outcome != "FAIL" {
		t.Fatalf("missing name + malformed technique must FAIL: %+v", bad.structural)
	}
}

func TestAnalyze_RejectsUnparseableAndMissingID(t *testing.T) {
	if _, err := analyzeArtifact([]byte("id: [unclosed")); err == nil {
		t.Fatal("unparseable YAML must error")
	}
	if _, err := analyzeArtifact([]byte("name: no id\n")); err == nil {
		t.Fatal("missing id must error")
	}
}

func TestAnalyze_DynamicSafetyIsUnresolvedUnlessDestructive(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"dynamic only", "id: d\nname: D\nart_all_platform: true\n", "unresolved"},
		{"static safe plus art_techniques", `id: d
name: D
art_techniques: [T1082]
steps:
  - {name: a, technique_id: T1082, framework: custom, command: x}
`, "unresolved"},
		{"static destructive plus dynamic", `id: d
name: D
art_all_platform: true
steps:
  - {name: b, technique_id: T9999, framework: custom, command: y}
`, "destructive"},
		{"static only stays non_destructive", `id: d
name: D
steps:
  - {name: a, technique_id: T1082, framework: custom, command: x}
`, "non_destructive"},
	}
	for _, c := range cases {
		a, err := analyzeArtifact([]byte(c.yaml))
		if err != nil {
			t.Fatal(err)
		}
		if a.safety.verdict != c.want {
			t.Errorf("%s: verdict = %s, want %s", c.name, a.safety.verdict, c.want)
		}
	}
}

func TestAnalyze_CombinedDynamicModesAllRecorded(t *testing.T) {
	a, err := analyzeArtifact([]byte("id: c\nname: C\nart_all_windows: true\nart_techniques: [T1082]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.dynamicModes) != 2 || a.dynamicModes[0] != "art_all_windows" || a.dynamicModes[1] != "art_techniques" {
		t.Fatalf("modes = %v", a.dynamicModes)
	}
	if a.dynamicScope != "art_all_windows" {
		t.Fatalf("scope = %q", a.dynamicScope)
	}
	n := 0
	for _, d := range a.safety.detail {
		if d["dynamic"] == true {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("safety detail must record every mode: %v", a.safety.detail)
	}
}

func TestAnalyze_SafetyWorstStepWins(t *testing.T) {
	a, err := analyzeArtifact([]byte(`id: s
name: S
steps:
  - {name: a, technique_id: T1082, framework: custom, command: x}
  - {name: b, technique_id: T9999, framework: custom, command: y}
`))
	if err != nil {
		t.Fatal(err)
	}
	// T9999 has no execclass entry -> fails closed to destructive.
	if a.safety.verdict != "destructive" {
		t.Fatalf("verdict = %s", a.safety.verdict)
	}
}

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
