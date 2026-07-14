package scenario

import (
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// validExpectation is a minimal required expectation used across tests.
func validExpectation(id string) ExpectedDetection {
	return ExpectedDetection{
		ID:         id,
		Provider:   "microsoft_defender",
		Confidence: ConfidenceRequired,
		Finding:    ExpectedFinding{Title: "t", Severity: "High"},
	}
}

func TestValidateExpectation(t *testing.T) {
	if err := validateExpectation(validExpectation("a")); err != nil {
		t.Fatalf("valid expectation rejected: %v", err)
	}

	cases := map[string]ExpectedDetection{
		"missing id":       {Provider: "microsoft_defender", Confidence: ConfidenceRequired, Finding: ExpectedFinding{Title: "t", Severity: "High"}},
		"unknown provider": {ID: "a", Provider: "nope", Confidence: ConfidenceRequired, Finding: ExpectedFinding{Title: "t", Severity: "High"}},
		"bad confidence":   {ID: "a", Provider: "microsoft_defender", Confidence: "maybe"},
		"bad verification": {ID: "a", Provider: "microsoft_defender", Confidence: ConfidenceOptional, Verification: "psychic"},
		"bad domain":       {ID: "a", Provider: "microsoft_defender", Confidence: ConfidenceOptional, Type: "galaxy"},
		"required no find":  {ID: "a", Provider: "microsoft_defender", Confidence: ConfidenceRequired},
	}
	for name, exp := range cases {
		if err := validateExpectation(exp); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestValidateProfileDuplicateIDs(t *testing.T) {
	p := &DetectionProfile{
		Profile:  "dup",
		Version:  1,
		Expected: []ExpectedDetection{validExpectation("x"), validExpectation("x")},
	}
	if err := validateProfile(p); err == nil {
		t.Fatal("expected duplicate-id error")
	}
}

func TestValidateProfileVersion(t *testing.T) {
	p := &DetectionProfile{Profile: "v0", Version: 0}
	if err := validateProfile(p); err == nil {
		t.Fatal("expected version error for version 0")
	}
}

func TestCheckInheritanceCycle(t *testing.T) {
	all := map[string]*DetectionProfile{
		"a": {Profile: "a", Version: 1, Extends: []string{"b"}},
		"b": {Profile: "b", Version: 1, Extends: []string{"a"}},
	}
	if err := checkInheritance("a", all["a"], all, nil); err == nil {
		t.Fatal("expected circular-extends error")
	}
}

func TestCheckInheritanceUnknownParent(t *testing.T) {
	all := map[string]*DetectionProfile{
		"a": {Profile: "a", Version: 1, Extends: []string{"ghost"}},
	}
	if err := checkInheritance("a", all["a"], all, nil); err == nil {
		t.Fatal("expected unknown-parent error")
	}
}

func TestResolveExpectationsMergeAndInherit(t *testing.T) {
	base := &DetectionProfile{
		Profile:  "base",
		Version:  2,
		Expected: []ExpectedDetection{validExpectation("shared"), validExpectation("base-only")},
	}
	child := &DetectionProfile{
		Profile: "child",
		Version: 3,
		Extends: []string{"base"},
		// Override "shared" with a different provider to prove child wins.
		Expected: []ExpectedDetection{{ID: "shared", Provider: "crowdstrike", Confidence: ConfidenceOptional}},
	}
	profiles := map[string]*DetectionProfile{"base": base, "child": child}

	// Inline expectation overrides everything for its id.
	inline := []ExpectedDetection{{ID: "base-only", Provider: "sentinelone", Confidence: ConfidenceOptional}}

	out, refs := ResolveExpectations([]string{"child"}, inline, profiles)

	if len(out) != 2 {
		t.Fatalf("want 2 merged expectations, got %d", len(out))
	}
	byID := map[string]ExpectedDetection{}
	for _, e := range out {
		byID[e.ID] = e
	}
	if byID["shared"].Provider != "crowdstrike" {
		t.Errorf("child should override base for 'shared', got %q", byID["shared"].Provider)
	}
	if byID["base-only"].Provider != "sentinelone" {
		t.Errorf("inline should override for 'base-only', got %q", byID["base-only"].Provider)
	}
	// Output must be sorted by id for deterministic rendering.
	if out[0].ID != "base-only" || out[1].ID != "shared" {
		t.Errorf("expectations not sorted by id: %q, %q", out[0].ID, out[1].ID)
	}
	// Both profiles contribute refs.
	if len(refs) != 2 {
		t.Fatalf("want 2 profile refs, got %d", len(refs))
	}
}

// TestSeedProfilesLoad loads the real, signed seed profiles from the repo and
// asserts they parse, validate, sign-verify, and that a wired flagship step
// resolves its expectations.
func TestSeedProfilesLoad(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("engine load: %v", err)
	}
	profiles := e.Profiles()
	if len(profiles) == 0 {
		t.Fatal("no detection profiles loaded — signatures missing or invalid?")
	}
	for _, want := range []string{"windows_credential_access", "windows_netsh_portproxy", "windows_kerberoast"} {
		if _, ok := profiles[want]; !ok {
			t.Errorf("expected seed profile %q to be loaded", want)
		}
	}
	// A wired flagship step must resolve non-empty expectations.
	sc, ok := e.Get("volt-typhoon-lotl")
	if !ok {
		t.Fatal("volt-typhoon-lotl scenario did not load (signature stale?)")
	}
	var resolvedAny bool
	for _, step := range sc.Steps {
		if len(step.DetectionProfiles) == 0 {
			continue
		}
		exp, refs := e.ResolveStepExpectations(step)
		if len(exp) == 0 {
			t.Errorf("step %q references profiles %v but resolved 0 expectations", step.TechniqueID, step.DetectionProfiles)
		}
		if len(refs) == 0 {
			t.Errorf("step %q resolved 0 profile refs", step.TechniqueID)
		}
		resolvedAny = true
	}
	if !resolvedAny {
		t.Error("no volt-typhoon step carried detection_profiles")
	}
}

func TestExpectedDetection_RuleIDsRoundTripsThroughYAML(t *testing.T) {
	yamlDoc := []byte(`
profile: test_profile
version: 1
expected_detection:
  - id: exp-1
    provider: microsoft_sentinel
    confidence: required
    rule_ids: ["AUDRULE-000001", "AUDRULE-000002"]
  - id: exp-2
    provider: microsoft_defender
    confidence: recommended
`)
	var p DetectionProfile
	if err := yaml.Unmarshal(yamlDoc, &p); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := p.Expected[0].RuleIDs; len(got) != 2 || got[0] != "AUDRULE-000001" || got[1] != "AUDRULE-000002" {
		t.Fatalf("Expected[0].RuleIDs = %v, want [AUDRULE-000001 AUDRULE-000002]", got)
	}
	if got := p.Expected[1].RuleIDs; len(got) != 0 {
		t.Fatalf("Expected[1].RuleIDs = %v, want empty when rule_ids is omitted", got)
	}
}
