package dlpfixture

import "testing"

func TestFixtureIDForStep_KnownUniqueStepName_ResolvesExactly(t *testing.T) {
	id, ok := FixtureIDForStep("DLP Validation — HTTPS Exfiltration of Visa Card Record (T1567)")
	if !ok {
		t.Fatal("want ok=true for a real catalogued step name")
	}
	if id != "visa-card-record" {
		t.Errorf("id = %q, want %q", id, "visa-card-record")
	}
}

// Review Focus: a step name shared verbatim by several scenario files (the
// BFSI/India anchor's base steps) must still resolve unambiguously, because
// every one of those occurrences belongs to the same fixture.
func TestFixtureIDForStep_SharedStepNameAcrossScenarios_StillResolvesToOneFixture(t *testing.T) {
	id, ok := FixtureIDForStep("DLP Validation — SFTP Exfiltration (T1048.002)")
	if !ok {
		t.Fatal("want ok=true for a step name shared by sftp and multichannel, both bfsi-india-anchor")
	}
	if id != "bfsi-india-anchor" {
		t.Errorf("id = %q, want %q", id, "bfsi-india-anchor")
	}
}

func TestFixtureIDForStep_UnknownStepName_ReturnsFalse(t *testing.T) {
	_, ok := FixtureIDForStep("this step name does not exist in any scenario")
	if ok {
		t.Fatal("want ok=false for an unknown step name")
	}
}

func TestFixtureIDForStep_EmptyStepName_ReturnsFalse(t *testing.T) {
	_, ok := FixtureIDForStep("")
	if ok {
		t.Fatal("want ok=false for an empty step name")
	}
}

// Review Focus: if the same literal step name were ever claimed by two
// DIFFERENT fixtures, the lookup must fail closed (false), never guess.
func TestFixtureIDForStep_AmbiguousAcrossDifferentFixtures_ReturnsFalse(t *testing.T) {
	const sharedName = "synthetic ambiguous step name for this test only"
	a, err := NewFixture("test-fixture-a", "x", []string{"v"}, []Occurrence{{ScenarioID: "scenario-a", StepName: sharedName}}, "note")
	if err != nil {
		t.Fatalf("NewFixture a: %v", err)
	}
	b, err := NewFixture("test-fixture-b", "x", []string{"v"}, []Occurrence{{ScenarioID: "scenario-b", StepName: sharedName}}, "note")
	if err != nil {
		t.Fatalf("NewFixture b: %v", err)
	}
	id, ok := fixtureIDForStepIn([]Fixture{a, b}, sharedName)
	if ok {
		t.Fatalf("want ok=false for a step name ambiguous across two different fixtures, got id=%q", id)
	}
}
