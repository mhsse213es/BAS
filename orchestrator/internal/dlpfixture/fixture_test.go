package dlpfixture

import "testing"

func TestNewFixture_Valid_Succeeds(t *testing.T) {
	f, err := NewFixture("bfsi-india-anchor", "BFSI/India customer record",
		[]string{"ABCDE1234F"},
		[]Occurrence{{ScenarioID: "dlp-exfiltration-sftp", StepName: "DLP Validation — SFTP Exfiltration (T1048.002)"}},
		"canonical duplicated record")
	if err != nil {
		t.Fatalf("NewFixture: %v", err)
	}
	if f.ID != "bfsi-india-anchor" {
		t.Errorf("ID = %q, want %q", f.ID, "bfsi-india-anchor")
	}
}

func TestNewFixture_EmptyID_Rejected(t *testing.T) {
	_, err := NewFixture("", "x", []string{"v"}, []Occurrence{{ScenarioID: "s", StepName: "n"}}, "note")
	if err == nil {
		t.Fatal("want error for empty id, got nil")
	}
}

func TestNewFixture_EmptyDataType_Rejected(t *testing.T) {
	_, err := NewFixture("id", "", []string{"v"}, []Occurrence{{ScenarioID: "s", StepName: "n"}}, "note")
	if err == nil {
		t.Fatal("want error for empty dataType, got nil")
	}
}

func TestNewFixture_EmptyValues_Rejected(t *testing.T) {
	_, err := NewFixture("id", "x", nil, []Occurrence{{ScenarioID: "s", StepName: "n"}}, "note")
	if err == nil {
		t.Fatal("want error for empty values, got nil")
	}
}

func TestNewFixture_EmptyStringValue_Rejected(t *testing.T) {
	_, err := NewFixture("id", "x", []string{""}, []Occurrence{{ScenarioID: "s", StepName: "n"}}, "note")
	if err == nil {
		t.Fatal("want error for an empty-string value, got nil")
	}
}

func TestNewFixture_EmptyOccurrences_Rejected(t *testing.T) {
	_, err := NewFixture("id", "x", []string{"v"}, nil, "note")
	if err == nil {
		t.Fatal("want error for empty occurrences, got nil")
	}
}

func TestNewFixture_OccurrenceWithEmptyScenarioID_Rejected(t *testing.T) {
	_, err := NewFixture("id", "x", []string{"v"}, []Occurrence{{ScenarioID: "", StepName: "n"}}, "note")
	if err == nil {
		t.Fatal("want error for an occurrence with empty ScenarioID, got nil")
	}
}

func TestNewFixture_OccurrenceWithEmptyStepName_Rejected(t *testing.T) {
	_, err := NewFixture("id", "x", []string{"v"}, []Occurrence{{ScenarioID: "s", StepName: ""}}, "note")
	if err == nil {
		t.Fatal("want error for an occurrence with empty StepName, got nil")
	}
}

// Review Focus: a duplicate occurrence within the same fixture must be
// detected, not just an empty slice.
func TestNewFixture_DuplicateOccurrenceWithinFixture_Rejected(t *testing.T) {
	dup := Occurrence{ScenarioID: "s", StepName: "n"}
	_, err := NewFixture("id", "x", []string{"v"}, []Occurrence{dup, dup}, "note")
	if err == nil {
		t.Fatal("want error for a duplicate occurrence within one fixture, got nil")
	}
}

func TestNewFixture_EmptyNote_Rejected(t *testing.T) {
	_, err := NewFixture("id", "x", []string{"v"}, []Occurrence{{ScenarioID: "s", StepName: "n"}}, "")
	if err == nil {
		t.Fatal("want error for empty note, got nil")
	}
}

func mustFixture(t *testing.T, id string, occs []Occurrence) Fixture {
	t.Helper()
	f, err := NewFixture(id, "x", []string{"v"}, occs, "note")
	if err != nil {
		t.Fatalf("NewFixture: %v", err)
	}
	return f
}

func TestValidateCatalog_NoDuplicates_ReturnsNil(t *testing.T) {
	a := mustFixture(t, "fixture-a", []Occurrence{{ScenarioID: "s1", StepName: "step1"}})
	b := mustFixture(t, "fixture-b", []Occurrence{{ScenarioID: "s2", StepName: "step2"}})
	if err := ValidateCatalog([]Fixture{a, b}); err != nil {
		t.Errorf("ValidateCatalog: %v", err)
	}
}

func TestValidateCatalog_DuplicateFixtureID_Rejected(t *testing.T) {
	a := mustFixture(t, "same-id", []Occurrence{{ScenarioID: "s1", StepName: "step1"}})
	b := mustFixture(t, "same-id", []Occurrence{{ScenarioID: "s2", StepName: "step2"}})
	if err := ValidateCatalog([]Fixture{a, b}); err == nil {
		t.Fatal("want error for a duplicate fixture ID across the catalog, got nil")
	}
}

// Review Focus: two different fixtures must never claim the same
// (ScenarioID, StepName) occurrence -- that would mean two different
// catalog entries disagree about what one real step actually contains.
func TestValidateCatalog_SameOccurrenceClaimedByTwoFixtures_Rejected(t *testing.T) {
	occ := Occurrence{ScenarioID: "s1", StepName: "step1"}
	a := mustFixture(t, "fixture-a", []Occurrence{occ})
	b := mustFixture(t, "fixture-b", []Occurrence{occ})
	if err := ValidateCatalog([]Fixture{a, b}); err == nil {
		t.Fatal("want error for the same occurrence claimed by two different fixtures, got nil")
	}
}
