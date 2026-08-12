package openaev

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

// buildFixtureZip constructs a minimal but realistic OpenAEV export ZIP: one
// entry named "<scenarioName>.json" whose ZipEntry.Comment is "Scenario" —
// matching openaev-main's ImportService.EXPORT_ENTRY_SCENARIO convention,
// which ParseBundle must key off (not the filename).
func buildFixtureZip(t *testing.T, scenarioJSON string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "Ransomware Drill.json", Method: zip.Deflate}
	hdr.Comment = "Scenario"
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write([]byte(scenarioJSON)); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

const fixtureScenarioJSON = `{
  "export_version": 1,
  "scenario_information": {
    "scenario_id": "sc-openaev-001",
    "scenario_name": "Ransomware Drill",
    "scenario_description": "Simulated ransomware kill chain",
    "scenario_category": "ransomware",
    "scenario_severity": "high",
    "scenario_updated_at": "2026-07-10T12:00:00Z"
  },
  "scenario_objectives": [
    {"objective_id": "obj-1", "objective_title": "Detect initial access", "objective_description": "SOC must alert within 15 minutes"}
  ],
  "scenario_injects": [
    {
      "inject_id": "inj-1",
      "inject_title": "Phishing delivery",
      "inject_attack_patterns": [
        {"attack_pattern_external_id": "T1566.001", "attack_pattern_name": "Spearphishing Attachment", "attack_pattern_platforms": ["windows"]}
      ]
    },
    {
      "inject_id": "inj-2",
      "inject_title": "Encrypt files",
      "inject_attack_patterns": [
        {"attack_pattern_external_id": "T1486", "attack_pattern_name": "Data Encrypted for Impact", "attack_pattern_platforms": ["windows", "linux"]}
      ]
    }
  ],
  "scenario_tags": [{"tag_name": "ransomware"}, {"tag_name": "critical-infra"}],
  "scenario_variables": [
    {"variable_key": "target_host", "variable_description": "Primary target hostname"}
  ]
}`

func TestParseBundle_DecodesScenarioAndTechniques(t *testing.T) {
	zipBytes := buildFixtureZip(t, fixtureScenarioJSON)

	parsed, err := ParseBundle(zipBytes)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	if parsed.Scenario.ID != "sc-openaev-001" {
		t.Errorf("scenario ID = %q, want sc-openaev-001", parsed.Scenario.ID)
	}
	if parsed.Scenario.Name != "Ransomware Drill" {
		t.Errorf("scenario name = %q, want Ransomware Drill", parsed.Scenario.Name)
	}
	wantUpdated := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	if !parsed.Scenario.UpdatedAt.Equal(wantUpdated) {
		t.Errorf("updated at = %v, want %v", parsed.Scenario.UpdatedAt, wantUpdated)
	}
	if len(parsed.Injects) != 2 {
		t.Fatalf("injects = %d, want 2", len(parsed.Injects))
	}
	if parsed.Injects[0].AttackPatterns[0].ExternalID != "T1566.001" {
		t.Errorf("first inject technique = %q, want T1566.001", parsed.Injects[0].AttackPatterns[0].ExternalID)
	}
	if len(parsed.Tags) != 2 || parsed.Tags[0].Name != "ransomware" {
		t.Errorf("tags = %+v, want [ransomware critical-infra]", parsed.Tags)
	}
}

func TestParseBundle_MissingScenarioEntry_Errors(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// An entry with no "Scenario" comment — e.g. a stray attachment — must not
	// be mistaken for the scenario JSON.
	w, _ := zw.Create("readme.txt")
	w.Write([]byte("not a scenario"))
	zw.Close()

	if _, err := ParseBundle(buf.Bytes()); err == nil {
		t.Fatal("expected error for a bundle with no Scenario-commented entry, got nil")
	}
}

func TestParseBundle_NotAZip_Errors(t *testing.T) {
	if _, err := ParseBundle([]byte("this is not a zip file")); err == nil {
		t.Fatal("expected error for non-ZIP input, got nil")
	}
}

// buildFixtureExerciseZip mirrors buildFixtureZip but for an Exercise export
// -- entry commented "Exercise" (EXPORT_ENTRY_EXERCISE in openaev-main's
// ImportService.java), exercise_*-prefixed JSON keys.
func buildFixtureExerciseZip(t *testing.T, exerciseJSON string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "Live Fire Drill.json", Method: zip.Deflate}
	hdr.Comment = "Exercise"
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := w.Write([]byte(exerciseJSON)); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

const fixtureExerciseJSON = `{
  "export_version": 1,
  "exercise_information": {
    "exercise_id": "ex-openaev-001",
    "exercise_name": "Live Fire Drill",
    "exercise_description": "Standalone simulation, no parent scenario",
    "exercise_category": "redteam",
    "exercise_severity": "critical",
    "exercise_updated_at": "2026-08-01T09:00:00Z"
  },
  "exercise_objectives": [
    {"objective_id": "obj-e1", "objective_title": "Contain lateral movement", "objective_description": "within 30 minutes"}
  ],
  "exercise_injects": [
    {
      "inject_id": "inj-e1",
      "inject_title": "Credential dump",
      "inject_attack_patterns": [
        {"attack_pattern_external_id": "T1003", "attack_pattern_name": "OS Credential Dumping", "attack_pattern_platforms": ["windows"]}
      ]
    }
  ],
  "exercise_tags": [{"tag_name": "live-fire"}],
  "exercise_variables": [
    {"variable_key": "target_dc", "variable_description": "Domain controller hostname"}
  ]
}`

func TestParseExerciseBundle_DecodesExerciseAndTechniques(t *testing.T) {
	zipBytes := buildFixtureExerciseZip(t, fixtureExerciseJSON)

	parsed, err := ParseExerciseBundle(zipBytes)
	if err != nil {
		t.Fatalf("ParseExerciseBundle: %v", err)
	}
	if parsed.SourceType != "exercise" {
		t.Errorf("SourceType = %q, want exercise", parsed.SourceType)
	}
	if parsed.Scenario.ID != "ex-openaev-001" {
		t.Errorf("ID = %q, want ex-openaev-001", parsed.Scenario.ID)
	}
	if parsed.Scenario.Name != "Live Fire Drill" {
		t.Errorf("Name = %q, want Live Fire Drill", parsed.Scenario.Name)
	}
	if parsed.Scenario.Category != "redteam" || parsed.Scenario.Severity != "critical" {
		t.Errorf("Category/Severity = %q/%q", parsed.Scenario.Category, parsed.Scenario.Severity)
	}
	wantUpdated := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	if !parsed.Scenario.UpdatedAt.Equal(wantUpdated) {
		t.Errorf("UpdatedAt = %v, want %v", parsed.Scenario.UpdatedAt, wantUpdated)
	}
	if len(parsed.Injects) != 1 || parsed.Injects[0].AttackPatterns[0].ExternalID != "T1003" {
		t.Errorf("Injects = %+v", parsed.Injects)
	}
	if len(parsed.Tags) != 1 || parsed.Tags[0].Name != "live-fire" {
		t.Errorf("Tags = %+v", parsed.Tags)
	}
}

func TestParseExerciseBundle_MissingExerciseEntry_Errors(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("readme.txt")
	w.Write([]byte("not an exercise"))
	zw.Close()

	if _, err := ParseExerciseBundle(buf.Bytes()); err == nil {
		t.Fatal("expected error for a bundle with no Exercise-commented entry, got nil")
	}
}

func TestParseExerciseBundle_RejectsScenarioEntry(t *testing.T) {
	// A Scenario-flavored zip (commented "Scenario") must not be silently
	// accepted by the Exercise parser -- the two are visually similar but
	// distinct wire formats, and ScenarioApi vs ExerciseApi are genuinely
	// different OpenAEV objects.
	zipBytes := buildFixtureZip(t, fixtureScenarioJSON)
	if _, err := ParseExerciseBundle(zipBytes); err == nil {
		t.Fatal("expected error when Exercise parser is given a Scenario-commented entry, got nil")
	}
}

func TestMarshalAsScenarioZip_RoundTripsThroughParseBundle(t *testing.T) {
	exerciseZip := buildFixtureExerciseZip(t, fixtureExerciseJSON)
	parsed, err := ParseExerciseBundle(exerciseZip)
	if err != nil {
		t.Fatalf("ParseExerciseBundle: %v", err)
	}
	parsed.Scenario.ID = "exercise:ex-openaev-001" // simulate the provider's ID re-stamp

	synthetic, err := marshalAsScenarioZip(parsed)
	if err != nil {
		t.Fatalf("marshalAsScenarioZip: %v", err)
	}

	roundTripped, err := ParseBundle(synthetic)
	if err != nil {
		t.Fatalf("ParseBundle(synthetic): %v", err)
	}
	if roundTripped.Scenario.ID != "exercise:ex-openaev-001" {
		t.Errorf("round-tripped ID = %q, want exercise:ex-openaev-001", roundTripped.Scenario.ID)
	}
	if roundTripped.Scenario.Name != "Live Fire Drill" {
		t.Errorf("round-tripped Name = %q", roundTripped.Scenario.Name)
	}
	if roundTripped.SourceType != "exercise" {
		t.Errorf("round-tripped SourceType = %q, want exercise (must survive the synthetic-zip round trip)", roundTripped.SourceType)
	}
	if len(roundTripped.Injects) != 1 || roundTripped.Injects[0].AttackPatterns[0].ExternalID != "T1003" {
		t.Errorf("round-tripped Injects = %+v", roundTripped.Injects)
	}
}
