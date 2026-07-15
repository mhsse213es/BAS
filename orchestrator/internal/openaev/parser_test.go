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
