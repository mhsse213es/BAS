package openaev

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestNormalize_ExtractsTechniquesPlatformsAndCounts(t *testing.T) {
	parsed := &ParsedBundle{
		Scenario: ParsedScenario{
			ID:        "sc-openaev-001",
			Name:      "Ransomware Drill",
			Category:  "ransomware",
			Severity:  "high",
			UpdatedAt: time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		},
		Objectives: []ParsedObjective{
			{Title: "Detect initial access", Description: "SOC must alert within 15 minutes"},
		},
		Injects: []ParsedInject{
			{
				Title: "Phishing delivery",
				AttackPatterns: []ParsedAttackPattern{
					{ExternalID: "T1566.001", Platforms: []string{"windows"}},
				},
			},
			{
				Title: "Encrypt files",
				AttackPatterns: []ParsedAttackPattern{
					{ExternalID: "T1486", Platforms: []string{"windows", "linux"}},
				},
			},
		},
		Tags: []ParsedTag{{Name: "ransomware"}, {Name: "critical-infra"}},
		Variables: []ParsedVariable{
			{Key: "target_host", Description: "Primary target hostname"},
		},
	}

	scenario, detail := Normalize(parsed)

	if scenario.OpenAEVScenarioID != "sc-openaev-001" {
		t.Errorf("ID = %q", scenario.OpenAEVScenarioID)
	}
	if scenario.InjectsCount != 2 {
		t.Errorf("InjectsCount = %d, want 2", scenario.InjectsCount)
	}
	if scenario.ObjectivesCount != 1 {
		t.Errorf("ObjectivesCount = %d, want 1", scenario.ObjectivesCount)
	}

	wantTechniques := []string{"T1486", "T1566.001"}
	gotTechniques := append([]string{}, scenario.TechniqueIDs...)
	sort.Strings(gotTechniques)
	if !reflect.DeepEqual(gotTechniques, wantTechniques) {
		t.Errorf("TechniqueIDs = %v, want %v", gotTechniques, wantTechniques)
	}

	wantPlatforms := []string{"linux", "windows"}
	gotPlatforms := append([]string{}, scenario.Platforms...)
	sort.Strings(gotPlatforms)
	if !reflect.DeepEqual(gotPlatforms, wantPlatforms) {
		t.Errorf("Platforms = %v, want %v", gotPlatforms, wantPlatforms)
	}

	if len(detail.Injects) != 2 || detail.Injects[0].Title != "Phishing delivery" {
		t.Errorf("detail.Injects = %+v", detail.Injects)
	}
	if len(detail.Injects[0].TechniqueIDs) != 1 || detail.Injects[0].TechniqueIDs[0] != "T1566.001" {
		t.Errorf("detail.Injects[0].TechniqueIDs = %v", detail.Injects[0].TechniqueIDs)
	}
}

func TestNormalize_DedupesTechniquesAcrossInjects(t *testing.T) {
	parsed := &ParsedBundle{
		Scenario: ParsedScenario{ID: "sc-x", Name: "X"},
		Injects: []ParsedInject{
			{AttackPatterns: []ParsedAttackPattern{{ExternalID: "T1059"}}},
			{AttackPatterns: []ParsedAttackPattern{{ExternalID: "T1059"}}},
		},
	}
	scenario, _ := Normalize(parsed)
	if len(scenario.TechniqueIDs) != 1 {
		t.Errorf("TechniqueIDs = %v, want exactly one T1059 (deduped)", scenario.TechniqueIDs)
	}
}
