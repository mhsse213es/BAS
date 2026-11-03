package rulelib

import "testing"

func TestNewEngine_LoadsEmbeddedBundle(t *testing.T) {
	e := NewEngine()
	if e.RuleCount() == 0 {
		t.Fatal("expected at least one rule from the embedded ruledata bundle")
	}
	meta := e.Metadata()
	if meta.SchemaVersion != currentSchemaVersion {
		t.Fatalf("Metadata().SchemaVersion = %d, want %d", meta.SchemaVersion, currentSchemaVersion)
	}
}

func TestLoadFromBytes_SchemaVersionMismatch_ReturnsEmptyEngine(t *testing.T) {
	meta := []byte(`{"schemaVersion": 999}`)
	e := loadFromBytes([]byte(`[]`), meta)
	if e.RuleCount() != 0 {
		t.Fatalf("RuleCount() = %d, want 0 for an unsupported schema version", e.RuleCount())
	}
}

func TestLoadFromBytes_CorruptJSON_ReturnsEmptyEngine(t *testing.T) {
	e := loadFromBytes([]byte(`not json`), []byte(`{"schemaVersion": 1}`))
	if e.RuleCount() != 0 {
		t.Fatalf("RuleCount() = %d, want 0 for corrupt rules.json", e.RuleCount())
	}

	e2 := loadFromBytes([]byte(`[]`), []byte(`not json`))
	if e2.RuleCount() != 0 {
		t.Fatalf("RuleCount() = %d, want 0 for corrupt metadata.json", e2.RuleCount())
	}
}

// A translation says whether its query was field-mapped for the SIEM, with which pipeline, and which data source
// the customer must collect for it to match anything. (The generic case, for log sources with no mapping, is
// covered by scripts/rulelib-gen/tests/test_pipelines.py: both seed rules are Windows process-creation.)
func TestTranslationsRecordMappingPipelineAndDataSource(t *testing.T) {
	e := NewEngine()
	for _, id := range []string{"AUDRULE-000001", "AUDRULE-000002"} {
		rule, ok := e.RuleByID(id)
		if !ok {
			t.Fatalf("seed rule %s not found", id)
		}
		if len(rule.Translations) != 5 {
			t.Fatalf("%s: translations = %d, want 5", id, len(rule.Translations))
		}
		for _, tr := range rule.Translations {
			if tr.Mapping != "pipeline" || tr.Pipeline == "" || tr.DataSource == "" {
				t.Errorf("%s/%s: mapping=%q pipeline=%q dataSource=%q, want a mapped translation with a data source", id, tr.Backend, tr.Mapping, tr.Pipeline, tr.DataSource)
			}
		}
	}
}
