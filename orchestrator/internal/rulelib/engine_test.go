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
