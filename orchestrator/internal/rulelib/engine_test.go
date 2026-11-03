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
	e := loadFromBytes([]byte(`not json`), []byte(`{"schemaVersion": 2}`))
	if e.RuleCount() != 0 {
		t.Fatalf("RuleCount() = %d, want 0 for corrupt rules.json", e.RuleCount())
	}

	e2 := loadFromBytes([]byte(`[]`), []byte(`not json`))
	if e2.RuleCount() != 0 {
		t.Fatalf("RuleCount() = %d, want 0 for corrupt metadata.json", e2.RuleCount())
	}
}

// A translation says whether its query was field-mapped for the SIEM, with which pipeline, and which data source
// the customer must collect for it to match anything. A generic query (log source with no mapping) names neither.
func TestTranslationsRecordMappingPipelineAndDataSource(t *testing.T) {
	e := NewEngine()
	mapped, generic := 0, 0
	for _, r := range e.Search(SearchFilter{}) {
		for _, tr := range r.Translations {
			switch tr.Mapping {
			case "pipeline":
				mapped++
				if tr.Pipeline == "" || tr.DataSource == "" {
					t.Fatalf("%s/%s: mapped translation without pipeline/data source", r.ID, tr.Backend)
				}
				if r.LogSource.Category != "process_creation" || r.LogSource.Product != "windows" {
					t.Fatalf("%s/%s: mapped although the log source is %+v", r.ID, tr.Backend, r.LogSource)
				}
			case "generic":
				generic++
				if tr.Pipeline != "" || tr.DataSource != "" {
					t.Fatalf("%s/%s: generic translation claims a pipeline or data source", r.ID, tr.Backend)
				}
			default:
				t.Fatalf("%s/%s: mapping = %q", r.ID, tr.Backend, tr.Mapping)
			}
		}
	}
	if mapped == 0 || generic == 0 {
		t.Errorf("expected both mapped and generic translations, got %d mapped / %d generic", mapped, generic)
	}
}

// The shipped library is the full SigmaHQ set for the techniques Audspect tests. Every rule must say where it came
// from and under what licence, keep its upstream id, and have an Audspect id that is unique.
func TestEmbeddedLibrary_EveryRuleCarriesProvenanceAndLicence(t *testing.T) {
	e := NewEngine()
	if e.RuleCount() < 1500 {
		t.Fatalf("embedded library has %d rules, want the full set (>= 1500)", e.RuleCount())
	}
	meta := e.Metadata()
	if len(meta.SigmaCommit) != 40 || meta.SourceLicense != "DRL-1.1" || meta.Attribution == "" {
		t.Errorf("metadata provenance missing: commit=%q license=%q attribution set=%v", meta.SigmaCommit, meta.SourceLicense, meta.Attribution != "")
	}
	ids := map[string]bool{}
	for _, r := range e.Search(SearchFilter{}) {
		if ids[r.ID] {
			t.Fatalf("duplicate rule id %s", r.ID)
		}
		ids[r.ID] = true
		if r.SigmaID == "" || r.Title == "" || r.Source.Commit != meta.SigmaCommit || r.Source.License != "DRL-1.1" || r.Source.Path == "" {
			t.Fatalf("rule %s lacks upstream id/title or provenance: %+v", r.ID, r.Source)
		}
	}
}
