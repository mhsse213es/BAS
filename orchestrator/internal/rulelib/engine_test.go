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
// mappedGroup names the log-source group a rule belongs to, for counting which groups have field-mapped translations.
func mappedGroup(ls LogSource) string {
	switch {
	case ls.Service != "":
		return ls.Product + "/" + ls.Service
	case ls.Category != "":
		return ls.Product + "/" + ls.Category
	}
	return ls.Product
}

func TestTranslationsRecordMappingPipelineAndDataSource(t *testing.T) {
	e := NewEngine()
	mapped, generic := 0, 0
	mappedByGroup := map[string]int{}
	for _, r := range e.Search(SearchFilter{}) {
		for _, tr := range r.Translations {
			switch tr.Mapping {
			case "pipeline":
				mapped++
				if tr.Pipeline == "" || tr.DataSource == "" {
					t.Fatalf("%s/%s: mapped translation without pipeline/data source", r.ID, tr.Backend)
				}
				switch r.LogSource.Product {
				case "windows", "linux", "macos", "aws", "azure":
				default:
					t.Fatalf("%s/%s: mapped although the log source is %+v", r.ID, tr.Backend, r.LogSource)
				}
				mappedByGroup[mappedGroup(r.LogSource)]++
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
	// Every family the generator maps must have produced field-mapped translations in the shipped bundle.
	for _, g := range []string{
		"windows/process_creation", "windows/network_connection", "windows/ps_script", "windows/registry_set", "windows/file_event",
		"windows/image_load", "windows/security", "windows/system", "windows/ps_module", "linux/process_creation",
		"macos/process_creation", "aws/cloudtrail", "azure/activitylogs", "azure/auditlogs", "azure/signinlogs",
		"windows/dns_query", "windows/registry_event", "windows/registry_delete", "windows/file_delete", "windows/pipe_created",
		"windows/driver_load", "windows/process_access", "windows/create_remote_thread", "windows/ps_classic_start", "windows/windefend",
	} {
		if mappedByGroup[g] == 0 {
			t.Errorf("no field-mapped translations for %s (got %v)", g, mappedByGroup)
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

// QRadar is generated in a separate environment and has no field-mapping pipeline, so every rule must either carry a
// generic AQL query or say why it has none. A QRadar query is never presented as field-mapped.
func TestEmbeddedLibrary_QRadarIsPresentAndAlwaysGeneric(t *testing.T) {
	e := NewEngine()
	withQRadar, failedQRadar := 0, 0
	for _, r := range e.Search(SearchFilter{}) {
		got := false
		for _, tr := range r.Translations {
			if tr.Backend != "qradar" {
				continue
			}
			got = true
			withQRadar++
			if tr.Language != "AQL" || tr.Mapping != "generic" || tr.Pipeline != "" || tr.DataSource != "" || tr.Query == "" || tr.Generator == "" {
				t.Fatalf("%s: qradar translation = %+v, want a generic AQL query with a generator", r.ID, tr)
			}
		}
		for _, f := range r.Failures {
			if f.Backend == "qradar" {
				got = true
				failedQRadar++
				if f.Reason == "" {
					t.Fatalf("%s: qradar failure without a reason", r.ID)
				}
			}
		}
		if !got {
			t.Fatalf("%s has neither a qradar translation nor a recorded failure", r.ID)
		}
	}
	if withQRadar < 1500 {
		t.Errorf("only %d rules have a QRadar query (%d failed); expected most of the library", withQRadar, failedQRadar)
	}
	if e.Metadata().Backends["qradar"] != withQRadar {
		t.Errorf("metadata counts %d qradar translations, the rules hold %d", e.Metadata().Backends["qradar"], withQRadar)
	}
}
