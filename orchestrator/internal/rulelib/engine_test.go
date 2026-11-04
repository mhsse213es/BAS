package rulelib

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

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
	var parts []string
	for _, p := range []string{ls.Product, ls.Service, ls.Category} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "/") // windows/process_creation, azure/activitylogs, proxy, zeek/dns ...
}

func TestTranslationsRecordMappingPipelineAndDataSource(t *testing.T) {
	e := NewEngine()
	mapped, generic, keyword := 0, 0, 0
	mappedByGroup := map[string]int{}
	for _, r := range e.Search(SearchFilter{}) {
		for _, tr := range r.Translations {
			switch tr.Mapping {
			case "pipeline":
				mapped++
				if tr.Pipeline == "" || tr.DataSource == "" {
					t.Fatalf("%s/%s: mapped translation without pipeline/data source", r.ID, tr.Backend)
				}
				switch tr.Verification {
				case "documented", "assumed":
				default:
					t.Fatalf("%s/%s: mapped translation with verification %q (the generator may only say documented or assumed)", r.ID, tr.Backend, tr.Verification)
				}
				if (tr.Verification == "assumed") != strings.Contains(tr.DataSource, "nverified") {
					t.Fatalf("%s/%s: verification %q disagrees with the data-source note %q", r.ID, tr.Backend, tr.Verification, tr.DataSource)
				}
				mappedByGroup[mappedGroup(r.LogSource)]++
			case "keyword":
				// a free-text search: no pipeline and no schema claim, but it must name the log it belongs to
				if tr.Pipeline != "" || tr.DataSource == "" || tr.Verification != "none" || (tr.Backend != "splunk" && tr.Backend != "elastic" && tr.Backend != "microsoft_sentinel") {
					t.Fatalf("%s/%s: malformed keyword translation: %+v", r.ID, tr.Backend, tr)
				}
				keyword++
			case "generic":
				generic++
				if tr.Pipeline != "" || tr.DataSource != "" {
					t.Fatalf("%s/%s: generic translation claims a pipeline or data source", r.ID, tr.Backend)
				}
				if tr.Verification != "none" {
					t.Fatalf("%s/%s: generic translation with verification %q, want none", r.ID, tr.Backend, tr.Verification)
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
		"proxy", "webserver", "dns", "antivirus", "linux/auditd", "cisco/aaa", "okta/okta", "kubernetes/audit", "gcp/gcp.audit",
		"opencanary/application", "bitbucket/audit", "zeek/dns", "zeek/http", "zeek/smb_files", "azure/riskdetection",
		"windows/wmi_event", "windows/sysmon_status", "windows/sysmon_error", "windows/file_executable_detected", "windows/process_tampering",
		"windows/ps_classic_provider_start",
	} {
		if mappedByGroup[g] == 0 {
			t.Errorf("no field-mapped translations for %s (got %v)", g, mappedByGroup)
		}
	}
	if keyword == 0 {
		t.Error("expected keyword translations for the free-text rules")
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

// The Elasticsearch DSL exists to give Sigma's case-insensitive matching to field-mapped Elastic rules. It is
// present only on a field-mapped elastic translation, is valid JSON with a query, and always asks for
// case-insensitive matching somewhere (a DSL with no such clause would be a Lucene query in disguise).
func TestEmbeddedBundle_ElasticDSLInvariants(t *testing.T) {
	e := NewEngine()
	withDSL := 0
	for _, r := range e.Search(SearchFilter{}) {
		for _, tr := range r.Translations {
			if tr.DSL == "" {
				continue
			}
			withDSL++
			if tr.Backend != "elastic" || tr.Mapping != "pipeline" {
				t.Errorf("%s: DSL on a %s/%s translation", r.ID, tr.Backend, tr.Mapping)
			}
			var doc map[string]any
			if err := json.Unmarshal([]byte(tr.DSL), &doc); err != nil || doc["query"] == nil {
				t.Errorf("%s: DSL is not JSON with a query: %v", r.ID, err)
			}
			if dslHasLetterValue(doc) && !strings.Contains(tr.DSL, `"case_insensitive":true`) {
				t.Errorf("%s: DSL has string conditions but never asks for case-insensitive matching", r.ID)
			}
			if tr.Query == "" {
				t.Errorf("%s: the Lucene query must stay beside the DSL", r.ID)
			}
		}
	}
	if withDSL == 0 {
		t.Fatal("no translation carries a DSL")
	}
}

// dslHasLetterValue reports whether any "value" in a DSL document is a string with a letter in it (a pattern such as
// "?*" has nothing to fold, so it needs no case-insensitivity).
func dslHasLetterValue(n any) bool {
	switch v := n.(type) {
	case map[string]any:
		for k, x := range v {
			if s, ok := x.(string); ok && k == "value" {
				if strings.ContainsFunc(s, unicode.IsLetter) {
					return true
				}
			} else if dslHasLetterValue(x) {
				return true
			}
		}
	case []any:
		for _, x := range v {
			if dslHasLetterValue(x) {
				return true
			}
		}
	}
	return false
}

// A pySigma object's repr must never reach a shipped query: it can never match, and a test that builds its events
// from the same rule cannot see it. 40 Elastic queries shipped like that once, because the Lucene backend escapes the
// parenthesis (`SigmaRegularExpression\(`) and the generator's gate only knew the plain form.
var leakedSigmaObject = regexp.MustCompile(`Sigma(?:String|RegularExpression|Number|Bool|CIDR|Null|Expansion|Placeholder|Query)\\?\(|SpecialChars\.`)

func TestEmbeddedBundle_NoQueryContainsALeakedPySigmaObject(t *testing.T) {
	e := NewEngine()
	for _, r := range e.Search(SearchFilter{}) {
		for _, tr := range r.Translations {
			if leakedSigmaObject.MatchString(tr.Query) {
				t.Errorf("%s (%s): the query contains a leaked pySigma object: %.90s", r.ID, tr.Backend, tr.Query)
			}
			if tr.DSL != "" && leakedSigmaObject.MatchString(tr.DSL) {
				t.Errorf("%s (%s): the DSL contains a leaked pySigma object", r.ID, tr.Backend)
			}
		}
	}
}
