package dbbuild

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/scenario"
)

func yamlUnmarshal(b []byte, v any) error { return yaml.Unmarshal(b, v) }

const repoScenarios = "../../../../scenarios"

var dbScenarioIDs = []string{"dbsim-db01-auth-policy", "dbsim-db02-excessive-grants", "dbsim-db03-unauthorized-access", "dbsim-db04-audit-coverage"}

// DB-04 asks the agent for the audit configuration first and then runs one
// marker-tagged read_roles whose statement the agent reads back from the
// target's audit source. Both steps must compile for either engine, be
// read-only, and carry distinct markers so the audit evidence of one step can
// never be attributed to the other.
func TestDB04AuditCoverageStepsBuildForBothEngines(t *testing.T) {
	eng := scenario.NewEngine(stageDBScenarios(t))
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	sc, ok := eng.Get("dbsim-db04-audit-coverage")
	if !ok {
		t.Fatal("dbsim-db04-audit-coverage not loaded")
	}
	my := labTarget()
	my.Engine, my.Port, my.ExpectedIdentity = "mysql", 3306, "3b0f6e7a-1111-2222-3333-444455556666"
	for _, tgt := range []dbsim.Target{labTarget(), my} {
		steps, err := BuildSteps(context.Background(), sc, opts(tgt))
		if err != nil {
			t.Fatalf("%s: %v", tgt.Engine, err)
		}
		if len(steps) != 2 {
			t.Fatalf("%s: %d steps, want 2", tgt.Engine, len(steps))
		}
		wantProbe := []string{"read_audit_config", "read_roles"}
		wantTech := []string{"T1562", "T1087"}
		markers := map[string]bool{}
		for i, st := range steps {
			var spec dbsim.DBProbeSpec
			if err := json.Unmarshal(st.DBProbe, &spec); err != nil {
				t.Fatal(err)
			}
			if spec.ProbeID != wantProbe[i] || st.Command != wantProbe[i] {
				t.Errorf("%s step %d: probe %q command %q, want %q", tgt.Engine, i, spec.ProbeID, st.Command, wantProbe[i])
			}
			if st.TechniqueID != wantTech[i] {
				t.Errorf("%s step %d: technique %q, want %q", tgt.Engine, i, st.TechniqueID, wantTech[i])
			}
			if st.Executor != "dbprobe" || st.ExecutionClass != scenario.ClassNonDestructive || len(st.Payloads) != 0 || st.Cleanup != "" {
				t.Errorf("%s step %d: shape %+v", tgt.Engine, i, st)
			}
			if len(spec.Params) != 0 {
				t.Errorf("%s step %d: unexpected params %v", tgt.Engine, i, spec.Params)
			}
			if markers[spec.Marker] {
				t.Errorf("duplicate marker %q", spec.Marker)
			}
			markers[spec.Marker] = true
		}
	}
}

// stageDBScenarios copies the shipped dbsim YAMLs and their .sig files, byte
// for byte, into a temp builtin scenarios directory, so Load verifies exactly
// the shipped artifacts without depending on any other scenario's state.
func stageDBScenarios(t *testing.T) string {
	t.Helper()
	return stageScenarios(t, allDBScenarioIDs()...)
}

// dbFixtureScenarioIDs are the fixture-reading scenarios (DB-05 read_only, DB-09
// bounded_synthetic). They are kept out of dbScenarioIDs because that list is
// asserted to be read_only/non_destructive end to end, which DB-09 is not.
var dbFixtureScenarioIDs = []string{"dbsim-db05-suspicious-read", "dbsim-db09-bounded-bulk-read",
	"dbsim-db06-account-revocation", "dbsim-db07-sensitive-classification"}

func allDBScenarioIDs() []string {
	return append(append([]string(nil), dbScenarioIDs...), dbFixtureScenarioIDs...)
}

func stageScenarios(t *testing.T, ids ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, id := range ids {
		for _, ext := range []string{".yaml", ".yaml.sig"} {
			b, err := os.ReadFile(filepath.Join(repoScenarios, id+ext))
			if err != nil {
				t.Fatalf("read %s%s: %v", id, ext, err)
			}
			if err := os.WriteFile(filepath.Join(dir, id+ext), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

func TestDBScenariosLoadAndVerifySignature(t *testing.T) {
	if !(integrity.CompiledVerifier{}).SigningEnabled() {
		t.Skip("dev build: signature verification disabled, nothing to prove")
	}
	eng := scenario.NewEngine(stageDBScenarios(t))
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	for _, id := range allDBScenarioIDs() {
		sc, ok := eng.Get(id)
		if !ok {
			t.Fatalf("%s did not load (signature or structure refused)", id)
		}
		if sc.ProductLine != "dbsim" || sc.Source != "builtin" {
			t.Errorf("%s: product line %q source %q", id, sc.ProductLine, sc.Source)
		}
		if len(sc.Steps) == 0 {
			t.Errorf("%s has no steps", id)
		}
	}
}

func TestDBScenarioTamperedYAMLIsRefused(t *testing.T) {
	if !(integrity.CompiledVerifier{}).SigningEnabled() {
		t.Skip("dev build: signature verification disabled")
	}
	dir := stageDBScenarios(t)
	p := filepath.Join(dir, "dbsim-db03-unauthorized-access.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x01
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	if eng.Loaded("dbsim-db03-unauthorized-access") {
		t.Fatal("tampered scenario was loaded")
	}
	if !eng.Loaded("dbsim-db01-auth-policy") {
		t.Fatal("untampered sibling should still load")
	}
}

func TestDBScenarioMissingSigIsRefused(t *testing.T) {
	if !(integrity.CompiledVerifier{}).SigningEnabled() {
		t.Skip("dev build")
	}
	dir := stageDBScenarios(t)
	if err := os.Remove(filepath.Join(dir, "dbsim-db01-auth-policy.yaml.sig")); err != nil {
		t.Fatal(err)
	}
	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	if eng.Loaded("dbsim-db01-auth-policy") {
		t.Fatal("unsigned scenario was loaded")
	}
}

// Every shipped DB scenario compiles against a lab target, and each emitted
// step is classified non-mutating (non_destructive), from the catalog and not
// from anything the YAML says.
func TestDBScenariosClassifiedNonMutating(t *testing.T) {
	eng := scenario.NewEngine(stageDBScenarios(t))
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	for _, id := range dbScenarioIDs {
		sc, ok := eng.Get(id)
		if !ok {
			t.Fatalf("%s not loaded", id)
		}
		steps, err := BuildSteps(context.Background(), sc, opts(labTarget()))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if len(steps) != len(sc.Steps) {
			t.Fatalf("%s: %d steps built from %d", id, len(steps), len(sc.Steps))
		}
		for _, st := range steps {
			if st.ExecutionClass != scenario.ClassNonDestructive {
				t.Errorf("%s/%s: class %q, want non_destructive", id, st.Name, st.ExecutionClass)
			}
			var spec dbsim.DBProbeSpec
			if err := json.Unmarshal(st.DBProbe, &spec); err != nil {
				t.Fatal(err)
			}
			e, _ := dbsim.LookupProbeEntry(spec.ProbeID)
			if e.Class != dbsim.ClassReadOnly {
				t.Errorf("%s/%s: probe %q is %s, shipped DB scenarios must be read_only", id, st.Name, spec.ProbeID, e.Class)
			}
			if st.Command != spec.ProbeID || st.Executor != "dbprobe" || len(st.Payloads) != 0 || st.Cleanup != "" {
				t.Errorf("%s/%s: step shape wrong: %+v", id, st.Name, st)
			}
		}
	}
}

// Shipped DB scenarios are refused when loaded from an operator-writable
// source (custom/): dbprobe steps are vendor-signed content only.
func TestDBProbeScenarioRefusedOutsideBuiltin(t *testing.T) {
	dir := stageDBScenarios(t)
	custom := filepath.Join(dir, "custom")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "dbsim-db01-auth-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(string(b)[len("id: dbsim-db01-auth-policy"):])
	b = append([]byte("id: dbsim-custom-copy"), b...)
	if err := os.WriteFile(filepath.Join(custom, "dbsim-custom-copy.yaml"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	if eng.Loaded("dbsim-custom-copy") {
		t.Fatal("custom scenario with dbprobe steps was loaded")
	}
}
