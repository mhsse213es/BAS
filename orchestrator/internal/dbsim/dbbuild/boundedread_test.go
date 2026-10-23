package dbbuild

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/scenario"
)

func TestFixtureScenariosTamperedOrUnsignedAreRefused(t *testing.T) {
	if !(integrity.CompiledVerifier{}).SigningEnabled() {
		t.Skip("dev build: signature verification disabled")
	}
	for _, id := range dbFixtureScenarioIDs {
		dir := stageScenarios(t, dbFixtureScenarioIDs...)
		p := filepath.Join(dir, id+".yaml")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)/2] ^= 0x01
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		e := scenario.NewEngine(dir)
		if err := e.Load(); err != nil {
			t.Fatal(err)
		}
		if e.Loaded(id) {
			t.Errorf("%s: tampered scenario was loaded", id)
		}
		dir2 := stageScenarios(t, dbFixtureScenarioIDs...)
		if err := os.Remove(filepath.Join(dir2, id+".yaml.sig")); err != nil {
			t.Fatal(err)
		}
		e2 := scenario.NewEngine(dir2)
		if err := e2.Load(); err != nil {
			t.Fatal(err)
		}
		if e2.Loaded(id) {
			t.Errorf("%s: unsigned scenario was loaded", id)
		}
	}
}

func fixtureScenario(probe, fixture, table string) *scenario.Scenario {
	return &scenario.Scenario{ID: "dbsim-t", Name: "t", ProductLine: "dbsim", Steps: []scenario.Step{{
		Name: "s1", TechniqueID: "T1213", Executor: "dbprobe", DBTarget: "lab-db", DBProbe: probe,
		DBParams: map[string]string{"table": table}, DBFixture: fixture,
		DBLimits: &scenario.StepDBLimits{MaxRows: 5, TimeoutSec: 20, MaxConns: 1},
	}}}
}

func approved(o Options) Options { o.MutationApproved = true; return o }

// The emitted DB-05 / DB-09 steps are exactly what the agent accepts: Command is
// the probe id, the signed class is the mapping of the registry class, the
// fixture id and table param ride in the spec, and nothing executable is attached.
func TestFixtureReadStepsMatchAgentShape(t *testing.T) {
	cases := []struct {
		probe     string
		fixture   string
		table     string
		wantClass scenario.ExecutionClass
		wantKey   string
	}{
		{"suspicious_read", "classified-pii", "customers_pii", scenario.ClassPotentiallyDestructive, "dbprobe_bounded_synthetic"},
		{"bounded_synthetic_read", "accounts", "accounts", scenario.ClassPotentiallyDestructive, "dbprobe_bounded_synthetic"},
	}
	for _, c := range cases {
		for _, eng := range []struct {
			name string
			port int
			id   string
		}{{"postgresql", 5432, "7312345678901234567"}, {"mysql", 3306, "3b0f6e7a-1111-2222-3333-444455556666"}} {
			tgt := labTarget()
			tgt.Engine, tgt.Port, tgt.ExpectedIdentity = eng.name, eng.port, eng.id
			steps, err := BuildSteps(context.Background(), fixtureScenario(c.probe, c.fixture, c.table), approved(opts(tgt)))
			if err != nil {
				t.Fatalf("%s/%s: %v", c.probe, eng.name, err)
			}
			st := steps[0]
			if st.Executor != "dbprobe" || st.Command != c.probe || len(st.Payloads) != 0 || st.Cleanup != "" {
				t.Errorf("%s/%s: shape %+v", c.probe, eng.name, st)
			}
			if st.ExecutionClass != c.wantClass || st.ActionKey != c.wantKey {
				t.Errorf("%s/%s: class %q key %q, want %q %q", c.probe, eng.name, st.ExecutionClass, st.ActionKey, c.wantClass, c.wantKey)
			}
			var spec dbsim.DBProbeSpec
			dec := json.NewDecoder(bytes.NewReader(st.DBProbe))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&spec); err != nil {
				t.Fatalf("%s/%s: spec: %v", c.probe, eng.name, err)
			}
			if spec.ProbeID != c.probe || spec.FixtureID != c.fixture || spec.Params["table"] != c.table || spec.Mode != dbsim.ModeLab {
				t.Errorf("%s/%s: spec %+v", c.probe, eng.name, spec)
			}
			if len(spec.Params) != 1 {
				t.Errorf("%s/%s: unexpected params %v (a schema must never ride in params)", c.probe, eng.name, spec.Params)
			}
			if spec.Limits.MaxRows != 5 || spec.Engine != eng.name {
				t.Errorf("%s/%s: limits/engine %+v", c.probe, eng.name, spec)
			}
		}
	}
}

func TestBoundedSyntheticReadRefusedInClientMode(t *testing.T) {
	tgt := labTarget()
	tgt.Mode, tgt.LabConfirmed, tgt.ReadOnlyIdentityVerified = dbsim.ModeClient, false, true
	o := approved(opts(tgt))
	o.ClientGate = dbsim.StaticClientGate(true)
	for _, probe := range []string{"bounded_synthetic_read", "suspicious_read"} {
		if _, err := BuildSteps(context.Background(), fixtureScenario(probe, "accounts", "accounts"), o); err == nil {
			t.Errorf("%s was built for a client target", probe)
		}
	}
}

func TestBoundedSyntheticReadNeedsApprovalAndConfirmedLab(t *testing.T) {
	sc := fixtureScenario("bounded_synthetic_read", "accounts", "accounts")
	if _, err := BuildSteps(context.Background(), sc, opts(labTarget())); err == nil {
		t.Fatal("built without scenario mutation approval")
	}
	unconfirmed := labTarget()
	unconfirmed.LabConfirmed = false
	if _, err := BuildSteps(context.Background(), sc, approved(opts(unconfirmed))); err == nil {
		t.Fatal("built against an unconfirmed lab target")
	}
	// R-AI: suspicious_read seeds a fixture and is gated identically.
	sr := fixtureScenario("suspicious_read", "classified-pii", "customers_pii")
	if _, err := BuildSteps(context.Background(), sr, opts(labTarget())); err == nil {
		t.Fatal("suspicious_read built without scenario mutation approval")
	}
	if _, err := BuildSteps(context.Background(), sr, approved(opts(unconfirmed))); err == nil {
		t.Fatal("suspicious_read built against an unconfirmed lab target")
	}
	if _, err := BuildSteps(context.Background(), sr, approved(opts(labTarget()))); err != nil {
		t.Fatalf("suspicious_read on an approved lab target: %v", err)
	}
}

// R-AI: even a read_only probe given a db_fixture is refused without the
// controls (the builder never emits a fixture step ungated).
func TestFixtureStepOfReadOnlyProbeNeedsApproval(t *testing.T) {
	sc := oneStepScenario("auth_check", nil)
	sc.Steps[0].DBFixture = "accounts"
	// checkFixture already refuses a fixture on a non fixture-aware probe.
	if _, err := BuildSteps(context.Background(), sc, approved(opts(labTarget()))); err == nil {
		t.Fatal("db_fixture on a read_only probe built")
	}
}

func TestFixtureAwareProbeNeedsFixtureAndTableOnlyThere(t *testing.T) {
	// Missing db_fixture.
	if _, err := BuildSteps(context.Background(), fixtureScenario("suspicious_read", "", "customers_pii"), opts(labTarget())); err == nil {
		t.Fatal("fixture-aware probe built without db_fixture")
	}
	// A schema-qualified or otherwise non-table-name value never reaches a spec.
	for _, tbl := range []string{"dbsim_x.accounts", "public.accounts", "acc ounts", "a;b", "", "`x`", `"x"`} {
		if _, err := BuildSteps(context.Background(), fixtureScenario("suspicious_read", "accounts", tbl), opts(labTarget())); err == nil {
			t.Errorf("table param %q accepted", tbl)
		}
	}
	// A non fixture-aware probe must not carry a fixture: nothing would use it.
	sc := oneStepScenario("auth_check", nil)
	sc.Steps[0].DBFixture = "accounts"
	if _, err := BuildSteps(context.Background(), sc, opts(labTarget())); err == nil {
		t.Fatal("db_fixture accepted on a probe that does not use a fixture")
	}
}

func TestShippedDB05DB09ScenariosBuild(t *testing.T) {
	eng := scenario.NewEngine(stageScenarios(t, dbFixtureScenarioIDs...))
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		probe string
		class scenario.ExecutionClass
	}{
		"dbsim-db05-suspicious-read":   {"suspicious_read", scenario.ClassPotentiallyDestructive},
		"dbsim-db09-bounded-bulk-read": {"bounded_synthetic_read", scenario.ClassPotentiallyDestructive},
	}
	for id, w := range want {
		sc, ok := eng.Get(id)
		if !ok {
			t.Fatalf("%s did not load (structure or signature refused)", id)
		}
		if sc.ProductLine != "dbsim" || len(sc.Steps) != 1 {
			t.Fatalf("%s: line %q steps %d", id, sc.ProductLine, len(sc.Steps))
		}
		steps, err := BuildSteps(context.Background(), sc, approved(opts(labTarget())))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		var spec dbsim.DBProbeSpec
		if err := json.Unmarshal(steps[0].DBProbe, &spec); err != nil {
			t.Fatal(err)
		}
		if spec.ProbeID != w.probe || steps[0].ExecutionClass != w.class || spec.FixtureID == "" || spec.Params["table"] == "" {
			t.Errorf("%s: probe %q class %q fixture %q params %v", id, spec.ProbeID, steps[0].ExecutionClass, spec.FixtureID, spec.Params)
		}
		if strings.Contains(spec.Params["table"], ".") {
			t.Errorf("%s: table param must be a bare table name: %q", id, spec.Params["table"])
		}
		// Both scenarios are refused without the scenario approval.
		if _, err = BuildSteps(context.Background(), sc, opts(labTarget())); err == nil {
			t.Errorf("%s: built without approval", id)
		}
	}
}
