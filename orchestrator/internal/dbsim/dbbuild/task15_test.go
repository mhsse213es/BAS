package dbbuild

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

var task15Cases = []struct {
	probe, tech, fixture string
	class                scenario.ExecutionClass
	key                  string
}{
	{"try_disable_audit", "T1562", "empty", scenario.ClassPotentiallyDestructive, "dbprobe_bounded_synthetic"},
	{"try_write_fixture", "T1565.001", "accounts", scenario.ClassPotentiallyDestructive, "dbprobe_bounded_synthetic"},
	{"check_export_privileges", "T1213", "", scenario.ClassNonDestructive, "dbprobe_read_only"},
}

// The signed steps have exactly the shape the agent accepts; none is a
// destructive class (option A: B5 vetoes every destructive step).
func TestTask15StepsMatchAgentShape(t *testing.T) {
	for _, c := range task15Cases {
		for _, eng := range []struct {
			name string
			port int
			id   string
		}{{"postgresql", 5432, "7312345678901234567"}, {"mysql", 3306, "3b0f6e7a-1111-2222-3333-444455556666"}} {
			tgt := labTarget()
			tgt.Engine, tgt.Port, tgt.ExpectedIdentity = eng.name, eng.port, eng.id
			steps, err := BuildSteps(context.Background(), requiredFixtureScenario(c.probe, c.tech, c.fixture, nil), approved(opts(tgt)))
			if err != nil {
				t.Fatalf("%s/%s: %v", c.probe, eng.name, err)
			}
			st := steps[0]
			if st.Executor != "dbprobe" || st.Command != c.probe || len(st.Payloads) != 0 || st.Cleanup != "" ||
				st.ExecutionClass != c.class || st.ActionKey != c.key {
				t.Errorf("%s/%s: shape %+v", c.probe, eng.name, st)
			}
			if st.ExecutionClass == scenario.ClassDestructive {
				t.Errorf("%s: a destructive signed class would be vetoed by B5", c.probe)
			}
			var spec dbsim.DBProbeSpec
			dec := json.NewDecoder(bytes.NewReader(st.DBProbe))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&spec); err != nil {
				t.Fatal(err)
			}
			if spec.ProbeID != c.probe || spec.FixtureID != c.fixture || spec.Mode != dbsim.ModeLab || len(spec.Params) != 0 {
				t.Errorf("%s/%s: spec %+v", c.probe, eng.name, spec)
			}
		}
	}
}

func TestTask15ProbesAreStrict(t *testing.T) {
	build := func(sc *scenario.Scenario, o Options) error {
		_, err := BuildSteps(context.Background(), sc, o)
		return err
	}
	for _, c := range task15Cases {
		if err := build(requiredFixtureScenario(c.probe, c.tech, c.fixture, nil), approved(opts(labTarget()))); err != nil {
			t.Fatalf("%s: valid step refused: %v", c.probe, err)
		}
		for _, fx := range []string{"classified-pii", "edge", "empty", "accounts"} {
			if fx == c.fixture {
				continue
			}
			if build(requiredFixtureScenario(c.probe, c.tech, fx, nil), approved(opts(labTarget()))) == nil {
				t.Errorf("%s: fixture %q accepted", c.probe, fx)
			}
		}
		if c.fixture != "" && build(requiredFixtureScenario(c.probe, c.tech, "", nil), approved(opts(labTarget()))) == nil {
			t.Errorf("%s: built without its fixture", c.probe)
		}
		for _, p := range []string{"table", "statement", "mode", "sql"} {
			if build(requiredFixtureScenario(c.probe, c.tech, c.fixture, map[string]string{p: "x"}), approved(opts(labTarget()))) == nil {
				t.Errorf("%s: parameter %q accepted", c.probe, p)
			}
		}
		// Gating: approval, confirmed lab, and never a client target (R-AS) -
		// including the read_only DB-11.
		if build(requiredFixtureScenario(c.probe, c.tech, c.fixture, nil), opts(labTarget())) == nil {
			t.Errorf("%s: built without scenario mutation approval", c.probe)
		}
		unconfirmed := labTarget()
		unconfirmed.LabConfirmed = false
		if build(requiredFixtureScenario(c.probe, c.tech, c.fixture, nil), approved(opts(unconfirmed))) == nil {
			t.Errorf("%s: built against an unconfirmed lab target", c.probe)
		}
		client := labTarget()
		client.Mode, client.LabConfirmed, client.ReadOnlyIdentityVerified = dbsim.ModeClient, false, true
		o := approved(opts(client))
		o.ClientEnabled = true
		if build(requiredFixtureScenario(c.probe, c.tech, c.fixture, nil), o) == nil {
			t.Errorf("%s: built for a client target", c.probe)
		}
	}
}

var task15ScenarioIDs = []string{"dbsim-db08-audit-tamper-resistance", "dbsim-db10-write-delete-prevention", "dbsim-db11-backup-export-permissions"}

func TestShippedTask15ScenariosBuild(t *testing.T) {
	eng := scenario.NewEngine(stageScenarios(t, task15ScenarioIDs...))
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		probe, fixture string
		class          scenario.ExecutionClass
	}{
		"dbsim-db08-audit-tamper-resistance":   {"try_disable_audit", "empty", scenario.ClassPotentiallyDestructive},
		"dbsim-db10-write-delete-prevention":   {"try_write_fixture", "accounts", scenario.ClassPotentiallyDestructive},
		"dbsim-db11-backup-export-permissions": {"check_export_privileges", "", scenario.ClassNonDestructive},
	}
	for id, w := range want {
		sc, ok := eng.Get(id)
		if !ok {
			t.Fatalf("%s did not load (structure or signature refused)", id)
		}
		if sc.ProductLine != "dbsim" || len(sc.Steps) != 1 || sc.Steps[0].DBProbe != w.probe || sc.Steps[0].DBFixture != w.fixture {
			t.Fatalf("%s: %+v", id, sc.Steps)
		}
		steps, err := BuildSteps(context.Background(), sc, approved(opts(labTarget())))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		var spec dbsim.DBProbeSpec
		if err := json.Unmarshal(steps[0].DBProbe, &spec); err != nil {
			t.Fatal(err)
		}
		if spec.ProbeID != w.probe || spec.FixtureID != w.fixture || steps[0].ExecutionClass != w.class || len(spec.Params) != 0 {
			t.Errorf("%s: %+v class %q", id, spec, steps[0].ExecutionClass)
		}
		if _, err := BuildSteps(context.Background(), sc, opts(labTarget())); err == nil {
			t.Errorf("%s: built without approval", id)
		}
		client := labTarget()
		client.Mode, client.LabConfirmed, client.ReadOnlyIdentityVerified = dbsim.ModeClient, false, true
		o := approved(opts(client))
		o.ClientEnabled = true
		if _, err := BuildSteps(context.Background(), sc, o); err == nil {
			t.Errorf("%s: built for a client target", id)
		}
	}
}
