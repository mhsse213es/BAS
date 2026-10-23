package dbbuild

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

func requiredFixtureScenario(probe, technique, fixture string, params map[string]string) *scenario.Scenario {
	return &scenario.Scenario{ID: "dbsim-t", Name: "t", ProductLine: "dbsim", Steps: []scenario.Step{{
		Name: "s1", TechniqueID: technique, Executor: "dbprobe", DBTarget: "lab-db", DBProbe: probe,
		DBParams: params, DBFixture: fixture,
		DBLimits: &scenario.StepDBLimits{MaxRows: 10, TimeoutSec: 30, MaxConns: 1},
	}}}
}

// DB-06 / DB-07 steps are exactly what the agent accepts: Command is the probe
// id, the signed class maps the registry class, the fixed fixture rides in the
// spec and no param (in particular no table) does.
func TestRequiredFixtureStepsMatchAgentShape(t *testing.T) {
	for _, c := range []struct {
		probe, tech, fixture string
		wantClass            scenario.ExecutionClass
		wantKey              string
	}{
		{"auth_after_revoke", "T1078", "empty", scenario.ClassDestructive, "dbprobe_mutation"},
		{"read_classified_fixture", "T1213", "classified-pii", scenario.ClassPotentiallyDestructive, "dbprobe_bounded_synthetic"},
	} {
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
				st.ExecutionClass != c.wantClass || st.ActionKey != c.wantKey {
				t.Errorf("%s/%s: shape %+v", c.probe, eng.name, st)
			}
			var spec dbsim.DBProbeSpec
			dec := json.NewDecoder(bytes.NewReader(st.DBProbe))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&spec); err != nil {
				t.Fatalf("%s/%s: %v", c.probe, eng.name, err)
			}
			if spec.ProbeID != c.probe || spec.FixtureID != c.fixture || spec.Mode != dbsim.ModeLab || len(spec.Params) != 0 {
				t.Errorf("%s/%s: spec %+v", c.probe, eng.name, spec)
			}
		}
	}
}

func TestRequiredFixtureProbesAreStrict(t *testing.T) {
	for _, c := range []struct{ probe, tech, fixture string }{
		{"auth_after_revoke", "T1078", "empty"},
		{"read_classified_fixture", "T1213", "classified-pii"},
	} {
		build := func(sc *scenario.Scenario, o Options) error {
			_, err := BuildSteps(context.Background(), sc, o)
			return err
		}
		if err := build(requiredFixtureScenario(c.probe, c.tech, c.fixture, nil), approved(opts(labTarget()))); err != nil {
			t.Fatalf("%s: valid step refused: %v", c.probe, err)
		}
		for _, fx := range []string{"", "accounts", "edge"} {
			if build(requiredFixtureScenario(c.probe, c.tech, fx, nil), approved(opts(labTarget()))) == nil {
				t.Errorf("%s: fixture %q accepted", c.probe, fx)
			}
		}
		if build(requiredFixtureScenario(c.probe, c.tech, c.fixture, map[string]string{"table": "customers_pii"}), approved(opts(labTarget()))) == nil {
			t.Errorf("%s: a table param was accepted", c.probe)
		}
		// Gating: approval, confirmed lab, and never a client target.
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

func TestShippedDB06DB07ScenariosBuild(t *testing.T) {
	eng := scenario.NewEngine(stageScenarios(t, dbFixtureScenarioIDs...))
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		probe, fixture string
		class          scenario.ExecutionClass
	}{
		"dbsim-db06-account-revocation":        {"auth_after_revoke", "empty", scenario.ClassDestructive},
		"dbsim-db07-sensitive-classification": {"read_classified_fixture", "classified-pii", scenario.ClassPotentiallyDestructive},
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
		if spec.ProbeID != w.probe || spec.FixtureID != w.fixture || steps[0].ExecutionClass != w.class || len(spec.Params) != 0 {
			t.Errorf("%s: %+v class %q", id, spec, steps[0].ExecutionClass)
		}
		if _, err := BuildSteps(context.Background(), sc, opts(labTarget())); err == nil {
			t.Errorf("%s: built without approval", id)
		}
	}
}
