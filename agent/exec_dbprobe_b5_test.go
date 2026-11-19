package main

import (
	"context"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

// signedStepFor mirrors the step the orchestrator signs for a probe: Command is
// the probe id, the action key is "dbprobe_<class>" and the ExecutionClass is
// the class mapping (expectedExecClass), with the catalog's fixture bound.
func signedStepFor(def dbprobe.ProbeDef) ScenarioStep {
	fixture := def.RequiredFixture
	if def.FixtureParam != "" {
		fixture = "accounts"
	}
	st := testDBProbeStep(func(s *protocol.DBProbeSpec) {
		s.ProbeID, s.FixtureID, s.Params = def.ID, fixture, nil
		if def.FixtureParam != "" {
			s.Params = map[string]string{def.FixtureParam: "accounts"}
		}
	})
	st.ActionKey = "dbprobe_" + string(def.Class)
	st.ExecutionClass = expectedExecClass(def.Class)
	return st
}

// Regression (live run 1): auth_after_revoke was registered as class mutation,
// signed "destructive", and B5 vetoes every destructive step with no approval
// path, so the probe could never run on a real agent. Every registered probe
// must be runnable through the REAL gateStep.
func TestEveryCatalogProbeIsRunnableThroughB5(t *testing.T) {
	for _, id := range dbprobe.ProbeIDs() {
		def, _ := dbprobe.LookupProbe(id)
		if v := gateStep(signedStepFor(def), "test-run"); v != nil {
			t.Errorf("probe %q (class %s, signed %s) is vetoed by gateStep (%s: %s): no registered probe may be unrunnable. "+
				"A true mutation-class probe needs a conscious B5/approval design decision, not a registration",
				id, def.Class, expectedExecClass(def.Class), v.source, v.reason)
		}
	}
}

// Tracing the signed DB-06 / DB-07 steps through gateStep and then the
// executor: the real B5 gate passes them, and the lab/fixture gates still hold.
func TestTask14StepsPassRealGateThenExecutor(t *testing.T) {
	for _, id := range []string{dbprobe.ProbeAuthAfterRevoke, dbprobe.ProbeReadClassifiedFixture} {
		def, _ := dbprobe.LookupProbe(id)
		step := signedStepFor(def)
		if v := gateStep(step, "test-run"); v != nil {
			t.Fatalf("%s vetoed by real gateStep: %s %s", id, v.source, v.reason)
		}
		// The agent-local allowance is still required after B5.
		t.Setenv(envDBProbeLabMutationAllows, "")
		bf := setupBinderFake(t)
		if out, _ := executeDBProbe(context.Background(), step); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: ran without the agent-local lab-mutation allowance", id)
		}
		t.Setenv(envDBProbeLabMutationAllows, "1")
		bf = setupBinderFake(t)
		out, err := executeDBProbe(context.Background(), step)
		if err != nil || out.GateRefusal != "" || bf.bound.Kind != def.RequiredFixture {
			t.Errorf("%s: err=%v refusal=%q bound=%+v", id, err, out.GateRefusal, bf.bound)
		}
		// Client mode refuses fixture probes whatever their class.
		t.Setenv(envDBProbeClientEnabled, "1")
		cs := step
		sp := *step.DBProbe
		sp.Mode = protocol.DBModeClient
		cs.DBProbe = &sp
		if out, _ := executeDBProbe(context.Background(), cs); out.GateRefusal == "" {
			t.Errorf("%s: client mode accepted", id)
		}
	}
}
