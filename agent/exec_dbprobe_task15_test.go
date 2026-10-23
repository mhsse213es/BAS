package main

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

var task15Probes = []string{dbprobe.ProbeTryDisableAudit, dbprobe.ProbeTryWriteFixture, dbprobe.ProbeCheckExportPrivileges}

// The signed Task 15 steps are pushed through the REAL gateStep (B5) and then
// the executor, the order the live agent applies (a Task 14 lesson: tests that
// call the executor directly missed the B5 veto).
func TestTask15StepsPassRealGateThenExecutor(t *testing.T) {
	for _, id := range task15Probes {
		def, _ := dbprobe.LookupProbe(id)
		step := signedStepFor(def)
		if def.Class == dbprobe.ClassMutation {
			t.Fatalf("%s must not be class mutation", id)
		}
		if v := gateStep(step); v != nil {
			t.Fatalf("%s vetoed by real gateStep: %s %s", id, v.source, v.reason)
		}
		// The agent-local allowance is required after B5, even for the read_only
		// lab-only probe.
		t.Setenv(envDBProbeLabMutationAllows, "")
		bf := setupBinderFake(t)
		if out, _ := executeDBProbe(context.Background(), step); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: ran without the agent-local lab-mutation allowance", id)
		}
		t.Setenv(envDBProbeLabMutationAllows, "1")
		bf = setupBinderFake(t)
		out, err := executeDBProbe(context.Background(), step)
		if err != nil || out.GateRefusal != "" {
			t.Fatalf("%s: err=%v refusal=%q", id, err, out.GateRefusal)
		}
		if def.RequiredFixture != "" {
			want := "Connect,Identity,Inspect,Seed,Inspect,Bind,RunProbe,Unbind,Cleanup,Inspect,Close"
			if got := strings.Join(bf.calls, ","); got != want {
				t.Errorf("%s: call order %s\nwant %s", id, got, want)
			}
			if bf.bound.Kind != def.RequiredFixture || out.Result.CleanupStatus != protocol.DBCleanupOK {
				t.Errorf("%s: bound %+v cleanup %q", id, bf.bound, out.Result.CleanupStatus)
			}
		} else if bf.count("Seed") != 0 || out.Result.CleanupStatus == protocol.DBCleanupOK {
			t.Errorf("%s: a fixture-less probe must not seed: %v", id, bf.calls)
		}
	}
}

func TestMutationProbesRefusedInClientMode(t *testing.T) {
	for _, id := range task15Probes {
		def, _ := dbprobe.LookupProbe(id)
		t.Setenv(envDBProbeLabMutationAllows, "1")
		t.Setenv(envDBProbeClientEnabled, "1")
		bf := setupBinderFake(t)
		step := signedStepFor(def)
		cs := step
		sp := *step.DBProbe
		sp.Mode = protocol.DBModeClient
		cs.DBProbe = &sp
		if out, _ := executeDBProbe(context.Background(), cs); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: client mode accepted: %+v", id, out)
		}
	}
}

func TestTask15StepsRefuseWrongShape(t *testing.T) {
	for _, id := range task15Probes {
		def, _ := dbprobe.LookupProbe(id)
		t.Setenv(envDBProbeLabMutationAllows, "1")
		bf := setupBinderFake(t)
		// Wrong signed class.
		bad := signedStepFor(def)
		bad.ExecutionClass = "destructive"
		if out, _ := executeDBProbe(context.Background(), bad); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: a destructive label accepted", id)
		}
		// Any parameter (a table, a statement, a mode).
		for _, p := range []string{"table", "statement", "sql", "mode", "actual"} {
			st := signedStepFor(def)
			st.DBProbe.Params = map[string]string{p: "x"}
			if out, _ := executeDBProbe(context.Background(), st); out.GateRefusal == "" || bf.count("Connect") != 0 {
				t.Errorf("%s: parameter %q accepted", id, p)
			}
		}
		// Wrong fixture.
		for _, fx := range []string{"classified-pii", "edge"} {
			st := signedStepFor(def)
			st.DBProbe.FixtureID = fx
			if out, _ := executeDBProbe(context.Background(), st); out.GateRefusal == "" || bf.count("Connect") != 0 {
				t.Errorf("%s: fixture %q accepted", id, fx)
			}
		}
	}
}
