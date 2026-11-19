package main

import (
	"context"
	"sort"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

// plainReadOnly reports whether a probe may run in client mode at all.
func plainReadOnly(d dbprobe.ProbeDef) bool {
	return d.Class == dbprobe.ClassReadOnly && !d.LabOnly && d.FixtureParam == "" && d.RequiredFixture == ""
}

func clientStep(def dbprobe.ProbeDef) ScenarioStep {
	step := signedStepFor(def)
	sp := *step.DBProbe
	sp.Mode = protocol.DBModeClient
	step.DBProbe = &sp
	return step
}

// A client-mode run of anything but a plain read-only probe is refused at the
// agent even with BOTH agent-local allowances set and a perfectly signed step.
// The orchestrator layers have the same-named test in the orchestrator module.
func TestClientRunWithMutationScenarioRefusedAtEveryLayer(t *testing.T) {
	t.Setenv(envDBProbeClientEnabled, "1")
	t.Setenv(envDBProbeLabMutationAllows, "1")
	all := dbprobe.Policy{ClientEnabled: true, LabMutationAllowed: true}

	t.Run("agent_checkspec", func(t *testing.T) {
		for _, id := range dbprobe.ProbeIDs() {
			def, _ := dbprobe.LookupProbe(id)
			if plainReadOnly(def) {
				continue
			}
			s := *clientStep(def).DBProbe
			if err := dbprobe.CheckSpec(s, def, "7001", "7001", all); err == nil {
				t.Errorf("%s: CheckSpec accepted client mode", id)
			}
			// A mislabelled definition cannot launder it: the catalog class wins.
			label := def
			label.Class = dbprobe.ClassReadOnly
			if err := dbprobe.CheckSpec(s, label, "7001", "7001", all); err == nil {
				t.Errorf("%s: a definition mislabelled read_only was accepted", id)
			}
		}
	})

	t.Run("agent_gate_and_executor", func(t *testing.T) {
		for _, id := range dbprobe.ProbeIDs() {
			def, _ := dbprobe.LookupProbe(id)
			if plainReadOnly(def) {
				continue
			}
			bf := setupBinderFake(t)
			step := clientStep(def)
			// B5 itself passes the (correctly signed) step: the refusal below is the dbsim gate.
			if v := gateStep(step, "test-run"); v != nil {
				t.Fatalf("%s: unexpectedly vetoed by B5: %s %s", id, v.source, v.reason)
			}
			out, err := executeDBProbe(context.Background(), step)
			if err != nil || out.GateRefusal == "" || bf.count("Connect") != 0 {
				t.Errorf("%s: executor ran in client mode: err=%v out=%+v", id, err, out)
			}
			// A step re-labelled as a harmless read_only step is refused by what it IS.
			lie := step
			lie.ExecutionClass = expectedExecClass(dbprobe.ClassReadOnly)
			lie.ActionKey = "dbprobe_" + string(dbprobe.ClassReadOnly)
			bf = setupBinderFake(t)
			if out, _ := executeDBProbe(context.Background(), lie); out.GateRefusal == "" || bf.count("Connect") != 0 {
				t.Errorf("%s: a mislabelled step ran in client mode: %+v", id, out)
			}
		}
	})
}

// Exactly the plain read-only probes run in client mode at the executor; the
// control for the test above.
func TestClientModeExecutorRunsOnlyPlainReadOnlyProbes(t *testing.T) {
	t.Setenv(envDBProbeClientEnabled, "1")
	t.Setenv(envDBProbeLabMutationAllows, "1")
	var ran []string
	for _, id := range dbprobe.ProbeIDs() {
		def, _ := dbprobe.LookupProbe(id)
		bf := setupBinderFake(t)
		out, err := executeDBProbe(context.Background(), clientStep(def))
		if err == nil && out.GateRefusal == "" && bf.count("Connect") == 1 {
			ran = append(ran, id)
			if !plainReadOnly(def) {
				t.Errorf("%s ran in client mode but is not a plain read-only probe", id)
			}
		}
	}
	sort.Strings(ran)
	want := []string{"auth_check", "check_readonly_identity", "read_audit_config", "read_grants", "read_restricted_table", "read_roles"}
	if strings.Join(ran, ",") != strings.Join(want, ",") {
		t.Fatalf("client-mode executor ran %v, want %v", ran, want)
	}
}
