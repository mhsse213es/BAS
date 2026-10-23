package main

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

func task14Step(probe, fixture, class string) ScenarioStep {
	st := testDBProbeStep(func(s *protocol.DBProbeSpec) {
		s.ProbeID = probe
		s.FixtureID = fixture
		s.Params = nil
	})
	st.ExecutionClass = class
	return st
}

// The two Task 14 probes carry a fixed fixture and no table param. The executor
// must seed that fixture, bind it to the adapter for the probe, unbind it before
// cleanup, and run the usual verified teardown.
func TestTask14ProbesBindTheirRequiredFixture(t *testing.T) {
	for _, c := range []struct{ probe, fixture, class string }{
		{dbprobe.ProbeAuthAfterRevoke, "empty", "destructive"},
		{dbprobe.ProbeReadClassifiedFixture, "classified-pii", "potentially_destructive"},
	} {
		t.Setenv(envDBProbeLabMutationAllows, "1")
		bf := setupBinderFake(t)
		out, err := executeDBProbe(context.Background(), task14Step(c.probe, c.fixture, c.class))
		if err != nil || out.GateRefusal != "" {
			t.Fatalf("%s: err=%v refusal=%q", c.probe, err, out.GateRefusal)
		}
		want := "Connect,Identity,Inspect,Seed,Inspect,Bind,RunProbe,Unbind,Cleanup,Inspect,Close"
		if got := strings.Join(bf.calls, ","); got != want {
			t.Fatalf("%s: call order = %s\nwant %s", c.probe, got, want)
		}
		if bf.bound.Kind != c.fixture || bf.bound.ID == "" {
			t.Fatalf("%s: bound fixture %+v", c.probe, bf.bound)
		}
		if out.Result.CleanupStatus != protocol.DBCleanupOK || out.Result.SafetyIncident {
			t.Fatalf("%s: %+v", c.probe, out.Result)
		}
	}
}

func TestTask14ProbesGatedBeforeConnect(t *testing.T) {
	for _, c := range []struct{ probe, fixture, class string }{
		{dbprobe.ProbeAuthAfterRevoke, "empty", "destructive"},
		{dbprobe.ProbeReadClassifiedFixture, "classified-pii", "potentially_destructive"},
	} {
		// No agent-local lab mutation allowance.
		t.Setenv(envDBProbeLabMutationAllows, "")
		bf := setupBinderFake(t)
		if out, _ := executeDBProbe(context.Background(), task14Step(c.probe, c.fixture, c.class)); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: no allowance must refuse before connect: %+v", c.probe, out)
		}
		t.Setenv(envDBProbeLabMutationAllows, "1")
		// Wrong signed class.
		if out, _ := executeDBProbe(context.Background(), task14Step(c.probe, c.fixture, "non_destructive")); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: mislabelled class accepted", c.probe)
		}
		// Wrong or missing fixture.
		for _, fx := range []string{"", "accounts"} {
			if out, _ := executeDBProbe(context.Background(), task14Step(c.probe, fx, c.class)); out.GateRefusal == "" || bf.count("Connect") != 0 {
				t.Errorf("%s: fixture %q accepted", c.probe, fx)
			}
		}
		// A free-form table param.
		st := task14Step(c.probe, c.fixture, c.class)
		st.DBProbe.Params = map[string]string{"table": "customers_pii"}
		if out, _ := executeDBProbe(context.Background(), st); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: table param accepted", c.probe)
		}
		// Client mode.
		t.Setenv(envDBProbeClientEnabled, "1")
		st = task14Step(c.probe, c.fixture, c.class)
		st.DBProbe.Mode = protocol.DBModeClient
		if out, _ := executeDBProbe(context.Background(), st); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: client mode accepted", c.probe)
		}
	}
}

func TestTask14ProbeNeedsAFixtureBindingAdapter(t *testing.T) {
	t.Setenv(envDBProbeLabMutationAllows, "1")
	ff := setupFixtureFake(t) // adapter without FixtureBinder
	out, err := executeDBProbe(context.Background(), task14Step(dbprobe.ProbeAuthAfterRevoke, "empty", "destructive"))
	if err != nil || out.GateRefusal == "" || ff.count("Connect") != 0 || out.Result.ErrorClass != dbErrAdapterUnsupported {
		t.Fatalf("err=%v out=%+v calls=%v", err, out, ff.calls)
	}
}

// A lab run that leaves the throwaway account behind is a safety incident, as
// for every fixture.
func TestAuthAfterRevokeResidualIsASafetyIncident(t *testing.T) {
	t.Setenv(envDBProbeLabMutationAllows, "1")
	bf := setupBinderFake(t)
	bf.leftover = []string{"role:dbsim_x_acct"}
	out, err := executeDBProbe(context.Background(), task14Step(dbprobe.ProbeAuthAfterRevoke, "empty", "destructive"))
	if err == nil || !out.Result.SafetyIncident || out.Result.CleanupStatus != protocol.DBCleanupResidual {
		t.Fatalf("a leftover account must be a safety incident: err=%v %+v", err, out.Result)
	}
}
