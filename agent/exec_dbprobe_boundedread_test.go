package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

// binderFake adds the FixtureBinder seam to the fixture fake and records when
// the fixture was bound and unbound relative to the other calls.
type binderFake struct {
	*fixtureFakeAdapter
	bound   dbprobe.Fixture
	bindErr error
}

func (b *binderFake) BindFixture(f dbprobe.Fixture) error {
	b.rec("Bind")
	if b.bindErr != nil {
		return b.bindErr
	}
	b.bound = f
	return nil
}

func (b *binderFake) UnbindFixture() { b.rec("Unbind") }

func setupBinderFake(t *testing.T) *binderFake {
	t.Helper()
	bf := &binderFake{fixtureFakeAdapter: &fixtureFakeAdapter{fakeDBAdapter: happyFake(), mode: dbprobe.ModeLab}}
	orig := dbprobeNewAdapter
	dbprobeNewAdapter = func(string) (dbprobe.Adapter, bool) { return bf, true }
	t.Cleanup(func() { dbprobeNewAdapter = orig })
	provisionDBCred(t, "lab-pg-ro", "ro_user", testCredPassword)
	return bf
}

func fixtureReadStep(probe string) ScenarioStep {
	st := testDBProbeStep(func(s *protocol.DBProbeSpec) {
		s.ProbeID = probe
		s.FixtureID = "accounts"
		s.Params = map[string]string{"table": "accounts"}
	})
	// Both fixture probes are bounded_synthetic (R-AI): the run seeds a fixture.
	st.ExecutionClass = "potentially_destructive"
	return st
}

func TestBothFixtureProbesNeedLocalAllowanceAndSignedClass(t *testing.T) {
	for _, probe := range []string{dbprobe.ProbeSuspiciousRead, dbprobe.ProbeBoundedSyntheticRead} {
		t.Setenv(envDBProbeLabMutationAllows, "")
		bf := setupBinderFake(t)
		if out, _ := executeDBProbe(context.Background(), fixtureReadStep(probe)); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: lab mode without the agent-local allowance must be refused before connect: %+v", probe, out)
		}
		t.Setenv(envDBProbeLabMutationAllows, "1")
		st := fixtureReadStep(probe)
		st.ExecutionClass = "non_destructive"
		if out, _ := executeDBProbe(context.Background(), st); out.GateRefusal == "" || bf.count("Connect") != 0 {
			t.Errorf("%s: a non_destructive label must be refused: %+v", probe, out)
		}
		if out, err := executeDBProbe(context.Background(), fixtureReadStep(probe)); err != nil || out.GateRefusal != "" {
			t.Errorf("%s: allowed run refused: err=%v %q", probe, err, out.GateRefusal)
		}
	}
}

// R-AI: even a read_only probe given a fixture id is gated as a mutation.
func TestReadOnlyProbeWithFixtureNeedsAllowance(t *testing.T) {
	t.Setenv(envDBProbeLabMutationAllows, "")
	ff := setupFixtureFake(t)
	// setupFixtureFake enables the allowance for older tests; turn it back off.
	t.Setenv(envDBProbeLabMutationAllows, "")
	out, _ := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if out.GateRefusal == "" || ff.count("Connect") != 0 {
		t.Fatalf("read_roles + fixture without allowance must be refused: %+v", out)
	}
}

func TestFixtureReadBindsActiveFixtureAfterSeedAndUnbindsBeforeCleanup(t *testing.T) {
	t.Setenv(envDBProbeLabMutationAllows, "1")
	bf := setupBinderFake(t)
	out, err := executeDBProbe(context.Background(), fixtureReadStep(dbprobe.ProbeBoundedSyntheticRead))
	if err != nil || out.GateRefusal != "" {
		t.Fatalf("err=%v refusal=%q", err, out.GateRefusal)
	}
	want := "Connect,Identity,Inspect,Seed,Inspect,Bind,RunProbe,Unbind,Cleanup,Inspect,Close"
	if got := strings.Join(bf.calls, ","); got != want {
		t.Fatalf("call order = %s\nwant          %s", got, want)
	}
	if bf.bound.Kind != "accounts" || len(bf.bound.Tables) == 0 || bf.bound.Tables[0].Name != "accounts" || bf.bound.ID == "" {
		t.Fatalf("bound fixture: %+v", bf.bound)
	}
	if out.Result.CleanupStatus != protocol.DBCleanupOK {
		t.Fatalf("cleanup: %+v", out.Result)
	}
}

func TestFixtureReadUnbindsWhenProbeFails(t *testing.T) {
	t.Setenv(envDBProbeLabMutationAllows, "1")
	bf := setupBinderFake(t)
	bf.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		return dbprobe.ProbeResult{}, errors.New("boom")
	}
	_, _ = executeDBProbe(context.Background(), fixtureReadStep(dbprobe.ProbeBoundedSyntheticRead))
	if bf.count("Bind") != 1 || bf.count("Unbind") != 1 {
		t.Fatalf("bind/unbind not paired: %v", bf.calls)
	}
	bf2 := setupBinderFake(t)
	bf2.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		panic("probe exploded")
	}
	_, _ = executeDBProbe(context.Background(), fixtureReadStep(dbprobe.ProbeBoundedSyntheticRead))
	if bf2.count("Bind") != 1 || bf2.count("Unbind") != 1 {
		t.Fatalf("bind/unbind not paired after a panic: %v", bf2.calls)
	}
}

func TestFixtureReadBindFailureRunsNoProbe(t *testing.T) {
	t.Setenv(envDBProbeLabMutationAllows, "1")
	bf := setupBinderFake(t)
	bf.bindErr = errors.New("bad fixture")
	out, err := executeDBProbe(context.Background(), fixtureReadStep(dbprobe.ProbeBoundedSyntheticRead))
	if err == nil {
		t.Fatalf("a failed bind must be an error, got %+v", out)
	}
	if bf.count("RunProbe") != 0 {
		t.Fatalf("probe ran without an active fixture: %v", bf.calls)
	}
	if out.Result.CleanupStatus != protocol.DBCleanupOK || out.Result.SafetyIncident {
		t.Fatalf("teardown must still run and verify: %+v", out.Result)
	}
}

func TestFixtureReadRefusedBeforeConnect(t *testing.T) {
	// Lab mutation allowance off: the bounded_synthetic probe is refused.
	t.Setenv(envDBProbeLabMutationAllows, "")
	bf := setupBinderFake(t)
	out, err := executeDBProbe(context.Background(), fixtureReadStep(dbprobe.ProbeBoundedSyntheticRead))
	if err != nil || out.GateRefusal == "" || bf.count("Connect") != 0 {
		t.Fatalf("err=%v refusal=%q calls=%v", err, out.GateRefusal, bf.calls)
	}
	// The signed class must match the catalog class.
	t.Setenv(envDBProbeLabMutationAllows, "1")
	st := fixtureReadStep(dbprobe.ProbeBoundedSyntheticRead)
	st.ExecutionClass = "non_destructive"
	if out, _ := executeDBProbe(context.Background(), st); out.GateRefusal == "" || bf.count("Connect") != 0 {
		t.Fatalf("mislabelled class accepted: %+v %v", out, bf.calls)
	}
	// No fixture id: refused by spec validation.
	st2 := fixtureReadStep(dbprobe.ProbeSuspiciousRead)
	st2.DBProbe.FixtureID = ""
	if out, _ := executeDBProbe(context.Background(), st2); out.GateRefusal == "" || bf.count("Connect") != 0 {
		t.Fatalf("fixture-aware probe without a fixture id accepted: %+v %v", out, bf.calls)
	}
	// Client mode is refused whatever the class is.
	t.Setenv(envDBProbeClientEnabled, "1")
	st3 := fixtureReadStep(dbprobe.ProbeSuspiciousRead)
	st3.DBProbe.Mode = protocol.DBModeClient
	if out, _ := executeDBProbe(context.Background(), st3); out.GateRefusal == "" || bf.count("Connect") != 0 {
		t.Fatalf("client-mode fixture read accepted: %+v %v", out, bf.calls)
	}
}

func TestFixtureAwareProbeNeedsAFixtureBindingAdapter(t *testing.T) {
	t.Setenv(envDBProbeLabMutationAllows, "1")
	ff := setupFixtureFake(t) // adapter without FixtureBinder
	out, err := executeDBProbe(context.Background(), fixtureReadStep(dbprobe.ProbeBoundedSyntheticRead))
	if err != nil || out.GateRefusal == "" || ff.count("Connect") != 0 {
		t.Fatalf("an adapter that cannot bind a fixture must be refused before connect: err=%v out=%+v calls=%v", err, out, ff.calls)
	}
	if out.Result.ErrorClass != dbErrAdapterUnsupported {
		t.Fatalf("error class %q", out.Result.ErrorClass)
	}
}
