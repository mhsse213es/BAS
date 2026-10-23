package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

// fixtureFakeAdapter adds the fixture seams (ModeReporter, FixtureInspector)
// and scriptable Seed/Cleanup to fakeDBAdapter, recording call order.
type fixtureFakeAdapter struct {
	*fakeDBAdapter
	mode       dbprobe.ExecMode
	state      []string
	leftover   []string
	cleanupErr error
	errClears  bool
	seedErr    error
	seeded     dbprobe.Fixture
	invisible  bool
}

func (f *fixtureFakeAdapter) Mode() dbprobe.ExecMode { return f.mode }

func (f *fixtureFakeAdapter) InspectFixture(context.Context, dbprobe.Fixture) ([]string, error) {
	f.rec("Inspect")
	return append([]string(nil), f.state...), nil
}

func (f *fixtureFakeAdapter) Seed(_ context.Context, fx dbprobe.Fixture) error {
	f.rec("Seed")
	f.seeded = fx
	if f.seedErr != nil {
		return f.seedErr
	}
	if !f.invisible {
		f.state = []string{"schema:dbsim_" + fx.ID}
	}
	return nil
}

func (f *fixtureFakeAdapter) Cleanup(_ context.Context, fx dbprobe.Fixture) (dbprobe.CleanupResult, error) {
	f.rec("Cleanup")
	if f.cleanupErr != nil {
		if f.errClears {
			f.state = nil
		}
		return dbprobe.CleanupResult{Error: f.cleanupErr.Error()}, f.cleanupErr
	}
	f.state = append([]string(nil), f.leftover...)
	return dbprobe.CleanupResult{}, nil
}

func setupFixtureFake(t *testing.T) *fixtureFakeAdapter {
	t.Helper()
	ff := &fixtureFakeAdapter{fakeDBAdapter: happyFake(), mode: dbprobe.ModeLab}
	orig := dbprobeNewAdapter
	dbprobeNewAdapter = func(string) (dbprobe.Adapter, bool) { return ff, true }
	t.Cleanup(func() { dbprobeNewAdapter = orig })
	provisionDBCred(t, "lab-pg-ro", "ro_user", testCredPassword)
	return ff
}

func withFixtureID(id string) func(*protocol.DBProbeSpec) {
	return func(s *protocol.DBProbeSpec) { s.FixtureID = id }
}

func TestDBProbeFixtureIDRefusedInClientModeBeforeConnect(t *testing.T) {
	for _, enabled := range []string{"", "1"} {
		t.Setenv(envDBProbeClientEnabled, enabled)
		ff := setupFixtureFake(t)
		out, err := executeDBProbe(context.Background(), testDBProbeStep(func(s *protocol.DBProbeSpec) {
			s.Mode = protocol.DBModeClient
			s.FixtureID = "accounts"
		}))
		if err != nil || out.GateRefusal == "" {
			t.Fatalf("client mode + fixture must be refused (client enabled=%q): err=%v out=%+v", enabled, err, out)
		}
		if ff.count("Connect") != 0 || ff.count("Seed") != 0 {
			t.Fatalf("adapter reached despite refusal: %v", ff.calls)
		}
	}
}

func TestDBProbeUnknownFixtureNameRefusedBeforeConnect(t *testing.T) {
	ff := setupFixtureFake(t)
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("no-such-fixture")))
	if err != nil || out.GateRefusal == "" {
		t.Fatalf("unknown fixture must be refused: err=%v out=%+v", err, out)
	}
	if !strings.Contains(out.GateRefusal, "fixture") {
		t.Errorf("refusal should name the fixture problem: %s", out.GateRefusal)
	}
	if ff.count("Connect") != 0 {
		t.Fatal("Connect called for an unknown fixture")
	}
}

func TestDBProbeFixtureSeedsProbesCleansInOrder(t *testing.T) {
	ff := setupFixtureFake(t)
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err != nil || out.GateRefusal != "" {
		t.Fatalf("err=%v refusal=%q", err, out.GateRefusal)
	}
	want := "Connect,Identity,Inspect,Seed,Inspect,RunProbe,Cleanup,Inspect,Close"
	if got := strings.Join(ff.calls, ","); got != want {
		t.Fatalf("call order = %s\nwant          %s", got, want)
	}
	if out.Result.CleanupStatus != protocol.DBCleanupOK || out.Result.SafetyIncident {
		t.Fatalf("cleanup fields: %+v", out.Result)
	}
	if out.Result.RowsRead != 3 {
		t.Fatalf("probe result lost: %+v", out.Result)
	}
	if ff.seeded.Kind != "accounts" || len(ff.seeded.Tables) == 0 {
		t.Fatalf("catalog fixture not carried to the adapter: %+v", ff.seeded)
	}
}

func TestDBProbeNoFixtureLeavesCleanupFieldsEmpty(t *testing.T) {
	ff := setupFixtureFake(t)
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.CleanupStatus != "" || out.Result.SafetyIncident {
		t.Fatalf("no fixture requested: %+v", out.Result)
	}
	if ff.count("Seed") != 0 || ff.count("Cleanup") != 0 {
		t.Fatalf("fixture machinery ran without a fixture id: %v", ff.calls)
	}
}

func TestDBProbeCleanupFailureIsSafetyIncidentEvenWhenProbeSucceeded(t *testing.T) {
	cases := map[string]struct {
		mut    func(*fixtureFakeAdapter)
		status string
	}{
		"residual after clean cleanup call": {func(f *fixtureFakeAdapter) { f.leftover = []string{"table:dbsim_x.accounts"} }, protocol.DBCleanupResidual},
		"cleanup error leaves object":       {func(f *fixtureFakeAdapter) { f.cleanupErr = errors.New("drop denied") }, protocol.DBCleanupResidual},
		"cleanup error nothing visible":     {func(f *fixtureFakeAdapter) { f.cleanupErr = errors.New("timeout"); f.errClears = true }, protocol.DBCleanupFailed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ff := setupFixtureFake(t)
			c.mut(ff)
			out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
			if err == nil {
				t.Fatal("a run with a cleanup incident must not report normal completion")
			}
			r := out.Result
			if !r.SafetyIncident || r.CleanupStatus != c.status {
				t.Fatalf("want incident with status %s, got %+v", c.status, r)
			}
			if r.RowsRead != 3 {
				t.Errorf("the probe observation should still be reported: %+v", r)
			}
			if r.ErrorClass == "" {
				t.Error("an incident result must carry an error class so it cannot be read as a clean observation")
			}
			if strings.Contains(err.Error()+strings.Join(r.Notes, " "), testCredPassword) {
				t.Fatal("secret leaked")
			}
			// And through the ExecResult adapter: nonzero exit, DBProbe carries the flag.
			ff.state = nil // the lab account was repaired; the next run starts clean
			er := execDBProbeStep(context.Background(), testDBProbeStep(withFixtureID("accounts")))
			if er.ExitCode == 0 || er.DBProbe == nil || !er.DBProbe.SafetyIncident {
				t.Fatalf("ExecResult must show the incident: %+v", er)
			}
		})
	}
}

func TestDBProbeProbeErrorStillCleansUp(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		return dbprobe.ProbeResult{}, errors.New("boom")
	}
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("probe error must be returned")
	}
	if ff.count("Cleanup") != 1 {
		t.Fatalf("cleanup must run after a probe error: %v", ff.calls)
	}
	if out.Result.CleanupStatus != protocol.DBCleanupOK || out.Result.SafetyIncident {
		t.Fatalf("clean teardown after probe error: %+v", out.Result)
	}
	if out.Result.ErrorClass != dbErrProbe {
		t.Fatalf("probe error class lost: %+v", out.Result)
	}
}

func TestDBProbeSeedNotCreatedIssuesNoCleanupAndIsNotAnIncident(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.seedErr = fmt.Errorf("create failed (already exists): %w", dbprobe.ErrFixtureNotCreated)
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("seed error must surface")
	}
	if ff.count("Cleanup") != 0 || ff.count("RunProbe") != 0 {
		t.Fatalf("no cleanup (no DROP) and no probe when nothing was created: %v", ff.calls)
	}
	r := out.Result
	if r.SafetyIncident || r.CleanupStatus != protocol.DBCleanupNotApplicable || r.ErrorClass != dbErrFixture {
		t.Fatalf("result: %+v", r)
	}
}

func TestDBProbeInvisibleFixtureRefusesProbeAndIsIncident(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.invisible = true
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("expected an error")
	}
	if ff.count("RunProbe") != 0 {
		t.Fatalf("the probe must not run against an unverifiable fixture: %v", ff.calls)
	}
	if ff.count("Cleanup") != 1 {
		t.Fatalf("cleanup must still run: %v", ff.calls)
	}
	r := out.Result
	if !r.SafetyIncident || r.CleanupStatus != protocol.DBCleanupFailed || r.ErrorClass != dbErrFixture {
		t.Fatalf("result: %+v", r)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "fixture not visible to inspection; cleanup cannot be verified") {
		t.Fatalf("notes: %v", r.Notes)
	}
}

// A panic in the probe while cleanup fails reaches the executor as a panic
// carrying the incident; the executor must turn it into a result.
func TestDBProbePanicWithFailedCleanupBecomesIncidentResult(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.leftover = []string{"table:dbsim_x.accounts"}
	ff.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		panic("kaboom")
	}
	step := testDBProbeStep(withFixtureID("accounts"))
	var er protocol.ExecResult
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic escaped the executor: %v", r)
			}
		}()
		er = execDBProbeStep(context.Background(), step)
	}()
	if er.ExitCode == 0 || er.DBProbe == nil {
		t.Fatalf("exec result: %+v", er)
	}
	r := er.DBProbe
	if !r.SafetyIncident || r.CleanupStatus != protocol.DBCleanupResidual || r.ErrorClass == "" {
		t.Fatalf("result: %+v", r)
	}
	if strings.Contains(strings.Join(r.Notes, " ")+er.Stderr, testCredPassword) {
		t.Fatal("secret leaked")
	}
}

func TestDBProbePanicWithCleanCleanupIsProbeError(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		panic("kaboom")
	}
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("a probe panic must be an error")
	}
	if ff.count("Cleanup") != 1 {
		t.Fatalf("cleanup must run: %v", ff.calls)
	}
	r := out.Result
	if r.SafetyIncident || r.CleanupStatus != protocol.DBCleanupOK || r.ErrorClass != dbErrProbe {
		t.Fatalf("result: %+v", r)
	}
}

func TestDBProbeFixtureSeedRefusedByAdapterRunsNoProbe(t *testing.T) {
	// A plain adapter cannot report its mode, so fixtures.Seed refuses it.
	fa := setupHappy(t)
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("expected a fixture error")
	}
	if fa.count("RunProbe") != 0 || fa.count("Seed") != 0 {
		t.Fatalf("no probe or seed expected: %v", fa.calls)
	}
	if out.Result.SafetyIncident || out.Result.CleanupStatus != protocol.DBCleanupNotApplicable || out.Result.ErrorClass != dbErrFixture {
		t.Fatalf("refused seed: %+v", out.Result)
	}
}
