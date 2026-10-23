package main

import (
	"context"
	"strings"
	"testing"

	"audspect/agent/dbprobe"
	"audspect/agent/dbprobe/fixtures"
	"audspect/agent/protocol"
)

// Adapter Seed panics after creating: the exact-name teardown ran and verified
// clean, so the result is fixture_error with cleanup ok (never an unverified ok).
func TestDBProbeSeedPanicTeardownRunsAndIsVerified(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.seedPanic = true
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("a seed panic must be an error")
	}
	want := "Connect,Identity,Inspect,Seed,Cleanup,Inspect,Close"
	if got := strings.Join(ff.calls, ","); got != want {
		t.Fatalf("calls = %s\nwant    %s", got, want)
	}
	r := out.Result
	if r.SafetyIncident || r.CleanupStatus != protocol.DBCleanupOK || r.ErrorClass != dbErrFixture {
		t.Fatalf("result: %+v", r)
	}
}

func TestDBProbeSeedPanicWithFailedCleanupIsIncident(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.seedPanic = true
	ff.leftover = []string{"schema:dbsim_x"}
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("expected error")
	}
	r := out.Result
	if !r.SafetyIncident || r.CleanupStatus != protocol.DBCleanupResidual || r.ErrorClass != dbErrFixture {
		t.Fatalf("result: %+v", r)
	}
	if r.AgentTime.IsZero() {
		t.Fatal("incident result must not be zero-valued")
	}
}

// Panic in the pre-seed inspection: nothing existed, nothing was dropped.
func TestDBProbePreSeedInspectPanicIsNotApplicableNoCleanup(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.inspectPanicAt = 1
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("expected error")
	}
	if ff.count("Cleanup") != 0 || ff.count("Seed") != 0 {
		t.Fatalf("no seed/cleanup expected: %v", ff.calls)
	}
	r := out.Result
	if r.SafetyIncident || r.CleanupStatus != protocol.DBCleanupNotApplicable || r.ErrorClass != dbErrFixture {
		t.Fatalf("result: %+v", r)
	}
}

// A panic the executor cannot attribute to a completed teardown must never
// default to ok: it is an incident with status failed.
func TestDBProbeUnattributedPanicIsFailedIncident(t *testing.T) {
	setupFixtureFake(t)
	orig := withFixtureFn
	withFixtureFn = func(context.Context, dbprobe.Adapter, dbprobe.FixtureSpec, func(dbprobe.Fixture) error) (dbprobe.CleanupResult, error) {
		panic("mystery")
	}
	t.Cleanup(func() { withFixtureFn = orig })
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("expected error")
	}
	r := out.Result
	if !r.SafetyIncident || r.CleanupStatus != protocol.DBCleanupFailed || r.AgentTime.IsZero() {
		t.Fatalf("result: %+v", r)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "panic before cleanup could be verified") {
		t.Fatalf("notes: %v", r.Notes)
	}
}

// Fn-path behaviours stay: the incident result is not zero-valued and names
// the probe panic.
func TestDBProbeFnPanicIncidentResultIsPopulated(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.leftover = []string{"table:dbsim_x.accounts"}
	ff.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		panic("kaboom")
	}
	out, err := executeDBProbe(context.Background(), testDBProbeStep(withFixtureID("accounts")))
	if err == nil {
		t.Fatal("expected error")
	}
	r := out.Result
	if !r.SafetyIncident || r.AgentTime.IsZero() || r.ErrorClass != dbErrProbe {
		t.Fatalf("result: %+v", r)
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "probe panicked") {
		t.Fatalf("notes: %v", r.Notes)
	}
}

// Outside the fixture path nothing is swallowed.
func TestDBProbeNonFixturePanicStillPropagates(t *testing.T) {
	ff := setupFixtureFake(t)
	ff.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		panic("kaboom")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a non-fixture probe panic must not be swallowed")
		}
	}()
	_, _ = executeDBProbe(context.Background(), testDBProbeStep(nil))
}

var _ = fixtures.Names
