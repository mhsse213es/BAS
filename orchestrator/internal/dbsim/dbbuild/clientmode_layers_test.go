package dbbuild

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

func clientTarget() dbsim.Target {
	tg := labTarget()
	tg.Mode, tg.LabConfirmed, tg.ReadOnlyIdentityVerified = dbsim.ModeClient, false, true
	return tg
}

// scenarioFor builds a one-step scenario of the exact shape BuildSteps accepts
// for the probe, so that a refusal can only come from the client-mode gates.
func scenarioFor(e dbsim.ProbeRegistryEntry) *scenario.Scenario {
	switch {
	case e.FixtureParam != "":
		return fixtureScenario(e.ID, "accounts", "accounts")
	case e.RequiredFixture != "":
		return requiredFixtureScenario(e.ID, "T1213", e.RequiredFixture, nil)
	}
	return oneStepScenario(e.ID, nil)
}

// nonClientProbes lists every registered probe that is not a plain read-only
// probe: mutation, bounded_synthetic, fixture-aware and lab-only.
func nonClientProbes(t *testing.T) []dbsim.ProbeRegistryEntry {
	t.Helper()
	var out []dbsim.ProbeRegistryEntry
	for _, id := range dbsim.ProbeIDs() {
		e, _ := dbsim.LookupProbeEntry(id)
		if e.Class != dbsim.ClassReadOnly || e.LabOnly || e.FixtureParam != "" || e.RequiredFixture != "" {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		t.Fatal("no non-client probes found: the registry changed shape")
	}
	return out
}

// A client-mode run of a scenario containing anything but a plain read-only
// probe is refused at every orchestrator layer, even with every other approval
// (gate on, identity verified, scenario mutation approval, a confirmed target).
// The agent layers are covered by the same-named test in the agent module.
func TestClientRunWithMutationScenarioRefusedAtEveryLayer(t *testing.T) {
	gate := dbsim.StaticClientGate(true)

	t.Run("orchestrator_authorize", func(t *testing.T) {
		for _, e := range nonClientProbes(t) {
			tg := clientTarget()
			tg.LabConfirmed = true // even a (contradictory) confirmed client target
			err := dbsim.Authorize(tg, e, dbsim.AuthInput{
				ClientGate: gate, MutationApproved: true, Fixture: e.FixtureParam != "" || e.RequiredFixture != "",
				RunExpiry: fixedNow.Add(time.Hour), Now: fixedNow,
			})
			if err == nil {
				t.Errorf("%s: Authorize accepted a client-mode dispatch", e.ID)
			}
		}
	})

	t.Run("orchestrator_buildsteps", func(t *testing.T) {
		for _, e := range nonClientProbes(t) {
			o := approved(opts(clientTarget()))
			o.ClientGate = gate
			if steps, err := BuildSteps(context.Background(), scenarioFor(e), o); err == nil || len(steps) != 0 {
				t.Errorf("%s: BuildSteps emitted %d steps for a client target (err=%v)", e.ID, len(steps), err)
			}
			// The same scenario builds for a confirmed LAB target: the refusal is the client-mode gate, not the shape.
			lab := approved(opts(labTarget()))
			if _, err := BuildSteps(context.Background(), scenarioFor(e), lab); err != nil {
				t.Errorf("%s: control build against the lab target failed: %v", e.ID, err)
			}
		}
	})

	// A multi-step scenario that hides one mutating step among read-only steps
	// emits nothing at all (never a partially authorised scenario).
	t.Run("orchestrator_buildsteps_mixed_scenario", func(t *testing.T) {
		sc := &scenario.Scenario{ID: "dbsim-t", Name: "t", ProductLine: "dbsim", Steps: []scenario.Step{
			{Name: "ro", TechniqueID: "T1078", Executor: "dbprobe", DBTarget: "lab-db", DBProbe: "read_roles"},
			{Name: "rw", TechniqueID: "T1213", Executor: "dbprobe", DBTarget: "lab-db", DBProbe: "try_write_fixture", DBFixture: "accounts"},
		}}
		o := approved(opts(clientTarget()))
		o.ClientGate = gate
		if steps, err := BuildSteps(context.Background(), sc, o); err == nil || len(steps) != 0 {
			t.Fatalf("mixed scenario built %d steps (err=%v)", len(steps), err)
		}
	})

	// DB-role layer: the registered client identity must itself be read-only. A
	// target whose identity check fails (it can write, alter, administer or touch
	// audit settings, or could not be observed) is never verified, so not even a
	// read-only probe may run against it in client mode.
	t.Run("db_role_identity_check", func(t *testing.T) {
		reg, err := dbsim.TargetRegistration{
			ID: "lab-db", Engine: "postgresql", Host: "10.20.30.40", Port: 5432, CredentialRef: "dbcred:lab-pg",
			ExpectedIdentity: "7312345678901234567", Mode: dbsim.ModeClient, AgentID: "0123456789abcdef",
		}.Normalize()
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{
			"identity_checks=can_write=yes,can_ddl=no,can_admin=no,can_audit=no",
			"identity_checks=can_write=no,can_ddl=yes,can_admin=no,can_audit=no",
			"identity_checks=can_write=no,can_ddl=no,can_admin=yes,can_audit=no",
			"identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=yes",
			"identity_checks=can_write=unknown,can_ddl=no,can_admin=no,can_audit=no",
			"not_a_note=1",
		} {
			v := dbsim.EvaluateReadOnlyIdentity("postgresql", dbsim.DBProbeResult{Notes: []string{bad}})
			if v.Passed {
				t.Fatalf("%q passed the identity check", bad)
			}
			rec := dbsim.TargetRecord{TargetRegistration: reg,
				IdentityCheck: dbsim.IdentityCheckState{Checked: true, Passed: v.Passed, At: time.Now(), Reasons: v.Reasons}}
			o := opts(rec.ToTarget())
			o.ClientGate = gate
			if _, err := BuildSteps(context.Background(), oneStepScenario("read_roles", nil), o); err == nil ||
				!strings.Contains(err.Error(), "read-only identity not verified") {
				t.Fatalf("%q: a target that failed its identity check was usable in client mode: %v", bad, err)
			}
		}
		// Control: the same target with a clear check builds.
		v := dbsim.EvaluateReadOnlyIdentity("postgresql", dbsim.DBProbeResult{Notes: []string{"identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no"}})
		rec := dbsim.TargetRecord{TargetRegistration: reg, IdentityCheck: dbsim.IdentityCheckState{Checked: true, Passed: v.Passed, At: time.Now()}}
		o := opts(rec.ToTarget())
		o.ClientGate = gate
		if _, err := BuildSteps(context.Background(), oneStepScenario("read_roles", nil), o); err != nil {
			t.Fatalf("control: a verified read-only client target was refused: %v", err)
		}
	})
}
