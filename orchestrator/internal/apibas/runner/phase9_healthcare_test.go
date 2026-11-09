package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// The healthcare pack's scenarios, run through the existing grader in both builds on fixture.HealthcareTwoPatient. The
// vulnerable build must FAIL as exploited. The fixed build must PASS with control enforced.
var healthcareScenarios = []string{
	"API-BAS-AUTHZ-301", // HC-001: patient reads another patient's record
	"API-BAS-AUTHZ-302", // HC-002: clinician reads a record of a patient they do not treat
	"API-BAS-AUTHZ-303", // HC-003: clinician changes another clinician's patient's prescription
	"API-BAS-AUTHZ-304", // HC-004: patient alters their own diagnostic result
	"API-BAS-AUTHZ-305", // HC-005: delegate reads beyond the consent scope
	"API-BAS-DATA-301",  // HC-006: patient downloads another patient's medical image
	"API-BAS-DATA-302",  // HC-007: FHIR Observation read for another patient
	"API-BAS-DATA-303",  // HC-008: records export includes other patients' diagnoses
	"API-BAS-INTEG-301", // HC-009: bedside device posts a result for another patient
}

func TestPhase9_HealthcareScenariosBothBuilds(t *testing.T) {
	fx := fixture.HealthcareTwoPatient()
	for _, id := range healthcareScenarios {
		s := scenarioByID(t, id)
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			e := newEnvWith(t, mode, fx, s.Preconditions.LabFaults, false)
			rep := e.run(t, s, e.state)
			if mode == lab.ModeVulnerable {
				if rep.Outcome.Result != grade.FAIL || rep.Outcome.Exploitability != grade.Exploited {
					t.Errorf("%s vulnerable: result %s exploitability %s (%s), want FAIL exploited",
						id, rep.Outcome.Result, rep.Outcome.Exploitability, rep.Outcome.Reason)
				}
				continue
			}
			if rep.Outcome.Result != grade.PASS || rep.Outcome.Control != grade.Enforced {
				t.Errorf("%s fixed: result %s control %s (%s), want PASS enforced", id, rep.Outcome.Result, rep.Outcome.Control, rep.Outcome.Reason)
			}
		}
	}
}

// A delegate with a summary-only consent still gets the public summary in the fixed build, so the consent works rather than the
// route refusing everyone. The scenario above proves no protected value comes back; this proves the summary does.
func TestPhase9_FixedDelegateGetsTheConsentedSummary(t *testing.T) {
	fx := fixture.HealthcareTwoPatient()
	s := scenarioByID(t, "API-BAS-AUTHZ-305")
	e := newEnvWith(t, lab.ModeFixed, fx, nil, false)
	rep := e.run(t, s, e.state)
	if len(rep.Exchanges) == 0 {
		t.Fatalf("no exchanges recorded: %s %s", rep.Outcome.Result, rep.Outcome.Reason)
	}
	last := rep.Exchanges[len(rep.Exchanges)-1]
	if last.Status != 200 {
		t.Fatalf("delegate read: status %d, want 200 with the summary", last.Status)
	}
}

func TestPhase9_FixtureIsWellFormed(t *testing.T) {
	fx := fixture.HealthcareTwoPatient()
	if len(fx.Identities) != 7 {
		t.Fatalf("fixture has %d identities, want 7", len(fx.Identities))
	}
	seen := map[string]bool{}
	for _, o := range fx.Objects {
		if o.Kind == "" || o.OwnerID == "" {
			t.Errorf("%s: kind %q owner %q; every pack record needs both", o.ID, o.Kind, o.OwnerID)
		}
		if seen[o.ID] {
			t.Errorf("duplicate object id %s", o.ID)
		}
		seen[o.ID] = true
	}
}
