package runner_test

import (
	"fmt"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
	"github.com/audspect/bas/internal/apibas/runner"
)

// phase3CloseoutScope is every P3 ID in the blueprint's phase column (docs/api-bas-blueprint.md). Taken from the table,
// not hand-picked, so a scenario missing from the catalog fails here.
var phase3CloseoutScope = []string{
	"API-BAS-ABUSE-004", "API-BAS-ABUSE-006", "API-BAS-ABUSE-007", "API-BAS-ABUSE-010",
	"API-BAS-AUTHN-004", "API-BAS-AUTHN-005", "API-BAS-AUTHN-007", "API-BAS-AUTHN-009", "API-BAS-AUTHN-010",
	"API-BAS-AUTHZ-012",
	"API-BAS-BIZ-001", "API-BAS-BIZ-002", "API-BAS-BIZ-003", "API-BAS-BIZ-004", "API-BAS-BIZ-005",
	"API-BAS-BIZ-006", "API-BAS-BIZ-007", "API-BAS-BIZ-008", "API-BAS-BIZ-009", "API-BAS-BIZ-010", "API-BAS-BIZ-011",
	"API-BAS-DATA-005", "API-BAS-DATA-007", "API-BAS-DATA-009", "API-BAS-DATA-010",
	"API-BAS-DISC-006", "API-BAS-DISC-009", "API-BAS-DISC-010",
	"API-BAS-GWAY-012",
	"API-BAS-INJ-005", "API-BAS-INJ-007",
	"API-BAS-INTEG-001", "API-BAS-INTEG-002", "API-BAS-INTEG-005", "API-BAS-INTEG-006", "API-BAS-INTEG-007",
	"API-BAS-INTEG-009", "API-BAS-INTEG-010", "API-BAS-INTEG-011",
}

// TestPhase3_CloseoutAllP3Validated runs every blueprint P3 scenario in both builds. Each must be catalogued, FAIL as
// exploited on the vulnerable build, and PASS with control enforced on the fixed build.
func TestPhase3_CloseoutAllP3Validated(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 3 close-out run skipped in -short mode")
	}
	if len(phase3CloseoutScope) != 39 {
		t.Fatalf("P3 scope has %d IDs, blueprint lists 39", len(phase3CloseoutScope))
	}
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	byID := map[string]int{}
	for i, s := range all {
		byID[s.ID] = i
	}
	for _, id := range phase3CloseoutScope {
		idx, ok := byID[id]
		if !ok {
			t.Errorf("%s: not in the catalog", id)
			continue
		}
		s := all[idx]
		fx := fixtureFor(t, s.Preconditions.Fixture)
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			o := closeoutOutcome(t, s, fx, mode)
			if mode == lab.ModeVulnerable {
				if o.Result != grade.FAIL || o.Exploitability != grade.Exploited {
					t.Errorf("%s vulnerable: %s/%s (%s), want FAIL/exploited", id, o.Result, o.Exploitability, o.Reason)
				}
			} else if o.Result != grade.PASS || o.Control != grade.Enforced {
				t.Errorf("%s fixed: %s/%s (%s), want PASS/enforced", id, o.Result, o.Control, o.Reason)
			}
		}
	}
}

// closeoutOutcome runs one scenario in the environment it needs. The two TLS scenarios run on the TLS listener, and
// every other scenario runs on the plain HTTP lab.
func closeoutOutcome(t *testing.T, s contract.Scenario, fx fixture.Fixture, mode lab.Mode) grade.Outcome {
	t.Helper()
	if s.ID == "API-BAS-AUTHN-007" || s.ID == "API-BAS-GWAY-012" {
		return newTLSEnv(t, mode, fx, true, true).run(t, s).Outcome
	}
	e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
	return e.run(t, s, e.state).Outcome
}

// raceAccepted counts the attack requests of a race scenario that the server accepted. The race scenario's attack step
// is the one that repeats; its exchanges are the accepted and refused concurrent requests.
func raceAccepted(rep runner.Report, stepID string) int {
	n := 0
	for _, ex := range rep.Exchanges {
		if ex.StepID == stepID && ex.Status == 200 {
			n++
		}
	}
	return n
}

// TestPhase3_RaceFlakinessReport runs BIZ-005 100 times per build and reports how often each verdict and accept count
// occurs. The grader cannot fix goroutine scheduling, so a fixed seed is not available. The measured spread is the
// evidence instead. Any run that breaks the expected verdict fails the test.
func TestPhase3_RaceFlakinessReport(t *testing.T) {
	if testing.Short() {
		t.Skip("race flakiness run skipped in -short mode")
	}
	const runs = 100
	s := tlsScenario(t, "API-BAS-BIZ-005")
	fx := fixtureFor(t, s.Preconditions.Fixture)
	const attackStep = "attack-concurrent-withdraw"
	for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
		verdicts := map[string]int{}
		accepts := map[int]int{}
		unexpected := 0
		for i := 0; i < runs; i++ {
			e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
			rep := e.run(t, s, e.state)
			o := rep.Outcome
			verdicts[fmt.Sprintf("%s/%s/%s", o.Result, o.Exploitability, o.Control)]++
			accepts[raceAccepted(rep, attackStep)]++
			want := grade.PASS
			if mode == lab.ModeVulnerable {
				want = grade.FAIL
			}
			if o.Result != want {
				unexpected++
			}
		}
		fmt.Printf("BIZ-005 %s over %d runs: verdicts=%v accepted=%v unexpected=%d\n", modeName(mode), runs, verdicts, accepts, unexpected)
		if unexpected > 0 {
			t.Errorf("BIZ-005 %s: %d of %d runs broke the expected verdict", modeName(mode), unexpected, runs)
		}
	}
}
