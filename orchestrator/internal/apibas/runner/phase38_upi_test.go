package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// The UPI / open-banking pack's scenarios, run through the existing grader in both builds. Every scenario is graded on the
// same fixture (fixture.UPITwoCustomer). The vulnerable build must FAIL as exploited. The fixed build must PASS. A scenario
// that does not behave this way is wrong, not a result to record.
var upiScenarios = []string{
	"API-BAS-AUTHZ-501", // UPI-001: customer reads another customer's UPI transaction
	"API-BAS-AUTHZ-502", // UPI-002: customer reads another customer's VPA-linked account
	"API-BAS-AUTHZ-503", // UPI-003: mandate executed by a caller who is not the assigned merchant
	"API-BAS-AUTHZ-504", // UPI-004: customer reads another customer's standing-instruction mandate
	"API-BAS-DATA-501",  // UPI-005: a revoked Account Aggregator consent is still accepted for a fetch
	"API-BAS-GWAY-501",  // UPI-006: VPA-validate rate limit bypassed by rotating X-Forwarded-For
}

func TestPhase38_UPIScenariosBothBuilds(t *testing.T) {
	fx := fixture.UPITwoCustomer()
	for _, id := range upiScenarios {
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
			if rep.Outcome.Result != grade.PASS {
				t.Errorf("%s fixed: result %s (%s), want PASS", id, rep.Outcome.Result, rep.Outcome.Reason)
			}
		}
	}
}
