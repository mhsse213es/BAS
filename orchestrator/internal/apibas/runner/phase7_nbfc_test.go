package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// The NBFC pack's scenarios, run through the existing grader in both builds. Every scenario is graded on the same
// fixture (fixture.NBFCTwoBorrower). The vulnerable build must FAIL as exploited. The fixed build must PASS. A scenario that
// does not behave this way is wrong, not a result to record.
var nbfcScenarios = []string{
	"API-BAS-AUTHZ-101", // NBFC-001: borrower reads another borrower's loan
	"API-BAS-DATA-101",  // NBFC-002: borrower retrieves another borrower's KYC record
	"API-BAS-AUTHZ-102", // NBFC-003: borrower changes another borrower's loan application
	"API-BAS-AUTHZ-103", // NBFC-004: loan officer approves a loan not assigned to them
	"API-BAS-AUTHZ-104", // NBFC-005: loan officer approves their own prepared decision
	"API-BAS-AUTHZ-105", // NBFC-006: borrower alters a repayment status
	"API-BAS-DATA-102",  // NBFC-007: loan read exposes KYC fields beyond the projection
	"API-BAS-DATA-103",  // NBFC-008: loan lookup reveals another borrower's loans
	"API-BAS-AUTHZ-106", // NBFC-admin: borrower reads another borrower's loan through the administrative route
	"API-BAS-DATA-104",  // NBFC-statement: borrower reads another borrower's statement with debit mandates
}

func TestPhase7_NBFCScenariosBothBuilds(t *testing.T) {
	fx := fixture.NBFCTwoBorrower()
	for _, id := range nbfcScenarios {
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
