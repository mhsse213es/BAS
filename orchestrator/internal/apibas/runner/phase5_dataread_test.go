package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// DATA-012 (order summary) and DATA-013 (order export) extend DATA-011 to the other owner read paths. The erasure request is
// the same; only the read after it changes. The vulnerable build keeps the record, so the owner still reads the summary and
// the export, and the protected values come back: FAIL, exploited. The fixed build removes the record, so each read is 404:
// PASS. The status path is not built as a scenario: the status body carries no protected value in either build, so the
// grader could only report SKIPPED on the vulnerable build.
func TestPhase5_OwnerReadPathsAfterErasure(t *testing.T) {
	for _, id := range []string{"API-BAS-DATA-012", "API-BAS-DATA-013"} {
		s := scenarioByID(t, id)
		fx := fixtureFor(t, s.Preconditions.Fixture)
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
