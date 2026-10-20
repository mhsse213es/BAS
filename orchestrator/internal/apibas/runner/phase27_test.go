package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Blueprint section 2: a protocol without an executable adapter is UNSUPPORTED, never counted
// as covered. The verdict stays SKIPPED, the exploitability and control say unsupported, the
// reason is UNSUPPORTED_PROTOCOL, and no request reaches the target.
// GraphQL has an adapter since Phase 28, so it is not listed here.
var unsupportedProtocols = []string{"async"}

func TestPhase27_UnsupportedProtocolsAreReportedUnsupported(t *testing.T) {
	for _, p := range unsupportedProtocols {
		t.Run(p, func(t *testing.T) {
			e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
			s := scenarioByID(t, "API-BAS-AUTHZ-001")
			s.Protocol = p
			before := e.apiHits.Load()
			rep := e.run(t, s, e.state)

			if rep.Outcome.Result != grade.SKIPPED {
				t.Fatalf("result = %s, want SKIPPED (never PASS or FAIL)", rep.Outcome.Result)
			}
			if rep.Outcome.Exploitability != grade.ExploitUnsupported || rep.Outcome.Control != grade.ControlUnsupported {
				t.Fatalf("exploitability/control = %s/%s, want unsupported/unsupported",
					rep.Outcome.Exploitability, rep.Outcome.Control)
			}
			if rep.Outcome.Reason != grade.ReasonUnsupportedProtocol {
				t.Fatalf("reason = %s, want %s", rep.Outcome.Reason, grade.ReasonUnsupportedProtocol)
			}
			if got := e.apiHits.Load() - before; got != 0 {
				t.Fatalf("%d API requests sent for an unsupported protocol, want 0", got)
			}
		})
	}
}

// An HTTP scenario is not affected by the unsupported path.
func TestPhase27_HTTPScenarioIsNotReportedUnsupported(t *testing.T) {
	e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
	rep := e.run(t, scenarioByID(t, "API-BAS-AUTHZ-001"), e.state)
	if rep.Outcome.Exploitability == grade.ExploitUnsupported {
		t.Fatalf("HTTP scenario reported unsupported: %+v", rep.Outcome)
	}
}
