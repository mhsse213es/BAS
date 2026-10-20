package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 28: a protocol without an adapter is UNSUPPORTED. Each such scenario must be SKIPPED with
// unsupported fields and reason UNSUPPORTED_PROTOCOL, and must send zero requests to the target.
//
// Every protocol the catalog names now has an adapter, so the catalog walk currently checks no
// scenario. The guarantee is therefore tested with protocol names that have no adapter. The walk
// is kept, so any future catalog entry without an adapter is covered as soon as it is added.
func TestPhase28_UnsupportedProtocolsSendZeroTraffic(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	var cases []contract.Scenario
	for _, s := range all {
		if !contract.ProtocolSupported(s.Protocol) {
			cases = append(cases, s)
		}
	}
	// Protocol names with no adapter. They are not in the catalog, so this proves the runner gate
	// for any protocol, not only the ones catalogued today.
	base := scenarioByID(t, "API-BAS-AUTHZ-001")
	for _, p := range []string{"quic", "mqtt"} {
		s := base
		s.Protocol = p
		cases = append(cases, s)
	}

	for _, s := range cases {
		t.Run(s.ID+"/"+s.Protocol, func(t *testing.T) {
			e := newEnv(t, lab.ModeVulnerable, fixture.OrdersTwoTenant())
			before := e.apiHits.Load()
			rep := e.run(t, s, e.state)
			if rep.Outcome.Result != grade.SKIPPED {
				t.Fatalf("result = %s, want SKIPPED", rep.Outcome.Result)
			}
			if rep.Outcome.Exploitability != grade.ExploitUnsupported || rep.Outcome.Control != grade.ControlUnsupported {
				t.Fatalf("exploitability/control = %s/%s, want unsupported", rep.Outcome.Exploitability, rep.Outcome.Control)
			}
			if rep.Outcome.Reason != grade.ReasonUnsupportedProtocol {
				t.Fatalf("reason = %s, want UNSUPPORTED_PROTOCOL", rep.Outcome.Reason)
			}
			if sent := e.apiHits.Load() - before; sent != 0 {
				t.Fatalf("%d requests reached the target for an unsupported protocol, want 0", sent)
			}
		})
	}
}
