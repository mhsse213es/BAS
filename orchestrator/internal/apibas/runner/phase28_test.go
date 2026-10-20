package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// Phase 28: every non-HTTP scenario in the catalog is UNSUPPORTED until its adapter exists. Each
// one must be SKIPPED with unsupported fields and reason UNSUPPORTED_PROTOCOL, and must send zero
// requests to the target. The test walks the catalog, so a new protocol entry is covered without
// editing this file.
func TestPhase28_EveryNonHTTPCatalogScenarioIsUnsupportedWithZeroTraffic(t *testing.T) {
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	checked := 0
	for _, s := range all {
		if contract.ProtocolSupported(s.Protocol) {
			continue
		}
		checked++
		t.Run(s.ID, func(t *testing.T) {
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
	if checked < 3 {
		t.Fatalf("only %d unsupported scenarios in the catalog, want at least the 5 protocols without an adapter", checked)
	}
}
