package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// phase3BIZScope is the blueprint's P3 business-logic set (docs/api-bas-blueprint.md, BIZ rows marked P3). BIZ-012 is
// P4 and is not here. Expectations, written before the run: each scenario is catalogued; the vulnerable build FAILs as
// exploited; the fixed build PASSes with control enforced. Timing is not asserted.
var phase3BIZScope = []string{
	"API-BAS-BIZ-001",
	"API-BAS-BIZ-003",
	"API-BAS-BIZ-004",
	"API-BAS-BIZ-005",
	"API-BAS-BIZ-006",
	"API-BAS-BIZ-007",
	"API-BAS-BIZ-008",
	"API-BAS-BIZ-009",
	"API-BAS-BIZ-010",
	"API-BAS-BIZ-011",
}

// TestPhase3_BIZScopeAcceptance runs each P3 business-logic scenario in both builds and asserts the verdicts above.
func TestPhase3_BIZScopeAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 3 BIZ run skipped in -short mode")
	}
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	byID := map[string]int{}
	for i, s := range all {
		byID[s.ID] = i
	}
	for _, id := range phase3BIZScope {
		idx, ok := byID[id]
		if !ok {
			t.Errorf("%s: not in the catalog", id)
			continue
		}
		s := all[idx]
		fx := fixtureFor(t, s.Preconditions.Fixture)
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
			o := e.run(t, s, e.state).Outcome
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
