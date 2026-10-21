package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// phase3Batch1Scope is the first Phase 3 batch of the remaining P3 scenarios: AUTHN-010 (step-up) and DATA-007 (export
// leak). Expectations, written before the run: vulnerable FAIL/exploited; fixed PASS/enforced.
var phase3Batch1Scope = []string{
	"API-BAS-AUTHN-010",
	"API-BAS-DATA-007",
}

// TestPhase3_Batch1Acceptance runs the batch 1 scenarios in both builds and asserts the verdicts above.
func TestPhase3_Batch1Acceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 3 batch 1 run skipped in -short mode")
	}
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	byID := map[string]int{}
	for i, s := range all {
		byID[s.ID] = i
	}
	for _, id := range phase3Batch1Scope {
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
