package runner_test

import (
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/lab"
)

// phase2Scope is every scenario the blueprint marks P2 (docs/api-bas-blueprint.md, the phase column). Generated
// from the blueprint table, not hand-picked. Expectations, written before the run: each scenario is catalogued;
// the vulnerable build FAILs as exploited; the fixed build PASSes with control enforced. A scenario with no
// fixture is SKIPPED and is not counted; that rule is covered by the Phase 2 tests in phase2_test.go.
var phase2Scope = []string{
	"API-BAS-ABUSE-001",
	"API-BAS-ABUSE-002",
	"API-BAS-ABUSE-003",
	"API-BAS-ABUSE-005",
	"API-BAS-ABUSE-008",
	"API-BAS-ABUSE-009",
	"API-BAS-AUTHN-001",
	"API-BAS-AUTHN-002",
	"API-BAS-AUTHN-003",
	"API-BAS-AUTHN-006",
	"API-BAS-AUTHN-008",
	"API-BAS-AUTHZ-002",
	"API-BAS-AUTHZ-003",
	"API-BAS-AUTHZ-004",
	"API-BAS-AUTHZ-005",
	"API-BAS-AUTHZ-006",
	"API-BAS-AUTHZ-007",
	"API-BAS-AUTHZ-008",
	"API-BAS-AUTHZ-009",
	"API-BAS-AUTHZ-010",
	"API-BAS-AUTHZ-011",
	"API-BAS-DATA-001",
	"API-BAS-DATA-002",
	"API-BAS-DATA-003",
	"API-BAS-DATA-004",
	"API-BAS-DATA-006",
	"API-BAS-DATA-008",
	"API-BAS-DISC-001",
	"API-BAS-DISC-002",
	"API-BAS-DISC-003",
	"API-BAS-DISC-004",
	"API-BAS-DISC-005",
	"API-BAS-DISC-007",
	"API-BAS-DISC-008",
	"API-BAS-GWAY-001",
	"API-BAS-GWAY-002",
	"API-BAS-GWAY-003",
	"API-BAS-GWAY-004",
	"API-BAS-GWAY-005",
	"API-BAS-GWAY-006",
	"API-BAS-GWAY-007",
	"API-BAS-GWAY-008",
	"API-BAS-GWAY-009",
	"API-BAS-GWAY-010",
	"API-BAS-GWAY-011",
	"API-BAS-INJ-001",
	"API-BAS-INJ-002",
	"API-BAS-INJ-003",
	"API-BAS-INJ-004",
	"API-BAS-INJ-006",
	"API-BAS-INJ-008",
	"API-BAS-INJ-009",
	"API-BAS-INJ-010",
	"API-BAS-INJ-011",
	"API-BAS-INJ-012",
	"API-BAS-INTEG-003",
	"API-BAS-INTEG-004",
	"API-BAS-INTEG-008",
}

// TestPhase2_ScopeAcceptance runs every P2 scenario in both builds and asserts the blueprint's Phase 2
// acceptance: a vulnerable and a fixed lab case for each scenario. It does not assert timing; timing claims
// are governed by the timing policy and ABUSE-002 is provisional.
func TestPhase2_ScopeAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("Phase 2 scope run skipped in -short mode")
	}
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	byID := map[string]int{}
	for i, s := range all {
		byID[s.ID] = i
	}
	if len(phase2Scope) != 58 {
		t.Fatalf("phase 2 scope has %d IDs, blueprint lists 58", len(phase2Scope))
	}
	var failures []string
	for _, id := range phase2Scope {
		idx, ok := byID[id]
		if !ok {
			t.Errorf("%s: not in the catalog", id)
			continue
		}
		s := all[idx]
		fx := fixtureFor(t, s.Preconditions.Fixture)
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
			rep := e.run(t, s, e.state)
			o := rep.Outcome
			if mode == lab.ModeVulnerable {
				if o.Result != grade.FAIL || o.Exploitability != grade.Exploited {
					failures = append(failures, id+" vulnerable: "+string(o.Result)+"/"+string(o.Exploitability)+" ("+o.Reason+")")
				}
			} else if o.Result != grade.PASS || o.Control != grade.Enforced {
				failures = append(failures, id+" fixed: "+string(o.Result)+"/"+string(o.Control)+" ("+o.Reason+")")
			}
		}
	}
	for _, f := range failures {
		t.Error(f)
	}
}
