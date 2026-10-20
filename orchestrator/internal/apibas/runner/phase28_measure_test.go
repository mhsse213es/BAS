package runner_test

import (
	"fmt"
	"testing"

	"github.com/audspect/bas/internal/apibas/catalog"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/coverage"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/lab"
)

// fixtureFor returns the lab fixture a scenario names in its preconditions.
func fixtureFor(t *testing.T, name string) fixture.Fixture {
	t.Helper()
	switch name {
	case "orders-two-tenant":
		return fixture.OrdersTwoTenant()
	case "orders-no-protected":
		return fixture.OrdersNoProtected()
	case "orders-paged":
		return fixture.OrdersPaged()
	}
	t.Fatalf("unknown fixture %q", name)
	return fixture.Fixture{}
}

// TestPhase28_MeasuredCoverage runs every implemented scenario in both builds and reports coverage
// from the measured verdicts. Unsupported scenarios are not run. Skipped under -short, because the
// timing scenario takes a minute.
func TestPhase28_MeasuredCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip("full measured run skipped in -short mode")
	}
	all, err := catalog.All()
	if err != nil {
		t.Fatalf("catalog.All: %v", err)
	}
	results := map[string]coverage.Verdicts{}
	for _, s := range all {
		if !contract.ProtocolSupported(s.Protocol) {
			continue
		}
		fx := fixtureFor(t, s.Preconditions.Fixture)
		var v coverage.Verdicts
		for _, mode := range []lab.Mode{lab.ModeVulnerable, lab.ModeFixed} {
			e := newEnvFaults(t, mode, fx, s.Preconditions.LabFaults)
			rep := e.run(t, s, e.state)
			out := rep.Outcome
			if mode == lab.ModeVulnerable {
				v.Vulnerable = &out
			} else {
				v.Fixed = &out
			}
		}
		results[s.ID] = v
	}
	r := coverage.Build(all, contract.ProtocolSupported, results)
	if !r.Consistent() {
		t.Fatalf("coverage classes do not sum to the catalog: %+v", r)
	}
	fmt.Println(coverage.Format(r))
}
