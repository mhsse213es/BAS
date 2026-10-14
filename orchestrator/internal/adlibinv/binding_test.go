package adlibinv

import (
	"testing"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// Compile-time proof that the real runtime stores satisfy the seam. If either
// store's method set drifts, this file fails to build — the drift alarm.
var (
	_ ARTSource     = (*scenario.ARTStore)(nil)
	_ CalderaSource = (*scenario.CalderaStore)(nil)
)

// A real *scenario.CalderaStore (built from steps, no live Caldera needed) must
// flow through the seam and be counted as coverage — not just the test fakes.
func TestInventory_RealCalderaStoreFromStepsIsCounted(t *testing.T) {
	store := scenario.NewCalderaStoreFromSteps(map[string][]scenario.ScenarioStep{
		"T1003.006": {{Command: "mimikatz", Name: "dcsync", TechniqueID: "T1003.006"}},
	})
	rep := Inventory(
		[]adprimitive.Primitive{prim("dcsync", "T1003.006")},
		nil,   // no ART in this test
		store, // the real Caldera store
	)
	if len(rep.Covered) != 1 || rep.Covered[0].CalderaAbils < 1 || !rep.Covered[0].Covered {
		t.Fatalf("real Caldera store must flow through the seam and count as coverage, got %+v", rep)
	}
}
