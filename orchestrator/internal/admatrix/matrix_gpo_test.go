package admatrix

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adprimitive"
)

var localAdmin = adprimitive.Capability{Kind: adprimitive.CapLocalAdmin}

func TestSimulate_GPOAbuseReachableWithWritableLinkedGPO(t *testing.T) {
	env := adenv.Environment{Policy: adenv.Policy{GPOs: []adenv.GPO{
		{Name: "WS Policy", WritePrincipals: []string{"helpdesk"}, LinkedOUs: []string{"OU=Workstations"}},
	}}}
	if res := Simulate(adprimitive.GPOAbuseCatalog, env, "helpdesk", controlledAccount, localAdmin); !res.Reachable {
		t.Fatalf("GPO abuse must be reachable when the attacker can edit a linked GPO: %+v", res)
	}
	// writable but unlinked -> no affected scope -> not reachable
	unlinked := adenv.Environment{Policy: adenv.Policy{GPOs: []adenv.GPO{
		{Name: "Orphan", WritePrincipals: []string{"helpdesk"}},
	}}}
	if res := Simulate(adprimitive.GPOAbuseCatalog, unlinked, "helpdesk", controlledAccount, localAdmin); res.Reachable {
		t.Fatalf("GPO abuse must NOT be reachable for a writable but unlinked GPO: %+v", res)
	}
}

func TestGPOEntries_GroundedAndHonest(t *testing.T) {
	// Excludes gpo-abuse-exposure-check (read-only discovery primitive with
	// its own real scenario, tracked via realScenarioEvidenceByID).
	if len(GPOEntries()) != len(adprimitive.GPOAbuseCatalog)-1 {
		t.Fatalf("GPOEntries must cover every GPO-abuse catalog primitive except the exposure-check, got %d of %d", len(GPOEntries()), len(adprimitive.GPOAbuseCatalog))
	}
	for _, e := range GPOEntries() {
		if e.PrimitiveID == "gpo-abuse-exposure-check" {
			t.Fatal("gpo-abuse-exposure-check must NOT appear as a gap-matrix Entry")
		}
	}
	for _, e := range GPOEntries() {
		if e.CurrentValidation != LevelModelSimulated {
			t.Fatalf("entry %q must stay model-simulated", e.PrimitiveID)
		}
		if e.RequiredEnvToExecute == EnvSyntheticModel {
			t.Fatalf("entry %q cannot truly execute in a synthetic model", e.PrimitiveID)
		}
		if len(e.EvidenceRequirements) == 0 || len(e.Cleanup) == 0 || len(e.TelemetrySources) == 0 {
			t.Fatalf("entry %q must state evidence, cleanup, and telemetry", e.PrimitiveID)
		}
	}
}
