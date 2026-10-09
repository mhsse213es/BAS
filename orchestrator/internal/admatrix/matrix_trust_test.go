package admatrix

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adprimitive"
)

var domainCredMaterial = []adprimitive.Capability{{Kind: adprimitive.CapDomainCredentialMaterial}}

func TestSimulate_IntraForestTrustReachableWithParentChildTrust(t *testing.T) {
	env := adenv.Environment{Forest: adenv.Forest{Trusts: []adenv.Trust{{Type: adenv.TrustTypeParentChild}}}}
	if res := Simulate(adprimitive.TrustAbuseCatalog, env, "attacker", domainCredMaterial, ticket); !res.Reachable {
		t.Fatalf("intra-forest trust abuse must be reachable with a parent-child trust: %+v", res)
	}
	noTrust := adenv.Environment{Forest: adenv.Forest{Trusts: []adenv.Trust{{Type: adenv.TrustTypeExternal}}}}
	if res := Simulate(adprimitive.TrustAbuseCatalog, noTrust, "attacker", domainCredMaterial, ticket); res.Reachable {
		t.Fatalf("intra-forest trust abuse must NOT be reachable without an intra-forest trust: %+v", res)
	}
}

func TestSimulate_CrossForestTrustReachableOnlyWhenSIDFilterDisabled(t *testing.T) {
	disabled := adenv.Environment{Forest: adenv.Forest{Trusts: []adenv.Trust{{Type: adenv.TrustTypeExternal, SIDFilteringDisabled: true}}}}
	if res := Simulate(adprimitive.TrustAbuseCatalog, disabled, "attacker", domainCredMaterial, ticket); !res.Reachable {
		t.Fatalf("cross-forest trust abuse must be reachable when SID filtering is disabled: %+v", res)
	}
	enabled := adenv.Environment{Forest: adenv.Forest{Trusts: []adenv.Trust{{Type: adenv.TrustTypeExternal}}}}
	if res := Simulate(adprimitive.TrustAbuseCatalog, enabled, "attacker", domainCredMaterial, ticket); res.Reachable {
		t.Fatalf("cross-forest trust abuse must NOT be reachable with SID filtering enabled: %+v", res)
	}
}

func TestTrustEntries_GroundedAndHonest(t *testing.T) {
	if len(TrustEntries()) != len(adprimitive.TrustAbuseCatalog) {
		t.Fatalf("TrustEntries must cover every trust-abuse catalog primitive")
	}
	for _, e := range TrustEntries() {
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
