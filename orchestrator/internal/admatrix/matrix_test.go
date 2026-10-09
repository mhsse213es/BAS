package admatrix

import (
	"testing"

	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// esc1VulnerableEnv builds a synthetic AD environment with exactly one
// ESC1-vulnerable template the attacker can enroll in.
func esc1VulnerableEnv(attacker string) adenv.Environment {
	return adenv.Environment{
		PKI: adenv.PKI{
			Templates: []adenv.CertTemplate{{
				Name:                    "UserAuth",
				PublishedToCA:           true,
				EnrolleeSuppliesSubject: true,
				ManagerApprovalRequired: false,
				EKUs:                    []string{"Client Authentication"},
				EnrollmentRights:        []string{attacker},
			}},
		},
	}
}

func forceChangePasswordEnv(attacker, victim string) adenv.Environment {
	return adenv.Environment{
		Authorization: adenv.Authorization{
			ACLs: []adenv.ACLEntry{{Principal: attacker, Target: victim, Right: adenv.ACLForceChangePassword}},
		},
	}
}

var domainUser = []adprimitive.Capability{{Kind: adprimitive.CapDomainUser}}

// --- #4 graph reachability ---

func TestSimulate_ESC1ReachableInVulnerableEnv(t *testing.T) {
	res := Simulate(adprimitive.ADCSCatalog, esc1VulnerableEnv("attacker"), "attacker",
		domainUser, adprimitive.Capability{Kind: adprimitive.CapControlledAccount})
	if !res.Reachable {
		t.Fatalf("ESC1 must be reachable in a vulnerable, enrollable env: %+v", res)
	}
	found := false
	for _, s := range res.Steps {
		if s.ID == "adcs-esc1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("plan must include adcs-esc1, got %+v", res.Steps)
	}
}

func TestSimulate_ACLForceChangePasswordReachable(t *testing.T) {
	res := Simulate(adprimitive.ACLAbuseCatalog, forceChangePasswordEnv("attacker", "victim"), "attacker",
		domainUser, adprimitive.Capability{Kind: adprimitive.CapControlledAccount})
	if !res.Reachable {
		t.Fatalf("ForceChangePassword abuse must be reachable when the right is held: %+v", res)
	}
}

// --- #4 prerequisite failure ---

func TestSimulate_PrerequisiteFailureNotEnrollable(t *testing.T) {
	env := esc1VulnerableEnv("someone-else") // attacker has no enrollment right
	res := Simulate(adprimitive.ADCSCatalog, env, "attacker",
		domainUser, adprimitive.Capability{Kind: adprimitive.CapControlledAccount})
	if res.Reachable {
		t.Fatalf("must NOT be reachable when the attacker cannot enroll: %+v", res)
	}
}

// --- #4 invalid attack path ---

func TestSimulate_InvalidPathUnreachableTarget(t *testing.T) {
	res := Simulate(adprimitive.ADCSCatalog, esc1VulnerableEnv("attacker"), "attacker",
		domainUser, adprimitive.Capability{Kind: adprimitive.CapNTLMHash}) // no ADCS primitive grants this
	if res.Reachable || len(res.Steps) != 0 {
		t.Fatalf("an unreachable target must yield no plan: %+v", res)
	}
}

// --- #5 honesty: a simulated result can never be presented as executed ---

func TestSimulate_ResultIsAlwaysModelSimulated(t *testing.T) {
	reachable := Simulate(adprimitive.ADCSCatalog, esc1VulnerableEnv("attacker"), "attacker",
		domainUser, adprimitive.Capability{Kind: adprimitive.CapControlledAccount})
	unreachable := Simulate(adprimitive.ADCSCatalog, esc1VulnerableEnv("nobody"), "attacker",
		domainUser, adprimitive.Capability{Kind: adprimitive.CapControlledAccount})
	if reachable.Level != LevelModelSimulated || unreachable.Level != LevelModelSimulated {
		t.Fatalf("Simulate must always report LevelModelSimulated, got %v / %v", reachable.Level, unreachable.Level)
	}
}

// --- #2/#3 code-grounded matrix + honest validation levels ---

func TestEntries_GroundedInRealCatalog(t *testing.T) {
	if len(ADCSEntries()) != len(adprimitive.ADCSCatalog) {
		t.Fatalf("ADCSEntries must cover every ADCS catalog primitive")
	}
	if len(ACLEntries()) != len(adprimitive.ACLAbuseCatalog) {
		t.Fatalf("ACLEntries must cover every ACL-abuse catalog primitive")
	}
	byID := map[string]adprimitive.Primitive{}
	for _, p := range append(append([]adprimitive.Primitive{}, adprimitive.ADCSCatalog...), adprimitive.ACLAbuseCatalog...) {
		byID[p.ID] = p
	}
	for _, e := range append(ADCSEntries(), ACLEntries()...) {
		p, ok := byID[e.PrimitiveID]
		if !ok {
			t.Fatalf("entry %q is not grounded in the real catalog", e.PrimitiveID)
		}
		// Postconditions must be copied from the live primitive, not drift.
		if len(e.ExpectedPostconditions) != len(p.Postconditions) {
			t.Fatalf("entry %q postconditions drifted from the catalog", e.PrimitiveID)
		}
		for i := range p.Postconditions {
			if e.ExpectedPostconditions[i] != p.Postconditions[i] {
				t.Fatalf("entry %q postcondition %d drifted", e.PrimitiveID, i)
			}
		}
	}
}

func TestEntries_HonestValidationLevelAndEnv(t *testing.T) {
	for _, e := range append(ADCSEntries(), ACLEntries()...) {
		if e.CurrentValidation != LevelModelSimulated {
			t.Fatalf("entry %q claims validation above model-simulated with no real-AD evidence: %v", e.PrimitiveID, e.CurrentValidation)
		}
		if e.RequiredEnvToExecute == EnvSyntheticModel {
			t.Fatalf("entry %q claims it can truly execute in a synthetic model; these need a real host/DC", e.PrimitiveID)
		}
		if len(e.EvidenceRequirements) == 0 || len(e.Cleanup) == 0 {
			t.Fatalf("entry %q must state evidence requirements and cleanup", e.PrimitiveID)
		}
	}
}

func TestValidationLevel_Ordered(t *testing.T) {
	if !(LevelModelSimulated < LevelEndpointExecuted &&
		LevelEndpointExecuted < LevelRealADExecuted &&
		LevelRealADExecuted < LevelTelemetryObserved) {
		t.Fatal("validation levels must be strictly increasing in strength")
	}
	if LevelModelSimulated.String() != "model_simulated" {
		t.Fatalf("unexpected String(): %q", LevelModelSimulated.String())
	}
}

// --- #4 authorization decision (reuses adgate; no production dispatch touched) ---

func TestAuthorizationDecision_GatesExecutionOfASimulatedEntry(t *testing.T) {
	p := adprimitive.ADCSCatalog[0] // adcs-esc1, potentially-destructive
	class := scenario.ExecutionClass(p.RiskClass)
	prov := adgate.VerifiedControlledLabProvenance("run-x", "target-x")
	if d := adgate.Decide(adgate.Request{Class: class, Env: prov, Auth: adgate.Authorization{Authorized: false}}); d.Allowed {
		t.Fatal("unauthorized execution must be denied even for a verified lab")
	}
	if d := adgate.Decide(adgate.Request{Class: class, Env: prov, Auth: adgate.Authorization{Authorized: true}}); !d.Allowed {
		t.Fatalf("authorized verified-lab execution must be allowed, got %+v", d)
	}
}
