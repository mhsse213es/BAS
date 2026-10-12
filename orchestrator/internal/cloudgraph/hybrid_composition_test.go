package cloudgraph

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adprimitive"
)

// TestComposeHybridPath_FullMatch verifies the happy path: AD user is reachable
// to the capability tied to sync eligibility, the federation edge is fresh, and
// the cloud-side edge is PolicySupported. OverallState should reflect success
// end to end.
func TestComposeHybridPath_FullMatch(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "alice"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "alice-sync-eligible"}

	catalog := []adprimitive.Primitive{
		{
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}},
			Postconditions: []adprimitive.Capability{targetCap},
		},
	}

	fedEdge := &FederationEdge{
		ADIdentityRef:            "alice-sync-eligible",
		CloudIdentityCanonicalID: "azure:user_alice@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			CollectionAge: 1 * time.Hour,
		},
	}

	cloudIdentity := &CloudIdentity{CanonicalID: "azure:user_alice@corp.onmicrosoft.com"}
	cloudResource := &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"}

	cloudEdge := &CloudPermission{
		Source:     cloudIdentity,
		Target:     cloudResource,
		Action:     "Microsoft.Storage/storageAccounts/read",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":   "/subscriptions/sub-1",
			"role_actions": "Microsoft.Storage/storageAccounts/read",
		},
	}

	query := &HybridPathQuery{
		ADCatalog:          catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:         adchain.MapResolver{},
		FederationEdges:    []*FederationEdge{fedEdge},
		FederationMaxAge:   24 * time.Hour,
		CloudEdges:         []*CloudPermission{cloudEdge},
		CloudEvaluator:     &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.OverallState != "reachable" {
		t.Errorf("Expected overall reachable, got %s", result.OverallState)
	}
	if !result.ADReachable {
		t.Error("Expected AD hop to be reachable")
	}
	if result.FederationHop != "fresh" {
		t.Errorf("Expected federation hop fresh, got %s", result.FederationHop)
	}
	if len(result.CloudHops) != 1 || result.CloudHops[0].State != PolicySupported {
		t.Error("Expected cloud hop to be PolicySupported")
	}
}

// TestComposeHybridPath_NoFederationMatch verifies the no-match case: the AD
// identity has no FederationEdge at all, so the composer cannot cross domains
// and must report unknown, never infer a cloud path exists.
func TestComposeHybridPath_NoFederationMatch(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "bob"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "bob-sync-eligible"}

	catalog := []adprimitive.Primitive{
		{
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}},
			Postconditions: []adprimitive.Capability{targetCap},
		},
	}

	query := &HybridPathQuery{
		ADCatalog:          catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:         adchain.MapResolver{},
		FederationEdges:    []*FederationEdge{}, // no edge for bob
		FederationMaxAge:   24 * time.Hour,
		CloudEdges:         []*CloudPermission{},
		CloudEvaluator:     &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.OverallState != "unknown" {
		t.Errorf("Expected unknown (no federation edge to cross), got %s", result.OverallState)
	}
	if result.FederationHop != "no-match" {
		t.Errorf("Expected federation hop no-match, got %s", result.FederationHop)
	}
}

// TestComposeHybridPath_StaleFederationEvidence verifies a federation edge that
// exists but is stale degrades the path rather than being trusted as current.
func TestComposeHybridPath_StaleFederationEvidence(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "carol"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "carol-sync-eligible"}

	catalog := []adprimitive.Primitive{
		{
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}},
			Postconditions: []adprimitive.Capability{targetCap},
		},
	}

	staleFedEdge := &FederationEdge{
		ADIdentityRef:            "carol-sync-eligible",
		CloudIdentityCanonicalID: "azure:user_carol@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			CollectionAge: 72 * time.Hour, // stale against a 24h max age
		},
	}

	query := &HybridPathQuery{
		ADCatalog:          catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:         adchain.MapResolver{},
		FederationEdges:    []*FederationEdge{staleFedEdge},
		FederationMaxAge:   24 * time.Hour,
		CloudEdges:         []*CloudPermission{},
		CloudEvaluator:     &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.FederationHop != "stale" {
		t.Errorf("Expected federation hop stale, got %s", result.FederationHop)
	}
	if result.OverallState != "degraded" {
		t.Errorf("Expected overall degraded (stale evidence, not trusted as current), got %s", result.OverallState)
	}
}

// TestComposeHybridPath_ADBlockedStopsAtADHop verifies an AD-side failure is
// never laundered into a cloud-side Candidate — the composer must stop and
// report the AD hop as the blocking point, without evaluating cloud edges at all.
func TestComposeHybridPath_ADBlockedStopsAtADHop(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "dave"}
	unrelatedCap := adprimitive.Capability{Kind: adprimitive.CapLocalAdmin, Target: "some-other-host"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "dave-sync-eligible"}

	// Catalog has no primitive producing targetCap from heldCap -- dave cannot reach it.
	catalog := []adprimitive.Primitive{
		{
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}},
			Postconditions: []adprimitive.Capability{unrelatedCap},
		},
	}

	fedEdge := &FederationEdge{
		ADIdentityRef:            "dave-sync-eligible",
		CloudIdentityCanonicalID: "azure:user_dave@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			CollectionAge: 1 * time.Hour,
		},
	}

	cloudIdentity := &CloudIdentity{CanonicalID: "azure:user_dave@corp.onmicrosoft.com"}
	cloudResource := &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"}
	cloudEdge := &CloudPermission{
		Source: cloudIdentity, Target: cloudResource, Action: "Microsoft.Storage/storageAccounts/read",
		Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": "Microsoft.Storage/storageAccounts/read"},
	}

	query := &HybridPathQuery{
		ADCatalog:          catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:         adchain.MapResolver{},
		FederationEdges:    []*FederationEdge{fedEdge},
		FederationMaxAge:   24 * time.Hour,
		CloudEdges:         []*CloudPermission{cloudEdge},
		CloudEvaluator:     &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.ADReachable {
		t.Error("Expected AD hop to be unreachable")
	}
	if result.OverallState != "blocked" {
		t.Errorf("Expected overall blocked (stopped at AD hop), got %s", result.OverallState)
	}
	if len(result.CloudHops) != 0 {
		t.Error("Expected zero cloud hops evaluated -- composer must stop at the AD hop, never evaluate the cloud side as if AD had succeeded")
	}
}

// TestComposeHybridPath_CloudSideMissingTelemetryReturnsUnknown verifies that
// when the AD hop and federation hop both succeed but the cloud side has no
// edges to evaluate (e.g. discovery found no permissions for this identity),
// the overall result is unknown — never inferred as reachable.
func TestComposeHybridPath_CloudSideMissingTelemetryReturnsUnknown(t *testing.T) {
	heldCap := adprimitive.Capability{Kind: adprimitive.CapDomainUser, Target: "erin"}
	targetCap := adprimitive.Capability{Kind: adprimitive.CapDomainCredentialMaterial, Target: "erin-sync-eligible"}

	catalog := []adprimitive.Primitive{
		{
			Prerequisites:  adprimitive.Prerequisites{Capabilities: []adprimitive.Capability{heldCap}},
			Postconditions: []adprimitive.Capability{targetCap},
		},
	}

	fedEdge := &FederationEdge{
		ADIdentityRef:            "erin-sync-eligible",
		CloudIdentityCanonicalID: "azure:user_erin@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			CollectionAge: 1 * time.Hour,
		},
	}

	query := &HybridPathQuery{
		ADCatalog:          catalog,
		ADHeldCapabilities: []adprimitive.Capability{heldCap},
		ADTargetCapability: targetCap,
		ADResolver:         adchain.MapResolver{},
		FederationEdges:    []*FederationEdge{fedEdge},
		FederationMaxAge:   24 * time.Hour,
		CloudEdges:         []*CloudPermission{}, // nothing discovered on the cloud side
		CloudEvaluator:     &AzureEvaluator{},
	}

	result := ComposeHybridPath(query)

	if result.OverallState != "unknown" {
		t.Errorf("Expected unknown (AD+federation succeeded but no cloud evidence), got %s", result.OverallState)
	}
	if !result.ADReachable {
		t.Error("Expected AD hop to be reachable")
	}
	if result.FederationHop != "fresh" {
		t.Errorf("Expected federation hop fresh, got %s", result.FederationHop)
	}
}
