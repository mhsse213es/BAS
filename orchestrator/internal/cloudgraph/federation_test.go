package cloudgraph

import (
	"testing"
	"time"
)

// TestFederationEdge_ValidRequiresProvenanceSource verifies a federation edge
// without sync evidence is rejected — it must never be constructed from name
// matching alone.
func TestFederationEdge_ValidRequiresProvenanceSource(t *testing.T) {
	edge := &FederationEdge{
		ADIdentityRef:            "S-1-5-21-DOMAIN-500",
		CloudIdentityCanonicalID: "azure:user_alice@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:     "", // no sync evidence
			ObservedAt: time.Now(),
		},
	}

	err := ValidateFederationEdge(edge)
	if err == nil {
		t.Error("Expected validation error for federation edge with no Provenance.Source")
	}
}

// TestFederationEdge_ValidWithSyncEvidence verifies a properly-evidenced edge passes
func TestFederationEdge_ValidWithSyncEvidence(t *testing.T) {
	edge := &FederationEdge{
		ADIdentityRef:            "S-1-5-21-DOMAIN-500",
		CloudIdentityCanonicalID: "azure:user_alice@corp.onmicrosoft.com",
		Provenance: &Provenance{
			Source:     "entra-ad-connect-sync",
			ObservedAt: time.Now(),
		},
	}

	err := ValidateFederationEdge(edge)
	if err != nil {
		t.Errorf("Expected no validation error, got %v", err)
	}
}

// TestFederationEdge_IsFreshWithinMaxAge verifies freshness check
func TestFederationEdge_IsFreshWithinMaxAge(t *testing.T) {
	edge := &FederationEdge{
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			ObservedAt:    time.Now().Add(-1 * time.Hour),
			CollectionAge: 1 * time.Hour,
		},
	}

	if !edge.IsFresh(24 * time.Hour) {
		t.Error("Expected edge synced 1 hour ago to be fresh within a 24-hour max age")
	}
}

// TestFederationEdge_IsFreshFalseWhenStale verifies stale evidence is flagged
func TestFederationEdge_IsFreshFalseWhenStale(t *testing.T) {
	edge := &FederationEdge{
		Provenance: &Provenance{
			Source:        "entra-ad-connect-sync",
			ObservedAt:    time.Now().Add(-72 * time.Hour),
			CollectionAge: 72 * time.Hour,
		},
	}

	if edge.IsFresh(24 * time.Hour) {
		t.Error("Expected edge synced 72 hours ago to be stale against a 24-hour max age")
	}
}

// TestFederationEdge_NilProvenanceIsNeverFresh verifies the fail-closed default
func TestFederationEdge_NilProvenanceIsNeverFresh(t *testing.T) {
	edge := &FederationEdge{}

	if edge.IsFresh(24 * time.Hour) {
		t.Error("Expected nil Provenance to never be fresh")
	}
}
