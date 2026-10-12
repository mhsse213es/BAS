package cloudgraph

import (
	"errors"
	"time"
)

// FederationEdge links an on-prem AD identity to a synced cloud identity.
// It must always carry real sync evidence in Provenance — never be inferred
// from display-name or UPN similarity, which is exactly the shortcut that
// produces false cross-domain links.
type FederationEdge struct {
	ADIdentityRef            string // AD SID or other AD-native identifier
	CloudIdentityCanonicalID string // CloudIdentity.CanonicalID on the synced side
	Provenance               *Provenance
}

// IsFresh reports whether this edge's sync evidence is within maxAge.
// A nil Provenance or missing CollectionAge is never fresh.
func (f *FederationEdge) IsFresh(maxAge time.Duration) bool {
	if f.Provenance == nil {
		return false
	}
	return f.Provenance.CollectionAge <= maxAge
}

// ValidateFederationEdge rejects a federation edge that lacks real sync
// evidence. Provenance.Source is the evidence: an AD-Connect sync log entry,
// an Entra federation API response, etc. An empty Source means the edge was
// constructed without checking a real sync event, which this function refuses.
func ValidateFederationEdge(edge *FederationEdge) error {
	if edge.Provenance == nil || edge.Provenance.Source == "" {
		return errors.New("federation edge requires Provenance.Source naming real sync evidence; name/UPN matching alone is not sufficient")
	}
	if edge.ADIdentityRef == "" || edge.CloudIdentityCanonicalID == "" {
		return errors.New("federation edge requires both ADIdentityRef and CloudIdentityCanonicalID")
	}
	return nil
}
