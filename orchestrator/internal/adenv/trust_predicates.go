package adenv

// IsIntraForestTrustAbusable reports whether tr is an intra-forest (parent-child)
// trust. Such trusts never apply SID filtering, so an attacker who owns one
// domain can forge an inter-realm TGT carrying the forest root's Enterprise
// Admins SID (SID-history injection) and escalate across the trust.
func IsIntraForestTrustAbusable(tr Trust) bool {
	return tr.Type == TrustTypeParentChild
}

// IsCrossForestSIDAbusable reports whether tr is a cross-forest/external trust on
// which SID filtering has been disabled. Cross-forest trusts filter SIDs by
// default, so abuse is only possible once that protection has been turned off.
func IsCrossForestSIDAbusable(tr Trust) bool {
	return (tr.Type == TrustTypeExternal || tr.Type == TrustTypeForest) && tr.SIDFilteringDisabled
}
