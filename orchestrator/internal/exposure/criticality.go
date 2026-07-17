package exposure

// AssetCriticalityInputs is everything CriticalityRisk needs to score one
// asset: the operator-set tag fields (attackpath.AssetTag/Node's
// CriticalityTier/InternetFacing/IdentityExposed/Production/ComplianceScope)
// plus the two signals this package already derives for free —
// IsDomainController from attackpath.Node.Role==RoleDC (set from SharpHound
// data) and ThreatGroupCount from this asset's own AssetExposureProfile.ThreatIntel.
type AssetCriticalityInputs struct {
	CriticalityTier    string // "" | low | medium | high | critical
	InternetFacing     bool
	IdentityExposed    bool
	Production         bool
	ComplianceScope    []string
	IsDomainController bool
	ThreatGroupCount   int
}

// CriticalityRisk scores 0-100 (higher = matters more) — see
// docs/superpowers/specs/2026-07-17-sp6-asset-criticality-design.md for the
// starting bump values; they're deliberately not sacred, tune later against
// real fleet data the same way SP4's own formula was.
func CriticalityRisk(in AssetCriticalityInputs) int {
	risk := 0
	switch in.CriticalityTier {
	case "critical":
		risk = 100
	case "high":
		risk = 70
	case "medium":
		risk = 40
	case "low":
		risk = 15
	}
	if in.IsDomainController {
		risk += 15
	}
	if in.InternetFacing {
		risk += 10
	}
	if in.IdentityExposed {
		risk += 10
	}
	if in.Production {
		risk += 10
	}
	if len(in.ComplianceScope) > 0 {
		risk += 10
	}
	if in.ThreatGroupCount > 0 {
		risk += 5
	}
	return clamp100(risk)
}
