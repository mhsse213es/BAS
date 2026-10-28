package license

import "fmt"

// buildTier is the tier this package was built for. It is set at link time (-X) by the release build and compiled
// into the signed orchestrator, so it cannot be edited on a customer's machine. Empty means the package was built
// without a tier (a development or older build).
var buildTier string

// BuildTier returns the tier this package was built for, or "" when it was not stamped or the stamp is not a tier.
func BuildTier() string {
	if _, ok := tierRank[Tier(buildTier)]; !ok {
		return ""
	}
	return buildTier
}

var tierRank = map[Tier]int{TierCore: 1, TierAdvanced: 2, TierEnterprise: 3}

// BuildMismatch returns a warning when the licence grants more than the package contains: a Core build carries only
// the Core product lines' content, so a higher-tier licence unlocks product lines that have nothing to run. It
// returns "" when the licence is at or below the build's tier, or when the build is not stamped. It is a warning
// only; the licence alone still decides what is permitted.
func BuildMismatch(build string, licence Tier) string {
	b, ok := tierRank[Tier(build)]
	if !ok {
		return ""
	}
	l, ok := tierRank[licence]
	if !ok || l <= b {
		return ""
	}
	return fmt.Sprintf("This package was built for the %s tier, but the licence is %s. The licence unlocks product lines whose content is not in this package, so they will have little or nothing to run. Install the %s package to use everything the licence allows.", build, licence, licence)
}
