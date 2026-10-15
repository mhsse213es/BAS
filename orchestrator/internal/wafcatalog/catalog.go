package wafcatalog

import "fmt"

// AudspectWAFAttackCatalog returns Audspect's real, current seed attack-test
// catalog: roughly 25-30 hand-authored vectors across all eleven AttackFamily
// constants, validated before being returned. A seed-data error (a bad
// construction call, or a duplicate ID introduced while hand-authoring
// across family files) returns an error here rather than a silently
// incomplete or invalid catalog.
func AudspectWAFAttackCatalog() ([]AttackVector, error) {
	var all []AttackVector

	families := []func() ([]AttackVector, error){
		sqlInjectionVectors, xssVectors, pathTraversalVectors,
		ssrfVectors, fileUploadVectors, httpParserVectors,
		apiAbuseVectors, authAbuseVectors,
		rateLimitVectors, cacheWeaknessVectors, policyMisconfigVectors,
	}
	for _, f := range families {
		vectors, err := f()
		if err != nil {
			return nil, fmt.Errorf("loading seed catalog: %w", err)
		}
		all = append(all, vectors...)
	}

	if err := ValidateCatalog(all); err != nil {
		return nil, fmt.Errorf("seed catalog failed validation: %w", err)
	}
	return all, nil
}
