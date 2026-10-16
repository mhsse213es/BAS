package avcatalog

import "fmt"

// AudspectAVAttackCatalog returns Audspect's real, current seed AV/NGAV
// test catalog: hand-authored vectors across the seven vector-bearing
// AttackFamily constants (av.txt §2 groups A, B, C, D, E, G, H), validated
// before being returned. A seed-data error (a bad construction call, or a
// duplicate ID introduced while hand-authoring across family files) returns
// an error here rather than a silently incomplete or invalid catalog.
func AudspectAVAttackCatalog() ([]Vector, error) {
	var all []Vector

	families := []func() ([]Vector, error){
		fileBasedVectors, scriptFilelessVectors, behavioralVectors, configurationWeaknessVectors,
		networkDeliveredVectors, credentialPersistenceVectors, falsePositiveResilienceVectors,
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
