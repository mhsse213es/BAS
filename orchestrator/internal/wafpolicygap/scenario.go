package wafpolicygap

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

func validWeakness(w WeaknessType) bool {
	switch w {
	case WeaknessDetectionOnlyMode, WeaknessExclusionRule, WeaknessOverlyBroadException,
		WeaknessPriorityConflict, WeaknessUnprotectedRoute, WeaknessMissingCoverage:
		return true
	default:
		return false
	}
}

// NewPolicyGapScenario validates at construction time, never at evaluation
// time. attackVectorID must reference a real ID in
// wafcatalog.AudspectWAFAttackCatalog() -- a fictional or retired vector ID
// is rejected here, never silently carried to evaluation.
func NewPolicyGapScenario(
	id string,
	weakness WeaknessType,
	attackVectorID string,
	baselineDesc string,
	weakenedDesc string,
	provenance string,
) (PolicyGapScenario, error) {
	if id == "" {
		return PolicyGapScenario{}, fmt.Errorf("id must not be empty")
	}
	if !validWeakness(weakness) {
		return PolicyGapScenario{}, fmt.Errorf("weakness %q is not one of the known WeaknessType constants", weakness)
	}
	if attackVectorID == "" {
		return PolicyGapScenario{}, fmt.Errorf("attackVectorID must not be empty")
	}
	vectors, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return PolicyGapScenario{}, fmt.Errorf("loading wafcatalog for cross-reference: %w", err)
	}
	found := false
	for _, v := range vectors {
		if v.ID == attackVectorID {
			found = true
			break
		}
	}
	if !found {
		return PolicyGapScenario{}, fmt.Errorf("attackVectorID %q does not exist in wafcatalog.AudspectWAFAttackCatalog()", attackVectorID)
	}
	if baselineDesc == "" {
		return PolicyGapScenario{}, fmt.Errorf("baselineDesc must not be empty")
	}
	if weakenedDesc == "" {
		return PolicyGapScenario{}, fmt.Errorf("weakenedDesc must not be empty")
	}
	if provenance == "" {
		return PolicyGapScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return PolicyGapScenario{
		ID: id, Weakness: weakness, AttackVectorID: attackVectorID,
		BaselinePolicyDescription: baselineDesc, WeakenedPolicyDescription: weakenedDesc, Provenance: provenance,
	}, nil
}
