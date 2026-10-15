package wafevasion

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

func validTechnique(t EvasionTechnique) bool {
	switch t {
	case EvasionEncodingObfuscation, EvasionNormalizationMismatch, EvasionContentTypeConfusion,
		EvasionHTTPDiscrepancy, EvasionMultipartBoundaryManipulation, EvasionRequestBoundaryAbuse:
		return true
	default:
		return false
	}
}

// NewEvasionScenario validates at construction time, never at evaluation
// time. attackVectorID must reference a real ID in
// wafcatalog.AudspectWAFAttackCatalog() -- a fictional or retired vector ID
// is rejected here, never silently carried to evaluation.
func NewEvasionScenario(
	id string,
	technique EvasionTechnique,
	attackVectorID string,
	canonicalDesc string,
	evasiveDesc string,
	originEquivalenceRationale string,
	provenance string,
) (EvasionScenario, error) {
	if id == "" {
		return EvasionScenario{}, fmt.Errorf("id must not be empty")
	}
	if !validTechnique(technique) {
		return EvasionScenario{}, fmt.Errorf("technique %q is not one of the known EvasionTechnique constants", technique)
	}
	if attackVectorID == "" {
		return EvasionScenario{}, fmt.Errorf("attackVectorID must not be empty")
	}
	vectors, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EvasionScenario{}, fmt.Errorf("loading wafcatalog for cross-reference: %w", err)
	}
	found := false
	for _, v := range vectors {
		if v.ID == attackVectorID {
			found = true
			break
		}
	}
	if !found {
		return EvasionScenario{}, fmt.Errorf("attackVectorID %q does not exist in wafcatalog.AudspectWAFAttackCatalog()", attackVectorID)
	}
	if canonicalDesc == "" {
		return EvasionScenario{}, fmt.Errorf("canonicalDesc must not be empty")
	}
	if evasiveDesc == "" {
		return EvasionScenario{}, fmt.Errorf("evasiveDesc must not be empty")
	}
	if originEquivalenceRationale == "" {
		return EvasionScenario{}, fmt.Errorf("originEquivalenceRationale must not be empty")
	}
	if provenance == "" {
		return EvasionScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return EvasionScenario{
		ID: id, Technique: technique, AttackVectorID: attackVectorID,
		CanonicalPayloadDescription: canonicalDesc, EvasivePayloadDescription: evasiveDesc,
		OriginEquivalenceRationale: originEquivalenceRationale, Provenance: provenance,
	}, nil
}
