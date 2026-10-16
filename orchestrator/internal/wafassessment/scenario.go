package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// EnterpriseScenario bundles a subset of wafcatalog's real attack-vector
// IDs under one customer-facing security objective. It evaluates nothing
// itself -- it is a reference layer, mirroring wafprofile.Profile's own
// "bundling, not evaluating" shape.
type EnterpriseScenario struct {
	ID                    string
	Name                  string
	Objective             string
	ContributingVectorIDs []string
	Prerequisites         string
	EvidenceRequirement   string
	Provenance            string
}

// NewEnterpriseScenario validates at construction time, never at
// evaluation time: every string field must be non-empty,
// ContributingVectorIDs must be non-empty with no empty or duplicate
// entries.
func NewEnterpriseScenario(id, name, objective string, contributingVectorIDs []string, prerequisites, evidenceRequirement, provenance string) (EnterpriseScenario, error) {
	if id == "" {
		return EnterpriseScenario{}, fmt.Errorf("id must not be empty")
	}
	if name == "" {
		return EnterpriseScenario{}, fmt.Errorf("name must not be empty")
	}
	if objective == "" {
		return EnterpriseScenario{}, fmt.Errorf("objective must not be empty")
	}
	if len(contributingVectorIDs) == 0 {
		return EnterpriseScenario{}, fmt.Errorf("contributingVectorIDs must not be empty")
	}
	seen := make(map[string]bool, len(contributingVectorIDs))
	for _, vectorID := range contributingVectorIDs {
		if vectorID == "" {
			return EnterpriseScenario{}, fmt.Errorf("contributingVectorIDs must not contain an empty ID")
		}
		if seen[vectorID] {
			return EnterpriseScenario{}, fmt.Errorf("contributingVectorIDs contains a duplicate ID %q", vectorID)
		}
		seen[vectorID] = true
	}
	if prerequisites == "" {
		return EnterpriseScenario{}, fmt.Errorf("prerequisites must not be empty")
	}
	if evidenceRequirement == "" {
		return EnterpriseScenario{}, fmt.Errorf("evidenceRequirement must not be empty")
	}
	if provenance == "" {
		return EnterpriseScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return EnterpriseScenario{
		ID: id, Name: name, Objective: objective, ContributingVectorIDs: contributingVectorIDs,
		Prerequisites: prerequisites, EvidenceRequirement: evidenceRequirement, Provenance: provenance,
	}, nil
}

// ValidateAgainstCatalog confirms every one of scenario's
// ContributingVectorIDs actually exists in catalog, returning an error
// naming the first one that does not -- catching a typo'd or
// since-removed vector ID. Mirrors wafprofile.ValidateAgainstCatalog
// exactly.
func ValidateAgainstCatalog(scenario EnterpriseScenario, catalog []wafcatalog.AttackVector) error {
	known := make(map[string]bool, len(catalog))
	for _, vector := range catalog {
		known[vector.ID] = true
	}
	for _, vectorID := range scenario.ContributingVectorIDs {
		if !known[vectorID] {
			return fmt.Errorf("scenario %q references attack-vector ID %q, which does not exist in the given catalog", scenario.ID, vectorID)
		}
	}
	return nil
}
