package avefficacy

import (
	"fmt"

	"github.com/audspect/bas/internal/avcatalog"
)

// EfficacyScenario bundles a subset of avcatalog's real vector IDs under
// one customer-facing security objective. It evaluates nothing itself --
// it is a reference layer, mirroring wafassessment.EnterpriseScenario's own
// "bundling, not evaluating" shape.
type EfficacyScenario struct {
	ID                    string
	Name                  string
	Objective             string
	ContributingVectorIDs []string
	Prerequisites         string
	EvidenceRequirement   string
	Provenance            string
}

// NewEfficacyScenario validates at construction time, never at evaluation
// time: every string field must be non-empty, ContributingVectorIDs must be
// non-empty with no empty or duplicate entries.
func NewEfficacyScenario(id, name, objective string, contributingVectorIDs []string, prerequisites, evidenceRequirement, provenance string) (EfficacyScenario, error) {
	if id == "" {
		return EfficacyScenario{}, fmt.Errorf("id must not be empty")
	}
	if name == "" {
		return EfficacyScenario{}, fmt.Errorf("name must not be empty")
	}
	if objective == "" {
		return EfficacyScenario{}, fmt.Errorf("objective must not be empty")
	}
	if len(contributingVectorIDs) == 0 {
		return EfficacyScenario{}, fmt.Errorf("contributingVectorIDs must not be empty")
	}
	seen := make(map[string]bool, len(contributingVectorIDs))
	for _, vectorID := range contributingVectorIDs {
		if vectorID == "" {
			return EfficacyScenario{}, fmt.Errorf("contributingVectorIDs must not contain an empty ID")
		}
		if seen[vectorID] {
			return EfficacyScenario{}, fmt.Errorf("contributingVectorIDs contains a duplicate ID %q", vectorID)
		}
		seen[vectorID] = true
	}
	if prerequisites == "" {
		return EfficacyScenario{}, fmt.Errorf("prerequisites must not be empty")
	}
	if evidenceRequirement == "" {
		return EfficacyScenario{}, fmt.Errorf("evidenceRequirement must not be empty")
	}
	if provenance == "" {
		return EfficacyScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return EfficacyScenario{
		ID: id, Name: name, Objective: objective, ContributingVectorIDs: contributingVectorIDs,
		Prerequisites: prerequisites, EvidenceRequirement: evidenceRequirement, Provenance: provenance,
	}, nil
}

// ValidateAgainstCatalog confirms every one of scenario's
// ContributingVectorIDs actually exists in catalog, returning an error
// naming the first one that does not.
func ValidateAgainstCatalog(scenario EfficacyScenario, catalog []avcatalog.Vector) error {
	known := make(map[string]bool, len(catalog))
	for _, v := range catalog {
		known[v.ID] = true
	}
	return ValidateAgainstKnownIDs(scenario, known)
}

// ValidateAgainstKnownIDs confirms every one of scenario's
// ContributingVectorIDs is a key of knownIDs, returning an error naming the
// first one that is not.
func ValidateAgainstKnownIDs(scenario EfficacyScenario, knownIDs map[string]bool) error {
	for _, vectorID := range scenario.ContributingVectorIDs {
		if !knownIDs[vectorID] {
			return fmt.Errorf("scenario %q references vector ID %q, which does not exist in the given catalog", scenario.ID, vectorID)
		}
	}
	return nil
}
