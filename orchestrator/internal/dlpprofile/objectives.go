package dlpprofile

import "fmt"

// CoverageStatus is whether a named industry/regional control objective
// has a real, evidence-backed scenario mapping, or is an honest gap.
type CoverageStatus string

const (
	CoverageStatusCovered CoverageStatus = "covered"
	CoverageStatusGap     CoverageStatus = "gap"
)

func validCoverageStatus(s CoverageStatus) bool {
	switch s {
	case CoverageStatusCovered, CoverageStatusGap:
		return true
	default:
		return false
	}
}

// ControlObjectiveCoverage is one named risk/control objective's mapping
// record for an industry or regional profile that needs per-requirement
// granularity, rather than a flat VectorIDs list: the real scenario ID
// that satisfies the objective (when one exists), the rationale for why
// that scenario is relevant to this specific objective, what evidence it
// is expected to produce, and an explicit coverage status. This exists so
// that "no valid mapping exists" can be recorded as a first-class fact --
// a Gap -- instead of silently omitted or papered over by assigning an
// unrelated scenario.
type ControlObjectiveCoverage struct {
	Objective        string
	VectorID         string
	Rationale        string
	RequiredEvidence string
	Status           CoverageStatus
}

// NewControlObjectiveCoverage validates at construction time. Objective
// and Rationale are always required. A Covered entry must name a real
// VectorID and its RequiredEvidence; a Gap entry must name neither --
// a gap is a gap, never a disguised mapping with the vector field left
// blank by accident.
func NewControlObjectiveCoverage(objective string, vectorID string, rationale string, requiredEvidence string, status CoverageStatus) (ControlObjectiveCoverage, error) {
	if objective == "" {
		return ControlObjectiveCoverage{}, fmt.Errorf("objective must not be empty")
	}
	if rationale == "" {
		return ControlObjectiveCoverage{}, fmt.Errorf("rationale must not be empty")
	}
	if !validCoverageStatus(status) {
		return ControlObjectiveCoverage{}, fmt.Errorf("status %q is not one of the known CoverageStatus constants", status)
	}
	switch status {
	case CoverageStatusCovered:
		if vectorID == "" {
			return ControlObjectiveCoverage{}, fmt.Errorf("objective %q is marked covered but names no vectorID", objective)
		}
		if requiredEvidence == "" {
			return ControlObjectiveCoverage{}, fmt.Errorf("objective %q is marked covered but names no requiredEvidence", objective)
		}
	case CoverageStatusGap:
		if vectorID != "" {
			return ControlObjectiveCoverage{}, fmt.Errorf("objective %q is marked a gap but names vectorID %q -- a gap must never carry a vector mapping", objective, vectorID)
		}
		if requiredEvidence != "" {
			return ControlObjectiveCoverage{}, fmt.Errorf("objective %q is marked a gap but names requiredEvidence -- a gap must never carry evidence that does not exist", objective)
		}
	}
	return ControlObjectiveCoverage{Objective: objective, VectorID: vectorID, Rationale: rationale, RequiredEvidence: requiredEvidence, Status: status}, nil
}

// ValidateControlObjectivesAgainstCatalog confirms every Covered
// objective's VectorID actually exists in knownIDs, naming the first
// objective whose mapping is stale.
func ValidateControlObjectivesAgainstCatalog(objectives []ControlObjectiveCoverage, knownIDs map[string]bool) error {
	for _, o := range objectives {
		if o.Status == CoverageStatusCovered && !knownIDs[o.VectorID] {
			return fmt.Errorf("control objective %q references scenario ID %q, which does not exist in the given real scenario ID list", o.Objective, o.VectorID)
		}
	}
	return nil
}
