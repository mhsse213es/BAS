package avprofile

import (
	"fmt"

	"github.com/audspect/bas/internal/avcatalog"
)

// ProfileKind distinguishes an industry profile from a regional one.
type ProfileKind string

const (
	ProfileIndustry ProfileKind = "industry"
	ProfileRegional ProfileKind = "regional"
)

func validProfileKind(k ProfileKind) bool {
	switch k {
	case ProfileIndustry, ProfileRegional:
		return true
	default:
		return false
	}
}

// Profile bundles a subset of avcatalog's real vector IDs with the
// compliance frameworks that make them relevant to a named industry or
// region. It evaluates nothing itself -- it is a reference layer.
type Profile struct {
	ID                   string
	Name                 string
	Kind                 ProfileKind
	VectorIDs            []string
	ComplianceReferences []ComplianceReference
	Rationale            string
	Provenance           string
	// ControlObjectives is the optional requirement-level mapping record
	// behind VectorIDs: one entry per named risk/control objective this
	// industry or region cares about, whether a real vector satisfies
	// it, and an explicit Gap when none does (see ControlObjectiveCoverage).
	// Empty for profiles authored before this field existed (BFSI, NBFC,
	// Manufacturing, Healthcare, India, UAE), which carry only the flat
	// VectorIDs/Rationale shape -- that omission is not itself a defect,
	// just a coarser-grained profile.
	ControlObjectives []ControlObjectiveCoverage
}

// WithControlObjectives is a profile-construction helper, used in place
// of setting the field directly, so every Profile carrying this richer
// shape is re-validated the same way NewProfile validates everything
// else: at construction time, not at render time. It does not duplicate
// NewProfile's own field checks -- call NewProfile first, then this.
func WithControlObjectives(profile Profile, objectives []ControlObjectiveCoverage) (Profile, error) {
	if len(objectives) == 0 {
		return Profile{}, fmt.Errorf("objectives must not be empty")
	}
	seen := make(map[string]bool, len(objectives))
	for _, o := range objectives {
		if seen[o.Objective] {
			return Profile{}, fmt.Errorf("objectives contains a duplicate objective %q", o.Objective)
		}
		seen[o.Objective] = true
	}
	profile.ControlObjectives = objectives
	return profile, nil
}

// NewProfile validates at construction time, never at render time. It
// re-validates each ComplianceReferences entry's own fields rather than
// trusting the caller already went through NewComplianceReference.
func NewProfile(id string, name string, kind ProfileKind, vectorIDs []string, complianceReferences []ComplianceReference, rationale string, provenance string) (Profile, error) {
	if id == "" {
		return Profile{}, fmt.Errorf("id must not be empty")
	}
	if name == "" {
		return Profile{}, fmt.Errorf("name must not be empty")
	}
	if !validProfileKind(kind) {
		return Profile{}, fmt.Errorf("kind %q is not one of the known ProfileKind constants", kind)
	}
	if len(vectorIDs) == 0 {
		return Profile{}, fmt.Errorf("vectorIDs must not be empty")
	}
	seen := make(map[string]bool, len(vectorIDs))
	for _, vectorID := range vectorIDs {
		if vectorID == "" {
			return Profile{}, fmt.Errorf("vectorIDs must not contain an empty ID")
		}
		if seen[vectorID] {
			return Profile{}, fmt.Errorf("vectorIDs contains a duplicate ID %q", vectorID)
		}
		seen[vectorID] = true
	}
	if len(complianceReferences) == 0 {
		return Profile{}, fmt.Errorf("complianceReferences must not be empty")
	}
	for _, ref := range complianceReferences {
		if ref.Framework == "" {
			return Profile{}, fmt.Errorf("a complianceReferences entry has an empty Framework")
		}
		if !validVerificationStatus(ref.VerificationStatus) {
			return Profile{}, fmt.Errorf("a complianceReferences entry has status %q, not one of the known VerificationStatus constants", ref.VerificationStatus)
		}
		if ref.Note == "" {
			return Profile{}, fmt.Errorf("a complianceReferences entry has an empty Note")
		}
	}
	if rationale == "" {
		return Profile{}, fmt.Errorf("rationale must not be empty")
	}
	if provenance == "" {
		return Profile{}, fmt.Errorf("provenance must not be empty")
	}
	return Profile{ID: id, Name: name, Kind: kind, VectorIDs: vectorIDs, ComplianceReferences: complianceReferences, Rationale: rationale, Provenance: provenance}, nil
}

// ValidateAgainstCatalog confirms every one of profile's VectorIDs
// actually exists in catalog, returning an error naming the first one
// that does not. It also validates profile.ControlObjectives, when
// present, against the same catalog.
func ValidateAgainstCatalog(profile Profile, catalog []avcatalog.Vector) error {
	known := make(map[string]bool, len(catalog))
	for _, v := range catalog {
		known[v.ID] = true
	}
	for _, vectorID := range profile.VectorIDs {
		if !known[vectorID] {
			return fmt.Errorf("profile %q references vector ID %q, which does not exist in the given catalog", profile.ID, vectorID)
		}
	}
	if err := ValidateControlObjectivesAgainstCatalog(profile.ControlObjectives, known); err != nil {
		return fmt.Errorf("profile %q: %w", profile.ID, err)
	}
	return nil
}
