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
// that does not.
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
	return nil
}
