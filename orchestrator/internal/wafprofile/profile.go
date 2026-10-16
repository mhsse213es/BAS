package wafprofile

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
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

// Profile bundles a subset of wafcatalog's real attack-vector IDs with
// the compliance frameworks that make them relevant to a named industry
// or region. It evaluates nothing itself -- it is a reference layer.
type Profile struct {
	ID                   string
	Name                 string
	Kind                 ProfileKind
	AttackVectorIDs      []string
	ComplianceReferences []ComplianceReference
	Rationale            string
	Provenance           string
}

// NewProfile validates at construction time, never at render time. It
// re-validates each ComplianceReferences entry's own fields rather than
// trusting the caller already went through NewComplianceReference --
// a struct literal can bypass that constructor entirely.
func NewProfile(id string, name string, kind ProfileKind, attackVectorIDs []string, complianceReferences []ComplianceReference, rationale string, provenance string) (Profile, error) {
	if id == "" {
		return Profile{}, fmt.Errorf("id must not be empty")
	}
	if name == "" {
		return Profile{}, fmt.Errorf("name must not be empty")
	}
	if !validProfileKind(kind) {
		return Profile{}, fmt.Errorf("kind %q is not one of the known ProfileKind constants", kind)
	}
	if len(attackVectorIDs) == 0 {
		return Profile{}, fmt.Errorf("attackVectorIDs must not be empty")
	}
	seen := make(map[string]bool, len(attackVectorIDs))
	for _, vectorID := range attackVectorIDs {
		if vectorID == "" {
			return Profile{}, fmt.Errorf("attackVectorIDs must not contain an empty ID")
		}
		if seen[vectorID] {
			return Profile{}, fmt.Errorf("attackVectorIDs contains a duplicate ID %q", vectorID)
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
	return Profile{ID: id, Name: name, Kind: kind, AttackVectorIDs: attackVectorIDs, ComplianceReferences: complianceReferences, Rationale: rationale, Provenance: provenance}, nil
}

// ValidateAgainstCatalog confirms every one of profile's AttackVectorIDs
// actually exists in catalog, returning an error naming the first one
// that does not -- catching a typo'd or since-removed vector ID.
func ValidateAgainstCatalog(profile Profile, catalog []wafcatalog.AttackVector) error {
	known := make(map[string]bool, len(catalog))
	for _, vector := range catalog {
		known[vector.ID] = true
	}
	for _, vectorID := range profile.AttackVectorIDs {
		if !known[vectorID] {
			return fmt.Errorf("profile %q references attack-vector ID %q, which does not exist in the given catalog", profile.ID, vectorID)
		}
	}
	return nil
}
