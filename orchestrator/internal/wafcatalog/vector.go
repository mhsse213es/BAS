package wafcatalog

import (
	"fmt"
	"regexp"
)

var cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)

func validFamily(f AttackFamily) bool {
	switch f {
	case FamilySQLInjection, FamilyXSS, FamilyPathTraversal, FamilySSRF, FamilyFileUpload,
		FamilyHTTPParser, FamilyAPIAbuse, FamilyAuthAbuse, FamilyRateLimit, FamilyCacheWeakness, FamilyPolicyMisconfig:
		return true
	default:
		return false
	}
}

func validSeverity(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

func validateRequestTemplate(r RequestTemplate, label string) error {
	if r.Method == "" {
		return fmt.Errorf("%s.Method must not be empty", label)
	}
	if r.Path == "" {
		return fmt.Errorf("%s.Path must not be empty", label)
	}
	if r.Description == "" {
		return fmt.Errorf("%s.Description must not be empty", label)
	}
	return nil
}

func validateStandards(s StandardsMapping) error {
	for _, id := range s.CWEIDs {
		if !cweIDPattern.MatchString(id) {
			return fmt.Errorf("CWE ID %q does not match ^CWE-\\d+$", id)
		}
	}
	if len(s.CWEIDs) == 0 && s.WSTGCategory == "" && s.Top10Category == "" && s.APITop10Category == "" {
		return fmt.Errorf("Standards must set at least one of CWEIDs, WSTGCategory, Top10Category, APITop10Category")
	}
	return nil
}

// NewAttackVector validates at construction time, never at render time.
func NewAttackVector(
	id string,
	version int,
	family AttackFamily,
	name string,
	severity Severity,
	preconditions string,
	malicious RequestTemplate,
	benignCounterpart *RequestTemplate,
	noBenignCounterpartReason string,
	standards StandardsMapping,
	provenance string,
) (AttackVector, error) {
	if id == "" {
		return AttackVector{}, fmt.Errorf("id must not be empty")
	}
	if version < 1 {
		return AttackVector{}, fmt.Errorf("version must be >= 1, got %d", version)
	}
	if !validFamily(family) {
		return AttackVector{}, fmt.Errorf("family %q is not one of the known AttackFamily constants", family)
	}
	if !validSeverity(severity) {
		return AttackVector{}, fmt.Errorf("severity %q is not one of the known Severity constants", severity)
	}
	if err := validateRequestTemplate(malicious, "Malicious"); err != nil {
		return AttackVector{}, err
	}
	if err := validateStandards(standards); err != nil {
		return AttackVector{}, err
	}
	if provenance == "" {
		return AttackVector{}, fmt.Errorf("provenance must not be empty")
	}
	hasBenign := benignCounterpart != nil
	hasReason := noBenignCounterpartReason != ""
	if hasBenign == hasReason {
		return AttackVector{}, fmt.Errorf("exactly one of benignCounterpart or noBenignCounterpartReason must be set, got benignCounterpart set=%v, reason set=%v", hasBenign, hasReason)
	}
	if hasBenign {
		if err := validateRequestTemplate(*benignCounterpart, "BenignCounterpart"); err != nil {
			return AttackVector{}, err
		}
	}
	return AttackVector{
		ID: id, Version: version, Family: family, Name: name, Severity: severity,
		Preconditions: preconditions, Malicious: malicious, BenignCounterpart: benignCounterpart,
		NoBenignCounterpartReason: noBenignCounterpartReason, Standards: standards, Provenance: provenance,
	}, nil
}
