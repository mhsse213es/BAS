package wafapiflow

import (
	"fmt"
	"regexp"
)

var cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)

func validCategory(c APIFlowCategory) bool {
	switch c {
	case CategorySchemaConformance, CategoryAuthBoundary, CategorySensitiveWorkflow, CategoryGraphQLAbuse, CategoryResourceControl:
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

// NewAPIFlowVector validates at construction time, never at render time.
func NewAPIFlowVector(
	id string,
	version int,
	category APIFlowCategory,
	name string,
	severity Severity,
	preconditions string,
	malicious RequestTemplate,
	benignCounterpart *RequestTemplate,
	noBenignCounterpartReason string,
	standards StandardsMapping,
	provenance string,
) (APIFlowVector, error) {
	if id == "" {
		return APIFlowVector{}, fmt.Errorf("id must not be empty")
	}
	if version < 1 {
		return APIFlowVector{}, fmt.Errorf("version must be >= 1, got %d", version)
	}
	if !validCategory(category) {
		return APIFlowVector{}, fmt.Errorf("category %q is not one of the known APIFlowCategory constants", category)
	}
	if !validSeverity(severity) {
		return APIFlowVector{}, fmt.Errorf("severity %q is not one of the known Severity constants", severity)
	}
	if err := validateRequestTemplate(malicious, "Malicious"); err != nil {
		return APIFlowVector{}, err
	}
	if err := validateStandards(standards); err != nil {
		return APIFlowVector{}, err
	}
	if provenance == "" {
		return APIFlowVector{}, fmt.Errorf("provenance must not be empty")
	}
	hasBenign := benignCounterpart != nil
	hasReason := noBenignCounterpartReason != ""
	if hasBenign == hasReason {
		return APIFlowVector{}, fmt.Errorf("exactly one of benignCounterpart or noBenignCounterpartReason must be set, got benignCounterpart set=%v, reason set=%v", hasBenign, hasReason)
	}
	if hasBenign {
		if err := validateRequestTemplate(*benignCounterpart, "BenignCounterpart"); err != nil {
			return APIFlowVector{}, err
		}
	}
	return APIFlowVector{
		ID: id, Version: version, Category: category, Name: name, Severity: severity,
		Preconditions: preconditions, Malicious: malicious, BenignCounterpart: benignCounterpart,
		NoBenignCounterpartReason: noBenignCounterpartReason, Standards: standards, Provenance: provenance,
	}, nil
}
