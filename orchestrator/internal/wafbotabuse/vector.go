package wafbotabuse

import (
	"fmt"
	"regexp"
)

var cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)

func validCategory(c BotAbuseCategory) bool {
	switch c {
	case CategoryBoundedAutomation, CategoryRateLimit, CategoryCredentialAbuse, CategoryDistributedEnforcement:
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

// NewBotAbuseVector validates at construction time, never at render time.
func NewBotAbuseVector(
	id string,
	version int,
	category BotAbuseCategory,
	name string,
	severity Severity,
	preconditions string,
	malicious RequestTemplate,
	benignCounterpart *RequestTemplate,
	noBenignCounterpartReason string,
	standards StandardsMapping,
	provenance string,
) (BotAbuseVector, error) {
	if id == "" {
		return BotAbuseVector{}, fmt.Errorf("id must not be empty")
	}
	if version < 1 {
		return BotAbuseVector{}, fmt.Errorf("version must be >= 1, got %d", version)
	}
	if !validCategory(category) {
		return BotAbuseVector{}, fmt.Errorf("category %q is not one of the known BotAbuseCategory constants", category)
	}
	if !validSeverity(severity) {
		return BotAbuseVector{}, fmt.Errorf("severity %q is not one of the known Severity constants", severity)
	}
	if err := validateRequestTemplate(malicious, "Malicious"); err != nil {
		return BotAbuseVector{}, err
	}
	if err := validateStandards(standards); err != nil {
		return BotAbuseVector{}, err
	}
	if provenance == "" {
		return BotAbuseVector{}, fmt.Errorf("provenance must not be empty")
	}
	hasBenign := benignCounterpart != nil
	hasReason := noBenignCounterpartReason != ""
	if hasBenign == hasReason {
		return BotAbuseVector{}, fmt.Errorf("exactly one of benignCounterpart or noBenignCounterpartReason must be set, got benignCounterpart set=%v, reason set=%v", hasBenign, hasReason)
	}
	if hasBenign {
		if err := validateRequestTemplate(*benignCounterpart, "BenignCounterpart"); err != nil {
			return BotAbuseVector{}, err
		}
	}
	return BotAbuseVector{
		ID: id, Version: version, Category: category, Name: name, Severity: severity,
		Preconditions: preconditions, Malicious: malicious, BenignCounterpart: benignCounterpart,
		NoBenignCounterpartReason: noBenignCounterpartReason, Standards: standards, Provenance: provenance,
	}, nil
}
