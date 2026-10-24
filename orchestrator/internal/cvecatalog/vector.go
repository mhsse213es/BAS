package cvecatalog

import (
	"fmt"
	"regexp"
	"time"

	"github.com/audspect/bas/internal/cveval"
)

var (
	cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)
)

func validSeverity(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return true
	default:
		return false
	}
}

func validExecutionProfile(p cveval.ExecutionProfile) bool {
	switch p {
	case cveval.ProfileFixtureOnly, cveval.ProfileLabCapable:
		return true
	default:
		return false
	}
}

func validateVersionRange(r VersionRange) error {
	if r.Introduced == "" && r.Fixed == "" {
		return fmt.Errorf("a VersionRange must set Introduced, Fixed, or both")
	}
	return nil
}

func validateAffectedProduct(p AffectedProduct) error {
	if p.Name == "" {
		return fmt.Errorf("AffectedProduct.Name must not be empty")
	}
	if len(p.Ranges) == 0 {
		return fmt.Errorf("AffectedProduct.Ranges must have at least one entry")
	}
	for i, r := range p.Ranges {
		if err := validateVersionRange(r); err != nil {
			return fmt.Errorf("AffectedProduct.Ranges[%d]: %w", i, err)
		}
	}
	return nil
}

func validateReferences(refs []Reference) error {
	if len(refs) == 0 {
		return fmt.Errorf("at least one Reference is required")
	}
	for i, r := range refs {
		if r.Source == "" || r.URL == "" {
			return fmt.Errorf("References[%d] must set both Source and URL", i)
		}
	}
	return nil
}

func validateFixture(f ConfigFixture, label string, want cveval.Verdict) error {
	if f.Description == "" {
		return fmt.Errorf("%s.Description must not be empty", label)
	}
	if f.Indicator == "" {
		return fmt.Errorf("%s.Indicator must not be empty", label)
	}
	if f.Implies != want {
		return fmt.Errorf("%s.Implies must be %q, got %q", label, want, f.Implies)
	}
	return nil
}

// NewCVEEntry validates at construction time, never at lookup time, so a
// malformed seed entry fails the build rather than silently shipping a
// catalog that cannot be trusted.
func NewCVEEntry(
	id string,
	cweIDs []string,
	severity Severity,
	affected AffectedProduct,
	description string,
	preconditions string,
	executionProfile cveval.ExecutionProfile,
	references []Reference,
	lastVerified string,
	vulnerableFixture ConfigFixture,
	patchedFixture ConfigFixture,
	provenance string,
) (CVEEntry, error) {
	if !cveIDPattern.MatchString(id) {
		return CVEEntry{}, fmt.Errorf("id %q does not match ^CVE-\\d{4}-\\d{4,}$", id)
	}
	for _, c := range cweIDs {
		if !cweIDPattern.MatchString(c) {
			return CVEEntry{}, fmt.Errorf("CWE ID %q does not match ^CWE-\\d+$", c)
		}
	}
	if !validSeverity(severity) {
		return CVEEntry{}, fmt.Errorf("severity %q is not one of the known Severity constants", severity)
	}
	if err := validateAffectedProduct(affected); err != nil {
		return CVEEntry{}, err
	}
	if description == "" {
		return CVEEntry{}, fmt.Errorf("description must not be empty")
	}
	if preconditions == "" {
		return CVEEntry{}, fmt.Errorf("preconditions must not be empty")
	}
	if !validExecutionProfile(executionProfile) {
		return CVEEntry{}, fmt.Errorf("executionProfile %q is not one of the known ExecutionProfile constants", executionProfile)
	}
	if err := validateReferences(references); err != nil {
		return CVEEntry{}, err
	}
	if _, err := time.Parse("2006-01-02", lastVerified); err != nil {
		return CVEEntry{}, fmt.Errorf("lastVerified %q must be an RFC3339 date (YYYY-MM-DD): %w", lastVerified, err)
	}
	if err := validateFixture(vulnerableFixture, "VulnerableFixture", cveval.VerdictVulnerable); err != nil {
		return CVEEntry{}, err
	}
	if err := validateFixture(patchedFixture, "PatchedFixture", cveval.VerdictNotVulnerable); err != nil {
		return CVEEntry{}, err
	}
	if vulnerableFixture.Indicator == patchedFixture.Indicator {
		return CVEEntry{}, fmt.Errorf("VulnerableFixture.Indicator and PatchedFixture.Indicator must differ")
	}
	if provenance == "" {
		return CVEEntry{}, fmt.Errorf("provenance must not be empty")
	}
	return CVEEntry{
		ID: id, CWEIDs: cweIDs, Severity: severity, AffectedProduct: affected,
		Description: description, Preconditions: preconditions, ExecutionProfile: executionProfile,
		References: references, LastVerified: lastVerified,
		VulnerableFixture: vulnerableFixture, PatchedFixture: patchedFixture, Provenance: provenance,
	}, nil
}
