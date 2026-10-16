package avcatalog

import (
	"fmt"
	"regexp"

	"github.com/audspect/bas/internal/avval"
)

var attackTechniquePattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
var cweIDPattern = regexp.MustCompile(`^CWE-\d+$`)

func validFamily(f AttackFamily) bool {
	switch f {
	case FamilyFileBasedThreat, FamilyScriptFileless, FamilyBehavioralExploit,
		FamilyNetworkDelivered, FamilyCredentialPersistence, FamilyFalsePositiveResilience:
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

func validPlatform(p Platform) bool {
	switch p {
	case PlatformWindowsWorkstation, PlatformWindowsServer, PlatformLinuxServer, PlatformMacOS:
		return true
	default:
		return false
	}
}

func validCapability(c RequiredCapability) bool {
	switch c {
	case CapabilitySignatureAV, CapabilityBehavioralNGAV, CapabilityEDRResponse, CapabilityNetworkControl:
		return true
	default:
		return false
	}
}

func validClaim(c avval.ClaimType) bool {
	return c == avval.ClaimPrevention || c == avval.ClaimFalsePositive
}

func validateExecutionTemplate(e ExecutionTemplate, label string) error {
	if e.Executor == "" {
		return fmt.Errorf("%s.Executor must not be empty", label)
	}
	if e.Command == "" {
		return fmt.Errorf("%s.Command must not be empty", label)
	}
	if e.Description == "" {
		return fmt.Errorf("%s.Description must not be empty", label)
	}
	return nil
}

func validateStandards(s StandardsMapping) error {
	if len(s.ATTACKTechniques) == 0 {
		return fmt.Errorf("Standards.ATTACKTechniques must have at least one entry")
	}
	for _, t := range s.ATTACKTechniques {
		if !attackTechniquePattern.MatchString(t) {
			return fmt.Errorf("ATT&CK technique %q does not match ^T\\d{4}(\\.\\d{3})?$", t)
		}
	}
	for _, id := range s.CWEIDs {
		if !cweIDPattern.MatchString(id) {
			return fmt.Errorf("CWE ID %q does not match ^CWE-\\d+$", id)
		}
	}
	return nil
}

// NewVector validates at construction time, never at render time.
func NewVector(
	id string,
	version int,
	family AttackFamily,
	name string,
	severity Severity,
	platforms []Platform,
	requiredCapabilities []RequiredCapability,
	preconditions string,
	primaryClaim avval.ClaimType,
	primary ExecutionTemplate,
	counterpart *ExecutionTemplate,
	noCounterpartReason string,
	cleanupRequirement string,
	limitations string,
	standards StandardsMapping,
	provenance string,
) (Vector, error) {
	if id == "" {
		return Vector{}, fmt.Errorf("id must not be empty")
	}
	if version < 1 {
		return Vector{}, fmt.Errorf("version must be >= 1, got %d", version)
	}
	if !validFamily(family) {
		return Vector{}, fmt.Errorf("family %q is not one of the known AttackFamily constants", family)
	}
	if !validSeverity(severity) {
		return Vector{}, fmt.Errorf("severity %q is not one of the known Severity constants", severity)
	}
	if len(platforms) == 0 {
		return Vector{}, fmt.Errorf("at least one Platform must be declared")
	}
	for _, p := range platforms {
		if !validPlatform(p) {
			return Vector{}, fmt.Errorf("platform %q is not one of the known Platform constants", p)
		}
	}
	if len(requiredCapabilities) == 0 {
		return Vector{}, fmt.Errorf("at least one RequiredCapability must be declared")
	}
	for _, c := range requiredCapabilities {
		if !validCapability(c) {
			return Vector{}, fmt.Errorf("capability %q is not one of the known RequiredCapability constants", c)
		}
	}
	if !validClaim(primaryClaim) {
		return Vector{}, fmt.Errorf("primaryClaim %q is not one of avval.ClaimPrevention/ClaimFalsePositive", primaryClaim)
	}
	if err := validateExecutionTemplate(primary, "Primary"); err != nil {
		return Vector{}, err
	}
	if err := validateStandards(standards); err != nil {
		return Vector{}, err
	}
	if cleanupRequirement == "" {
		return Vector{}, fmt.Errorf("cleanupRequirement must not be empty")
	}
	if provenance == "" {
		return Vector{}, fmt.Errorf("provenance must not be empty")
	}
	hasCounterpart := counterpart != nil
	hasReason := noCounterpartReason != ""
	if hasCounterpart == hasReason {
		return Vector{}, fmt.Errorf("exactly one of counterpart or noCounterpartReason must be set, got counterpart set=%v, reason set=%v", hasCounterpart, hasReason)
	}
	if hasCounterpart {
		if err := validateExecutionTemplate(*counterpart, "Counterpart"); err != nil {
			return Vector{}, err
		}
	}
	return Vector{
		ID: id, Version: version, Family: family, Name: name, Severity: severity,
		Platforms: platforms, RequiredCapabilities: requiredCapabilities, Preconditions: preconditions,
		PrimaryClaim: primaryClaim, Primary: primary, Counterpart: counterpart,
		NoCounterpartReason: noCounterpartReason, CleanupRequirement: cleanupRequirement,
		Limitations: limitations, Standards: standards, Provenance: provenance,
	}, nil
}
