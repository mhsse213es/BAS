package contentregistry

import "fmt"

// ExclusionReason is the machine-readable reason for rejecting content. The
// five codes are the spec's exclusion list (2026-11-10 content-velocity spec,
// section 4). Free text is not accepted: exclusions must be countable.
type ExclusionReason string

const (
	ExclusionRelevance                   ExclusionReason = "relevance"
	ExclusionInsufficientTechnicalDetail ExclusionReason = "insufficient_technical_detail"
	ExclusionUnsupportedPlatform         ExclusionReason = "unsupported_platform"
	ExclusionValidationEnvUnavailable    ExclusionReason = "validation_environment_unavailable"
	ExclusionThirdPartyDependency        ExclusionReason = "third_party_dependency"
)

// ExclusionReasons lists every valid code. The database CHECK constraint must
// match this list exactly.
var ExclusionReasons = []ExclusionReason{
	ExclusionRelevance,
	ExclusionInsufficientTechnicalDetail,
	ExclusionUnsupportedPlatform,
	ExclusionValidationEnvUnavailable,
	ExclusionThirdPartyDependency,
}

// Valid reports whether r is one of the five spec codes.
func (r ExclusionReason) Valid() bool {
	for _, v := range ExclusionReasons {
		if r == v {
			return true
		}
	}
	return false
}

// ErrRejectionNeedsReason is returned when content is rejected without a valid
// exclusion code. Rejections are never recorded without one.
var ErrRejectionNeedsReason = fmt.Errorf("rejection requires a valid exclusion reason code")

// ValidateRejection enforces the rule before any write. A transition to
// REJECTED must carry one of the five codes. Other transitions carry no code.
func ValidateRejection(to Lifecycle, code ExclusionReason) error {
	if to != LifecycleRejected {
		return nil
	}
	if !code.Valid() {
		return fmt.Errorf("%w: got %q", ErrRejectionNeedsReason, string(code))
	}
	return nil
}
