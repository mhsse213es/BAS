// Package rwevidence is a dedicated, capability-specific evidence engine
// for ransomware techniques -- the ransomware equivalent of
// adprimitive/admatrix/controlval (AD) and latmove/latdetect (lateral
// movement). It proves whether a deployed control actually prevented,
// detected, contained, recovered from, or protected data against a
// ransomware behavior, as independently-verified evidence rather than a
// scenario step merely running.
//
// This first slice covers exactly one technique (T1490, Inhibit System
// Recovery) and three of the five capability dimensions (Prevention,
// Recovery, Detection). Containment and DataProtection, every real
// observer, and any scoring/weighting UI are explicitly deferred.
package rwevidence

import "github.com/audspect/bas/internal/controlval"

// Capability names one of the five ransomware-mastery reporting dimensions.
// These are reporting categories, not independent execution engines: one
// technique can and does produce several independently-verified
// CapabilityResults, one per applicable dimension -- never inferred from
// each other.
type Capability string

const (
	CapabilityPrevention     Capability = "prevention"
	CapabilityDetection      Capability = "detection"
	CapabilityContainment    Capability = "containment"
	CapabilityRecovery       Capability = "recovery"
	CapabilityDataProtection Capability = "data_protection"
)

// CapabilityResult is one independently-verified claim about one capability
// dimension for one technique attempt.
type CapabilityResult struct {
	Capability  Capability
	TechniqueID string
	Verdict     controlval.Verdict
	SkipReason  controlval.SkipReason
	Reason      string
	Provenance  controlval.CorrelationKey
}

// AttemptKey identifies one technique attempt, for correlating independent
// observers (Recovery, ...) against the same event.
type AttemptKey struct {
	RunID       string
	TechniqueID string
}
