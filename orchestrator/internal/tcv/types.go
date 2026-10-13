package tcv

import "time"

// ClockKind is one of TCV's two immutable start clocks (spec §10.2).
type ClockKind string

const (
	ClockThreat       ClockKind = "threat"
	ClockIntelligence ClockKind = "intelligence"
)

// RelationshipKind mirrors content_version_threats.relationship_kind --
// the two ways a content version can cover a threat (spec §9.1, §10.3).
type RelationshipKind string

const (
	RelationshipEmulates     RelationshipKind = "emulates"
	RelationshipGeneratedFor RelationshipKind = "generated_for"
)

// MetricState classifies one TCV metric's current shape (spec §10.4).
type MetricState string

const (
	// StateNoClock: the relevant clock (threat or intelligence) has never
	// started for this threat -- there is no evidence to measure from yet.
	StateNoClock MetricState = "no_clock"
	// StateOpen: the clock started but no qualifying content has yet
	// become executable coverage. Only ElapsedSeconds moves over time.
	StateOpen MetricState = "open"
	// StatePreExisting: content became executable coverage BEFORE the
	// clock started (e.g. a generic technique-overlap scenario already
	// existed). TCVSeconds is always 0, never negative.
	StatePreExisting MetricState = "pre_existing"
	// StateMeasured: the normal case -- coverage became executable at or
	// after the clock started. TCVSeconds is the real elapsed duration.
	StateMeasured MetricState = "measured"
)

// Metric is one of TCV's four measurements for a single threat (spec
// §10.4): Threat→Emulation, Threat→Generation, Intelligence→Emulation,
// Intelligence→Generation. Exactly one of (TCVSeconds, ElapsedSeconds) is
// set, and only when State is StateMeasured/StatePreExisting or StateOpen
// respectively; both are nil for StateNoClock.
type Metric struct {
	ClockStartedAt *time.Time  `json:"clockStartedAt,omitempty"`
	CoveredAt      *time.Time  `json:"coveredAt,omitempty"`
	State          MetricState `json:"state"`
	TCVSeconds     *int64      `json:"tcvSeconds,omitempty"`
	ElapsedSeconds *int64      `json:"elapsedSeconds,omitempty"`
}

// ThreatTCV is the full read-model for GET /api/intel/threats/{id}/tcv.
type ThreatTCV struct {
	ThreatID                 string `json:"threatId"`
	ThreatToEmulation        Metric `json:"threatToEmulation"`
	ThreatToGeneration       Metric `json:"threatToGeneration"`
	IntelligenceToEmulation  Metric `json:"intelligenceToEmulation"`
	IntelligenceToGeneration Metric `json:"intelligenceToGeneration"`
}
