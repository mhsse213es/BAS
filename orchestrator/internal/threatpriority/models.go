// Package threatpriority computes a standing, fleet-wide, per-actor
// composite priority score from a pluggable set of ScoreFactors. It has no
// dependency on internal/connector -- connector.Scheduler depends on this
// package, not the reverse, to avoid an import cycle.
package threatpriority

import "time"

// FactorResult is one factor's contribution to an actor's composite score.
// Available=false means "no evidence yet" (rendered as "Not yet validated"
// in the UI), not a zero score -- a factor with no data must never silently
// drag the composite down.
type FactorResult struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	RawScore    float64 `json:"rawScore"`
	Weighted    float64 `json:"weighted"`
	Explanation string  `json:"explanation"`
	Available   bool    `json:"available"`
}

// VerdictEntry is one technique's latest fleet-wide verdict plus when it was
// recorded -- exported so internal/correlation (and any future consumer) can
// reuse the exact same "what does fleet-wide validation status mean" logic
// instead of re-deriving it.
type VerdictEntry struct {
	Verdict string
	At      time.Time
}

// ActorProfile mirrors a threat_actor_profiles row.
type ActorProfile struct {
	Name       string
	Aliases    []string
	Sectors    []string
	Regions    []string
	Confidence string
	// CanonicalGroupID is the resolved MITRE ATT&CK Group-ID (G####), or ""
	// if internal/connector.MergeActors couldn't confidently resolve one.
	CanonicalGroupID string
	LastSeen         *time.Time
}

// sharedIndexes holds engine-level, fleet-wide lookups computed once per
// Score/ScoreAll call and reused across every factor and every actor in that
// call -- never rebuilt per-actor or per-factor. Coverage indexes use raw
// technique-ID casing (matching internal/coverage's existing behavior,
// unmodified). Verdict indexes are keyed uppercase (matching the SQL that
// builds them in engine.go) -- callers must uppercase technique IDs before
// looking them up in preventionVerdict/validationVerdict.
type sharedIndexes struct {
	simulation, detection, purple, compliance map[string]bool
	preventionVerdict                         map[string]VerdictEntry // technique ID (upper) -> latest scenario_runs verdict+timestamp
	validationVerdict                         map[string]VerdictEntry // technique ID (upper) -> latest verification.Result*+timestamp
}

// Context is what every factor needs to score one actor. shared carries
// engine-level indexes computed once per Score/ScoreAll call (never once
// per factor) -- see engine.go.
type Context struct {
	ActorName      string
	TechniqueIDs   []string
	Profile        *ActorProfile
	Sectors        []string
	Regions        []string
	Now            time.Time
	ValidatedCount int

	shared *sharedIndexes
}

// ActorPriority is one actor's composite score plus every factor's
// contribution, so the UI can always show WHY, never just a bare number.
type ActorPriority struct {
	ActorName        string         `json:"actorName"`
	Score            int            `json:"score"`
	Tier             string         `json:"tier"`
	Factors          []FactorResult `json:"factors"`
	TechniqueCount   int            `json:"techniqueCount"`
	CoverageGapCount int            `json:"coverageGapCount"`
	Trend            string         `json:"trend"`
	TrendDelta       int            `json:"trendDelta,omitempty"`

	// CanonicalGroupID surfaces the actor's resolved MITRE ATT&CK Group-ID
	// (G####), when one was resolved, so the UI can show provenance beyond
	// whatever name a connector happened to report it under.
	CanonicalGroupID string `json:"canonicalGroupId,omitempty"`

	// TechniqueIDs is this actor's resolved ATT&CK technique roster. Used by
	// the Recommendations rollup (internal/api's buildActorPriorityByTechnique)
	// and the Actor Details UI's client-side Recommendations filter.
	TechniqueIDs []string `json:"techniqueIds,omitempty"`
}

// ActorPriorityHistory is one threat_priority_history snapshot row.
type ActorPriorityHistory struct {
	ActorName  string    `json:"actorName"`
	Score      int       `json:"score"`
	RecordedAt time.Time `json:"recordedAt"`
}
