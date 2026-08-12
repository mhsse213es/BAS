package threatpriority

// DefaultFactors returns the 10 built-in factors in a stable order: 4
// Coverage, 2 Validation, 3 curated standalone, 1 activity. Order only
// affects the sequence of entries in ActorPriority.Factors, not scoring
// (each factor's Weight/Score is independent of the others).
func DefaultFactors() []ScoreFactor {
	return []ScoreFactor{
		SimulationCoverageFactor{},
		DetectionCoverageFactor{},
		PurpleCoverageFactor{},
		ComplianceCoverageFactor{},
		PreventionSuccessFactor{},
		ValidationSuccessFactor{},
		IntelFreshnessFactor{},
		RelevanceFactor{},
		ConfidenceFactor{},
		ActivityFactor{},
	}
}
