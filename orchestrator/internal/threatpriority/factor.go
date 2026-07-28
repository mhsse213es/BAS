package threatpriority

import "context"

// ScoreFactor is one pluggable contributor to an actor's composite score.
// Weight takes Context (not a constant) because Coverage/Validation factors
// pick their weight band from ctx.ValidatedCount -- see blendWeights.
type ScoreFactor interface {
	Name() string
	Weight(ctx Context) float64
	// Score returns a 0-100 raw score, a human-readable explanation, and
	// whether real evidence backed the score at all (available=false when
	// there's nothing to measure yet -- e.g. an actor with zero tested
	// techniques). raw/explanation are meaningless when available=false.
	Score(ctx context.Context, tctx Context) (raw float64, explanation string, available bool, err error)
}
