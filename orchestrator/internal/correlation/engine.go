package correlation

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/threatgraph"
	"github.com/audspect/bas/internal/threatpriority"
)

type Engine struct {
	pool           *pgxpool.Pool
	scenarioEngine *scenario.Engine
}

// NewEngine wires the engine to a Postgres pool (threatgraph/threatpriority
// queries) and the scenario Engine (scenariosForTechnique). Mirrors
// threatpriority.NewEngine's construction pattern.
func NewEngine(pool *pgxpool.Pool, scenarioEngine *scenario.Engine) *Engine {
	return &Engine{pool: pool, scenarioEngine: scenarioEngine}
}

// CorrelateTechnique is the standalone entry point: loads its own
// single-call verdict maps, then delegates to correlateTechnique.
func (e *Engine) CorrelateTechnique(ctx context.Context, techniqueID string) (TechniqueCorrelation, error) {
	prevention, err := threatpriority.LoadPreventionVerdicts(ctx, e.pool)
	if err != nil {
		return TechniqueCorrelation{}, err
	}
	validation, err := threatpriority.LoadValidationVerdicts(ctx, e.pool)
	if err != nil {
		return TechniqueCorrelation{}, err
	}
	return e.correlateTechnique(ctx, techniqueID, prevention, validation)
}

// correlateTechnique is the shared body CorrelateActor/CorrelateIOC call
// per-technique, taking already-built verdict maps so they're loaded once
// per Correlate* call, never once per technique -- the same "shared indexes
// built once" discipline threatpriority.Engine already established.
//
// Step 0 (Canonical Resolution) runs before any relationship lookup: see
// resolveCanonicalTechnique's doc comment for why -- TechniqueNeighborhood
// returns a completely empty Neighborhood for a technique with zero
// relationships, so deriving the name from it (the original design draft)
// would leave TechniqueName blank for most techniques.
func (e *Engine) correlateTechnique(ctx context.Context, techniqueID string, prevention, validation map[string]threatpriority.VerdictEntry) (TechniqueCorrelation, error) {
	tc := TechniqueCorrelation{Technique: resolveCanonicalTechnique(techniqueID)}

	nb, err := threatgraph.TechniqueNeighborhood(ctx, e.pool, tc.Technique.ID)
	if err != nil {
		return TechniqueCorrelation{}, err
	}
	for _, node := range nb.Nodes {
		switch node.Type {
		case threatgraph.NodeTypeActor:
			tc.Actors = append(tc.Actors, node)
		case threatgraph.NodeTypeCampaign:
			tc.Campaigns = append(tc.Campaigns, node)
		case threatgraph.NodeTypeMalware:
			tc.Malware = append(tc.Malware, node)
		case threatgraph.NodeTypeTool:
			tc.Tools = append(tc.Tools, node)
			// NodeTypeTechnique is the neighborhood's own self-node -- skipped,
			// Technique is already set above from Canonical Resolution.
		}
	}

	tc.Scenarios = scenariosForTechnique(e.scenarioEngine, tc.Technique.ID)
	tc.Validation = lookupValidation(tc.Technique.ID, prevention, validation)
	tc.Recommendation = computeRecommendation(tc.Validation, len(tc.Scenarios) > 0)
	return tc, nil
}
