package correlation

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/reporting"
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

// CorrelateActor resolves the actor's technique roster via the alias-aware
// reporting.ResolveActorTechniques (not threatgraph.ActorNeighborhood's own
// internal, unaliased GroupTechniqueIndex()[name] lookup -- see the
// Disambiguation note below), correlates each technique with shared verdict
// maps built once, and surfaces actor-level campaign/malware/tool from
// ActorNeighborhood (not per-technique -- intelligence_malware/tools aren't
// specific to one technique in the existing schema).
func (e *Engine) CorrelateActor(ctx context.Context, actorName string) (ActorCorrelation, error) {
	aliases, err := e.loadActorAliases(ctx, actorName)
	if err != nil {
		return ActorCorrelation{}, err
	}
	techIDs, _, _ := reporting.ResolveActorTechniques(actorName, aliases)

	prevention, err := threatpriority.LoadPreventionVerdicts(ctx, e.pool)
	if err != nil {
		return ActorCorrelation{}, err
	}
	validation, err := threatpriority.LoadValidationVerdicts(ctx, e.pool)
	if err != nil {
		return ActorCorrelation{}, err
	}

	ac := ActorCorrelation{ActorName: actorName}
	for _, id := range techIDs {
		tc, err := e.correlateTechnique(ctx, id, prevention, validation)
		if err != nil {
			return ActorCorrelation{}, err
		}
		ac.Techniques = append(ac.Techniques, tc)
	}

	nb, err := threatgraph.ActorNeighborhood(ctx, e.pool, actorName)
	if err != nil {
		return ActorCorrelation{}, err
	}
	// Disambiguation: ActorNeighborhood also resolves and returns its own
	// technique nodes internally (assemble.go:194, the unaliased
	// GroupTechniqueIndex()[name] path this package does not standardize
	// on) -- only campaign/malware/tool nodes are kept here; technique
	// (and actor/sector/region) nodes are discarded, since the technique
	// roster above already came exclusively from ResolveActorTechniques.
	for _, node := range nb.Nodes {
		switch node.Type {
		case threatgraph.NodeTypeCampaign:
			ac.Campaigns = append(ac.Campaigns, node)
		case threatgraph.NodeTypeMalware:
			ac.Malware = append(ac.Malware, node)
		case threatgraph.NodeTypeTool:
			ac.Tools = append(ac.Tools, node)
		}
	}
	return ac, nil
}

// loadActorAliases is a small, independent query -- matches this session's
// established tolerance for this scale of duplication between independent
// read paths (internal/db.GetRunIOCsEnriched vs. GetRunIOCs is the
// precedent) rather than exporting threatpriority's own unexported
// loadProfile just for this one column.
func (e *Engine) loadActorAliases(ctx context.Context, name string) ([]string, error) {
	var aliases []string
	err := e.pool.QueryRow(ctx, `SELECT aliases FROM threat_actor_profiles WHERE name = $1`, name).Scan(&aliases)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return aliases, err
}
