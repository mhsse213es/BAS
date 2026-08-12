package threatpriority

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/coverage"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/reporting"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

type Engine struct {
	pool           *pgxpool.Pool
	scenarioEngine *scenario.Engine
	sectors        []string
	regions        []string
	factors        []ScoreFactor
}

// NewEngine wires the engine to a Postgres pool (for threat_actor_profiles,
// scenario_runs, verification_history, threat_priority_history) and the
// scenario Engine (for BuildSimulationIndex/BuildProfileIndex/BuildComplianceIndex).
// sectors/regions are the org's static config.ThreatIntelSectors/Regions --
// held here at construction rather than threaded per-call, matching
// reporting.Engine's pattern (this package is a stateful Engine, unlike
// internal/recommend which is deliberately a stateless function library).
func NewEngine(pool *pgxpool.Pool, scenarioEngine *scenario.Engine, sectors, regions []string) *Engine {
	return &Engine{
		pool: pool, scenarioEngine: scenarioEngine,
		sectors: sectors, regions: regions,
		factors: DefaultFactors(),
	}
}

func (e *Engine) buildSharedIndexes(ctx context.Context) (*sharedIndexes, error) {
	scenarios := e.scenarioEngine.List()
	profiles := e.scenarioEngine.Profiles()

	purple := map[string]bool{}
	for _, tmpl := range exercise.BuiltinTemplates {
		for _, id := range tmpl.Metadata.ExpectedTechniques {
			purple[id] = true
		}
	}

	idx := &sharedIndexes{
		simulation: coverage.BuildSimulationIndex(scenarios),
		detection:  coverage.BuildProfileIndex(profiles),
		purple:     purple,
		compliance: coverage.BuildComplianceIndex(scenarios),
	}

	prevention, err := LoadPreventionVerdicts(ctx, e.pool)
	if err != nil {
		return nil, fmt.Errorf("load prevention verdicts: %w", err)
	}
	idx.preventionVerdict = prevention

	validation, err := LoadValidationVerdicts(ctx, e.pool)
	if err != nil {
		return nil, fmt.Errorf("load validation verdicts: %w", err)
	}
	idx.validationVerdict = validation

	return idx, nil
}

// LoadPreventionVerdicts returns, per technique ID (uppercase), the verdict
// of its most recent scenario_runs result (completed/partial runs only,
// error/skipped excluded) and when that run executed. Exported for
// internal/correlation (see
// docs/superpowers/specs/2026-08-05-intelligence-correlation-engine-design.md).
func LoadPreventionVerdicts(ctx context.Context, pool *pgxpool.Pool) (map[string]VerdictEntry, error) {
	if pool == nil {
		return map[string]VerdictEntry{}, nil
	}
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (UPPER(r->'technique'->>'id'))
		       UPPER(r->'technique'->>'id') AS tid,
		       r->>'result'                 AS verdict,
		       (r->>'executedAt')::timestamptz AS at
		FROM scenario_runs sr, jsonb_array_elements(sr.results) r
		WHERE sr.status IN ('completed', 'partial')
		  AND r->'technique'->>'id' IS NOT NULL AND r->'technique'->>'id' <> ''
		  AND r->>'result' NOT IN ('error', 'skipped')
		ORDER BY UPPER(r->'technique'->>'id'), (r->>'executedAt')::timestamptz DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]VerdictEntry{}
	for rows.Next() {
		var tid string
		var v VerdictEntry
		if err := rows.Scan(&tid, &v.Verdict, &v.At); err != nil {
			return nil, err
		}
		out[tid] = v
	}
	return out, rows.Err()
}

// LoadValidationVerdicts returns, per technique ID (uppercase), the most
// recent active+Approved verification_history verdict (Detected/NotDetected
// only) and when it was verified. Exported for internal/correlation.
func LoadValidationVerdicts(ctx context.Context, pool *pgxpool.Pool) (map[string]VerdictEntry, error) {
	if pool == nil {
		return map[string]VerdictEntry{}, nil
	}
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (technique_id) technique_id, result, verified_at
		FROM verification_history
		WHERE active AND workflow_state = $1 AND result IN ($2, $3)
		ORDER BY technique_id, verified_at DESC`,
		verification.StateApproved, verification.ResultDetected, verification.ResultNotDetected)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]VerdictEntry{}
	for rows.Next() {
		var tid string
		var v VerdictEntry
		if err := rows.Scan(&tid, &v.Verdict, &v.At); err != nil {
			return nil, err
		}
		out[strings.ToUpper(tid)] = v
	}
	return out, rows.Err()
}

func (e *Engine) loadProfile(ctx context.Context, name string) (*ActorProfile, error) {
	row := e.pool.QueryRow(ctx,
		`SELECT name, aliases, sectors, regions, confidence, last_seen, canonical_group_id FROM threat_actor_profiles WHERE name=$1`, name)
	var p ActorProfile
	if err := row.Scan(&p.Name, &p.Aliases, &p.Sectors, &p.Regions, &p.Confidence, &p.LastSeen, &p.CanonicalGroupID); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

func (e *Engine) loadAllProfiles(ctx context.Context) ([]ActorProfile, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT name, aliases, sectors, regions, confidence, last_seen, canonical_group_id FROM threat_actor_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActorProfile
	for rows.Next() {
		var p ActorProfile
		if err := rows.Scan(&p.Name, &p.Aliases, &p.Sectors, &p.Regions, &p.Confidence, &p.LastSeen, &p.CanonicalGroupID); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// loadActivity returns actorName's OTX activity record, or nil if none
// exists yet. Filters explicitly to source='otx' rather than an unfiltered
// LIMIT 1 -- today it's the only activity source, and an explicit filter
// fails loudly (returns nil) instead of silently picking an arbitrary row
// if a second activity source is ever added without updating this query.
func (e *Engine) loadActivity(ctx context.Context, name string) (*ActivitySignal, error) {
	if e.pool == nil {
		return nil, nil
	}
	row := e.pool.QueryRow(ctx,
		`SELECT pulse_count, first_observed, last_observed FROM threat_actor_activity WHERE actor_name=$1 AND source='otx'`, name)
	var a ActivitySignal
	if err := row.Scan(&a.PulseCount, &a.FirstObserved, &a.LastObserved); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// previousScore returns the most recent threat_priority_history score for
// actorName, or ok=false if none exists yet (first-ever score for this
// actor, or no pool attached -- e.g. a pool-less unit test). Read-only.
func (e *Engine) previousScore(ctx context.Context, actorName string) (score int, ok bool, err error) {
	if e.pool == nil {
		return 0, false, nil
	}
	row := e.pool.QueryRow(ctx,
		`SELECT score FROM threat_priority_history WHERE actor_name=$1 ORDER BY recorded_at DESC LIMIT 1`,
		actorName)
	if err := row.Scan(&score); err != nil {
		if err == pgx.ErrNoRows {
			return 0, false, nil
		}
		return 0, false, err
	}
	return score, true, nil
}

// scoreActor is the shared body of Score and ScoreAll -- takes a profile and
// engine-level shared indexes (built once by the caller), resolves the
// actor's technique roster, runs every registered factor, and computes the
// composite.
func (e *Engine) scoreActor(ctx context.Context, profile *ActorProfile, shared *sharedIndexes) (ActorPriority, error) {
	techIDs, _, _ := reporting.ResolveActorTechniques(profile.Name, profile.Aliases)

	validatedCount := 0
	for _, id := range techIDs {
		upper := strings.ToUpper(id)
		if _, ok := shared.preventionVerdict[upper]; ok {
			validatedCount++
			continue
		}
		if _, ok := shared.validationVerdict[upper]; ok {
			validatedCount++
		}
	}

	activity, err := e.loadActivity(ctx, profile.Name)
	if err != nil {
		return ActorPriority{}, err
	}

	tctx := Context{
		ActorName: profile.Name, TechniqueIDs: techIDs, Profile: profile, Activity: activity,
		Sectors: e.sectors, Regions: e.regions, Now: time.Now().UTC(),
		ValidatedCount: validatedCount, shared: shared,
	}

	results := make([]FactorResult, 0, len(e.factors))
	for _, f := range e.factors {
		w := f.Weight(tctx)
		raw, explanation, available, err := f.Score(ctx, tctx)
		if err != nil {
			return ActorPriority{}, fmt.Errorf("factor %s: %w", f.Name(), err)
		}
		results = append(results, FactorResult{
			Name: f.Name(), Weight: w, RawScore: raw,
			Weighted: raw * w, Explanation: explanation, Available: available,
		})
	}

	score := Composite(results)
	coverageGap := 0
	for _, id := range techIDs {
		if !shared.simulation[id] && !shared.detection[id] && !shared.purple[id] && !shared.compliance[id] {
			coverageGap++
		}
	}

	ap := ActorPriority{
		ActorName: profile.Name, Score: score, Tier: reporting.PriorityTierFor(score),
		Factors: results, TechniqueCount: len(techIDs), CoverageGapCount: coverageGap,
		TechniqueIDs: techIDs, CanonicalGroupID: profile.CanonicalGroupID,
	}

	prevScore, hasPrev, err := e.previousScore(ctx, profile.Name)
	if err != nil {
		return ActorPriority{}, err
	}
	if hasPrev {
		ap.TrendDelta = score - prevScore
		switch {
		case ap.TrendDelta > 0:
			ap.Trend = "up"
		case ap.TrendDelta < 0:
			ap.Trend = "down"
		default:
			ap.Trend = "stable"
		}
	}
	return ap, nil
}

// Score computes one actor's ActorPriority live -- read-only, no history
// write. actorName need not have a threat_actor_profiles row (Coverage
// factors and technique resolution still work via attackdata alone; profile-
// dependent factors report Available=false).
func (e *Engine) Score(ctx context.Context, actorName string) (ActorPriority, error) {
	shared, err := e.buildSharedIndexes(ctx)
	if err != nil {
		return ActorPriority{}, err
	}
	profile, err := e.loadProfile(ctx, actorName)
	if err != nil {
		return ActorPriority{}, err
	}
	if profile == nil {
		profile = &ActorProfile{Name: actorName}
	}
	return e.scoreActor(ctx, profile, shared)
}

// ScoreAll computes every actor with a threat_actor_profiles row -- the
// roster of actors real connectors have actually surfaced, not all ~200
// MITRE groups attackdata.GroupTechniqueIndex knows about. Read-only; a
// single actor's scoring error is logged and skipped, never aborting the
// rest (same discipline connector.Scheduler.sync applies to source fetches).
func (e *Engine) ScoreAll(ctx context.Context) ([]ActorPriority, error) {
	shared, err := e.buildSharedIndexes(ctx)
	if err != nil {
		return nil, err
	}
	profiles, err := e.loadAllProfiles(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ActorPriority, 0, len(profiles))
	for i := range profiles {
		ap, err := e.scoreActor(ctx, &profiles[i], shared)
		if err != nil {
			log.Printf("[threatpriority] score %q: %v", profiles[i].Name, err)
			continue
		}
		out = append(out, ap)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ActorName < out[j].ActorName
	})
	return out, nil
}
