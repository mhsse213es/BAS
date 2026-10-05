package contentregistry

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/scenario"
)

type RunContentStatus string

const (
	RunVersioned   RunContentStatus = "versioned"
	RunUnversioned RunContentStatus = "unversioned"
	RunUnreadable  RunContentStatus = "unreadable"
	RunSynthetic   RunContentStatus = "synthetic"
)

type RunContent struct {
	Status    RunContentStatus
	Scenario  *scenario.Scenario
	VersionID string
	ContentID string
	Version   int
	Trust     string
	Lifecycle string
}

// Label is the operator/report-facing provenance line (spec §7).
func (rc RunContent) Label() string {
	switch rc.Status {
	case RunVersioned:
		return fmt.Sprintf("%s v%d (%s)", rc.ContentID, rc.Version, rc.Trust)
	case RunUnversioned:
		return "Unversioned — interpreted against current content"
	case RunUnreadable:
		return "Content version unreadable"
	}
	return ""
}

type CurrentLookup interface {
	Get(id string) (*scenario.Scenario, bool)
}

// RunContent resolves the scenario a run must be interpreted against. A
// versioned run NEVER falls back to current content; only pre-registry
// (legacy) runs do, and they are labelled.
func (r *Registry) RunContent(ctx context.Context, runID string, current CurrentLookup) RunContent {
	var kind, scenarioID string
	var vid *string
	if err := r.pool.QueryRow(ctx,
		`SELECT execution_kind, content_version_id, scenario_id FROM scenario_runs WHERE id = $1`, runID,
	).Scan(&kind, &vid, &scenarioID); err != nil {
		return RunContent{Status: RunUnreadable}
	}
	switch kind {
	case KindContent:
		if vid == nil {
			return RunContent{Status: RunUnreadable}
		}
		v, err := r.LoadVersion(ctx, *vid)
		if err != nil {
			return RunContent{Status: RunUnreadable, VersionID: *vid}
		}
		sc, err := v.Parse()
		if err != nil {
			return RunContent{Status: RunUnreadable, VersionID: v.ID, ContentID: v.ContentID, Version: v.Number}
		}
		return RunContent{Status: RunVersioned, Scenario: sc, VersionID: v.ID, ContentID: v.ContentID,
			Version: v.Number, Trust: string(v.Trust), Lifecycle: string(v.Lifecycle)}
	case KindLegacy:
		var sc *scenario.Scenario
		if current != nil {
			sc, _ = current.Get(scenarioID)
		}
		return RunContent{Status: RunUnversioned, Scenario: sc, ContentID: scenarioID}
	default:
		return RunContent{Status: RunSynthetic}
	}
}

// ExpectationResolver is the engine's detection-profile resolution (still
// current files -- plan amendment 9).
type ExpectationResolver interface {
	ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef)
}

// RunResolver satisfies reporting.ScenarioResolver / detectverify.ScenarioResolver
// for exactly one run.
type RunResolver struct {
	Content RunContent
	exp     ExpectationResolver
}

func (rr RunResolver) Get(id string) (*scenario.Scenario, bool) {
	if rr.Content.Scenario == nil || rr.Content.Scenario.ID != id {
		return nil, false
	}
	return rr.Content.Scenario, true
}

func (rr RunResolver) ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef) {
	if rr.exp == nil {
		return nil, nil
	}
	return rr.exp.ResolveStepExpectations(step)
}

// ForRun builds the run-scoped resolver. engine may be nil (no profile
// resolution, no legacy fallback).
func (r *Registry) ForRun(ctx context.Context, runID string, engine *scenario.Engine) RunResolver {
	var cur CurrentLookup
	var exp ExpectationResolver
	if engine != nil {
		cur, exp = engine, engine
	}
	return RunResolver{Content: r.RunContent(ctx, runID, cur), exp: exp}
}
