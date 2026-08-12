package openaev

import (
	"context"
	"strings"
)

// CompositeProvider merges a Scenario provider and an Exercise provider
// behind one ContentProvider, so Importer.SyncAll needs no knowledge that
// OpenAEV content comes from two distinct object types. List concatenates
// both sources' refs; Fetch routes to whichever sub-provider owns the given
// ID (see exerciseIDPrefix in provider_rest_exercise.go).
//
// If either sub-provider's List fails, the whole sync fails -- matching the
// existing single-provider behavior (SyncAll has always treated a List
// failure as fatal to the whole sync, not per-item). A partial-source
// degradation (e.g. only /api/exercises is down) is a deliberately
// unhandled edge case for this version; last_error still surfaces which
// source failed via the wrapped error message.
type CompositeProvider struct {
	scenarios ContentProvider
	exercises ContentProvider
}

func NewCompositeProvider(scenarios, exercises ContentProvider) *CompositeProvider {
	return &CompositeProvider{scenarios: scenarios, exercises: exercises}
}

func (p *CompositeProvider) Name() string { return "openaev-composite" }

func (p *CompositeProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	scenarioRefs, err := p.scenarios.List(ctx)
	if err != nil {
		return nil, err
	}
	exerciseRefs, err := p.exercises.List(ctx)
	if err != nil {
		return nil, err
	}
	return append(scenarioRefs, exerciseRefs...), nil
}

func (p *CompositeProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	if strings.HasPrefix(id, exerciseIDPrefix) {
		return p.exercises.Fetch(ctx, id)
	}
	return p.scenarios.Fetch(ctx, id)
}
