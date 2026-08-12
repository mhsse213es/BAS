package openaev

import (
	"context"
	"errors"
	"testing"
)

// compositeFakeProvider is a minimal ContentProvider for testing composition
// without real HTTP. Named distinctly from importer_test.go's fakeProvider
// (a different, unrelated fixture already used by the Importer tests).
type compositeFakeProvider struct {
	name    string
	refs    []ScenarioRef
	listErr error
	fetched []string // records every ID passed to Fetch, for routing assertions
}

func (f *compositeFakeProvider) Name() string { return f.name }
func (f *compositeFakeProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	return f.refs, f.listErr
}
func (f *compositeFakeProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	f.fetched = append(f.fetched, id)
	return []byte("data-for-" + id), nil
}

func TestCompositeProvider_List_MergesBothSources(t *testing.T) {
	scenarios := &compositeFakeProvider{refs: []ScenarioRef{{ID: "sc-1", Name: "Scenario One"}}}
	exercises := &compositeFakeProvider{refs: []ScenarioRef{{ID: "exercise:ex-1", Name: "Exercise One"}}}

	cp := NewCompositeProvider(scenarios, exercises)
	refs, err := cp.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %d, want 2", len(refs))
	}
	ids := map[string]bool{refs[0].ID: true, refs[1].ID: true}
	if !ids["sc-1"] || !ids["exercise:ex-1"] {
		t.Errorf("refs = %+v, want both sc-1 and exercise:ex-1", refs)
	}
}

func TestCompositeProvider_Fetch_RoutesByPrefix(t *testing.T) {
	scenarios := &compositeFakeProvider{}
	exercises := &compositeFakeProvider{}
	cp := NewCompositeProvider(scenarios, exercises)

	if _, err := cp.Fetch(context.Background(), "sc-1"); err != nil {
		t.Fatalf("Fetch(sc-1): %v", err)
	}
	if _, err := cp.Fetch(context.Background(), "exercise:ex-1"); err != nil {
		t.Fatalf("Fetch(exercise:ex-1): %v", err)
	}

	if len(scenarios.fetched) != 1 || scenarios.fetched[0] != "sc-1" {
		t.Errorf("scenarios provider fetched = %+v, want [sc-1]", scenarios.fetched)
	}
	if len(exercises.fetched) != 1 || exercises.fetched[0] != "exercise:ex-1" {
		t.Errorf("exercises provider fetched = %+v, want [exercise:ex-1]", exercises.fetched)
	}
}

func TestCompositeProvider_List_PropagatesScenarioListError(t *testing.T) {
	scenarios := &compositeFakeProvider{listErr: errors.New("scenario list boom")}
	exercises := &compositeFakeProvider{}
	cp := NewCompositeProvider(scenarios, exercises)

	if _, err := cp.List(context.Background()); err == nil {
		t.Fatal("expected error to propagate from the scenarios sub-provider")
	}
}

func TestCompositeProvider_List_PropagatesExerciseListError(t *testing.T) {
	scenarios := &compositeFakeProvider{}
	exercises := &compositeFakeProvider{listErr: errors.New("exercise list boom")}
	cp := NewCompositeProvider(scenarios, exercises)

	if _, err := cp.List(context.Background()); err == nil {
		t.Fatal("expected error to propagate from the exercises sub-provider")
	}
}
