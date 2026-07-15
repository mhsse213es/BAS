package openaev

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeStore is an in-memory contentStore for Importer tests — no database.
type fakeStore struct {
	state map[string]struct {
		updatedAt time.Time
		hash      string
	}
	upserts []string // records openaev_scenario_id of each successful Upsert, in order
	failOn  string   // if set, Upsert for this scenario ID returns an error
}

func newFakeStore() *fakeStore {
	return &fakeStore{state: map[string]struct {
		updatedAt time.Time
		hash      string
	}{}}
}

func (f *fakeStore) SyncState(ctx context.Context, id string) (time.Time, string, bool, error) {
	s, ok := f.state[id]
	return s.updatedAt, s.hash, ok, nil
}

func (f *fakeStore) Upsert(ctx context.Context, scenario Scenario, detail Detail, contentHash string, sizeBytes, sourceVersion int) error {
	if f.failOn == scenario.OpenAEVScenarioID {
		return errors.New("simulated store failure")
	}
	f.state[scenario.OpenAEVScenarioID] = struct {
		updatedAt time.Time
		hash      string
	}{scenario.SourceUpdatedAt, contentHash}
	f.upserts = append(f.upserts, scenario.OpenAEVScenarioID)
	return nil
}

// fakeProvider serves fixed bundle bytes per scenario ID, built with the real
// buildFixtureZip helper from parser_test.go so Importer exercises the real
// Parser/Normalizer, not a shortcut.
type fakeProvider struct {
	refs    []ScenarioRef
	bundles map[string][]byte
}

func (f *fakeProvider) Name() string                                    { return "fake" }
func (f *fakeProvider) List(ctx context.Context) ([]ScenarioRef, error) { return f.refs, nil }
func (f *fakeProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	b, ok := f.bundles[id]
	if !ok {
		return nil, errors.New("no such bundle")
	}
	return b, nil
}

func fixtureBundleFor(t *testing.T, id, name string, updatedAt time.Time) []byte {
	t.Helper()
	scenarioJSON := `{"export_version":1,"scenario_information":{"scenario_id":"` + id +
		`","scenario_name":"` + name + `","scenario_updated_at":"` + updatedAt.Format(time.RFC3339) + `"}}`
	return buildFixtureZip(t, scenarioJSON)
}

func TestImporter_SyncAll_CreatesNewScenarios(t *testing.T) {
	store := newFakeStore()
	imp := NewImporter(store)
	updated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	provider := &fakeProvider{
		refs: []ScenarioRef{{ID: "sc-1", Name: "One", SourceUpdated: updated}},
		bundles: map[string][]byte{
			"sc-1": fixtureBundleFor(t, "sc-1", "One", updated),
		},
	}

	result, err := imp.SyncAll(context.Background(), provider)
	if err != nil {
		t.Fatalf("SyncAll: %v", err)
	}
	if result.Created != 1 || result.Skipped != 0 || result.Errored != 0 {
		t.Errorf("result = %+v, want Created=1", result)
	}
	if len(store.upserts) != 1 || store.upserts[0] != "sc-1" {
		t.Errorf("upserts = %v", store.upserts)
	}
}

func TestImporter_SyncAll_SkipsUnchangedTimestamp(t *testing.T) {
	store := newFakeStore()
	updated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	store.state["sc-1"] = struct {
		updatedAt time.Time
		hash      string
	}{updated, "some-hash"}
	imp := NewImporter(store)
	provider := &fakeProvider{
		refs: []ScenarioRef{{ID: "sc-1", Name: "One", SourceUpdated: updated}},
		// No bundle registered for sc-1 — if the Importer tries to Fetch it,
		// the test fails with "no such bundle", proving the skip worked.
		bundles: map[string][]byte{},
	}

	result, err := imp.SyncAll(context.Background(), provider)
	if err != nil {
		t.Fatalf("SyncAll: %v", err)
	}
	if result.Skipped != 1 || result.Created != 0 {
		t.Errorf("result = %+v, want Skipped=1", result)
	}
}

func TestImporter_SyncAll_OneErrorDoesNotAbortTheRest(t *testing.T) {
	store := newFakeStore()
	store.failOn = "sc-bad"
	imp := NewImporter(store)
	updated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	provider := &fakeProvider{
		refs: []ScenarioRef{
			{ID: "sc-bad", Name: "Bad", SourceUpdated: updated},
			{ID: "sc-good", Name: "Good", SourceUpdated: updated},
		},
		bundles: map[string][]byte{
			"sc-bad":  fixtureBundleFor(t, "sc-bad", "Bad", updated),
			"sc-good": fixtureBundleFor(t, "sc-good", "Good", updated),
		},
	}

	result, err := imp.SyncAll(context.Background(), provider)
	if err != nil {
		t.Fatalf("SyncAll: %v", err)
	}
	if result.Errored != 1 || result.Created != 1 {
		t.Errorf("result = %+v, want Errored=1 Created=1 (sc-good must still succeed)", result)
	}
}

func TestImporter_ImportOne_ParsesAndUpserts(t *testing.T) {
	store := newFakeStore()
	imp := NewImporter(store)
	updated := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	data := fixtureBundleFor(t, "sc-air-gapped", "Air Gapped Scenario", updated)

	result, err := imp.ImportOne(context.Background(), data)
	if err != nil {
		t.Fatalf("ImportOne: %v", err)
	}
	if result.Created != 1 {
		t.Errorf("result = %+v, want Created=1", result)
	}
	if len(store.upserts) != 1 || store.upserts[0] != "sc-air-gapped" {
		t.Errorf("upserts = %v", store.upserts)
	}
}
