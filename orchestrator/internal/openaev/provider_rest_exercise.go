package openaev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// exerciseIDPrefix distinguishes exercise-origin IDs from scenario-origin
// IDs within the single ID namespace ContentProvider.Fetch operates on.
// CompositeProvider (see composite_provider.go) routes purely by checking
// this prefix. It is also stamped as the item's canonical stored ID
// (Scenario.OpenAEVScenarioID via ParsedBundle.Scenario.ID), so a re-sync's
// delta-check (Store.SyncState) looks up the same ID List() advertised --
// without this, every sync would see "not found" and treat already-synced
// Exercises as brand new every time.
const exerciseIDPrefix = "exercise:"

// ExerciseRESTProvider fetches OpenAEV Exercises -- a standalone simulation
// object that does not require a parent Scenario -- via OpenAEV's own
// /api/exercises REST API. Fetch's returned bytes are already
// ParseBundle-compatible (via ParseExerciseBundle + marshalAsScenarioZip),
// so the rest of the sync pipeline (Importer.SyncAll/processOne) needs no
// knowledge that an item originated from an Exercise rather than a Scenario.
type ExerciseRESTProvider struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewExerciseRESTProvider(baseURL, token string) *ExerciseRESTProvider {
	return &ExerciseRESTProvider{baseURL: baseURL, token: token, client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *ExerciseRESTProvider) Name() string { return "openaev-exercise-rest" }

type restExerciseListEntry struct {
	ID        string    `json:"exercise_id"`
	Name      string    `json:"exercise_name"`
	UpdatedAt time.Time `json:"exercise_updated_at"`
}

func (p *ExerciseRESTProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/api/exercises", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openaev exercise list request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openaev exercise list returned HTTP %d", resp.StatusCode)
	}

	var entries []restExerciseListEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode openaev exercise list: %w", err)
	}

	refs := make([]ScenarioRef, 0, len(entries))
	for _, e := range entries {
		refs = append(refs, ScenarioRef{ID: exerciseIDPrefix + e.ID, Name: e.Name, SourceUpdated: e.UpdatedAt})
	}
	return refs, nil
}

func (p *ExerciseRESTProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	rawID := strings.TrimPrefix(id, exerciseIDPrefix)
	url := p.baseURL + "/api/exercises/" + rawID + "/export"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openaev exercise export request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openaev exercise export returned HTTP %d for exercise %s", resp.StatusCode, rawID)
	}

	zipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read exercise export body: %w", err)
	}

	parsed, err := ParseExerciseBundle(zipBytes)
	if err != nil {
		return nil, err
	}
	parsed.Scenario.ID = id // re-stamp with the full prefixed ID List() advertised
	return marshalAsScenarioZip(parsed)
}
