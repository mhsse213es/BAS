package openaev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RESTProvider fetches scenarios from a live, reachable OpenAEV instance over
// its REST API. Auth is a Bearer Personal Access Token, same shape as the
// existing MISP/OpenCTI connectors (internal/connector).
type RESTProvider struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewRESTProvider(baseURL, token string) *RESTProvider {
	return &RESTProvider{baseURL: baseURL, token: token, client: &http.Client{Timeout: 30 * time.Second}}
}

func (p *RESTProvider) Name() string { return "openaev-rest" }

type restScenarioListEntry struct {
	ID        string    `json:"scenario_id"`
	Name      string    `json:"scenario_name"`
	UpdatedAt time.Time `json:"scenario_updated_at"`
}

func (p *RESTProvider) List(ctx context.Context) ([]ScenarioRef, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/api/scenarios", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openaev list request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openaev list returned HTTP %d", resp.StatusCode)
	}

	var entries []restScenarioListEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode openaev scenario list: %w", err)
	}

	refs := make([]ScenarioRef, 0, len(entries))
	for _, e := range entries {
		refs = append(refs, ScenarioRef{ID: e.ID, Name: e.Name, SourceUpdated: e.UpdatedAt})
	}
	return refs, nil
}

func (p *RESTProvider) Fetch(ctx context.Context, id string) ([]byte, error) {
	url := p.baseURL + "/api/scenarios/" + id + "/export"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openaev export request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openaev export returned HTTP %d for scenario %s", resp.StatusCode, id)
	}

	return io.ReadAll(resp.Body)
}
