package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OTXSource performs a periodic sync against AlienVault OTX, recording the
// account's subscribed-pulse count via Stats(). It does not yet extract
// threat actors or ATT&CK techniques from those pulses — Fetch always
// returns zero actors. That mapping is a separate, later piece of work;
// see docs/superpowers/specs/2026-07-22-otx-periodic-sync-design.md.
//
// This is a distinct client from internal/ioc/otx.go's otxProvider, which
// performs synchronous on-demand single-indicator lookups (IP/domain/hash/
// CVE) for LookupIOC — a different concern from this package's periodic
// sync + scenario generation, matching this codebase's existing package
// split between internal/ioc and internal/connector.
type OTXSource struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string // overridden by tests; otxAPIBaseURL in production
	lastStat   SourceStat
}

const otxAPIBaseURL = "https://otx.alienvault.com/api/v1"

// NewOTXSource creates an OTX periodic-sync client.
func NewOTXSource(apiKey string) *OTXSource {
	return &OTXSource{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    otxAPIBaseURL,
	}
}

// Name identifies this source. Implements Source.
func (c *OTXSource) Name() string { return "otx" }

type otxPulsesResponse struct {
	Count int `json:"count"`
}

// Fetch records the account's subscribed-pulse count via Stats() and always
// returns zero actors — a clean no-op contribution to MergeActors until
// pulse-to-technique mapping is built.
func (c *OTXSource) Fetch() ([]ThreatActor, error) {
	// limit=1 keeps the request cheap: only the total "count" field is
	// needed, not individual pulse objects.
	req, err := http.NewRequest("GET", c.baseURL+"/pulses/subscribed?limit=1", nil)
	if err != nil {
		c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("otx build request: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
		return nil, fmt.Errorf("otx request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("OTX returned HTTP %d", resp.StatusCode)
		c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
		return nil, err
	}

	var parsed otxPulsesResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		wrapped := fmt.Errorf("otx decode response: %w", err)
		c.lastStat = SourceStat{Name: "otx", Error: wrapped.Error(), FetchedAt: time.Now()}
		return nil, wrapped
	}

	c.lastStat = SourceStat{Name: "otx", RawCount: parsed.Count, ActorCount: 0, FetchedAt: time.Now()}
	return nil, nil
}

// Stats implements StatsSource.
func (c *OTXSource) Stats() SourceStat { return c.lastStat }
