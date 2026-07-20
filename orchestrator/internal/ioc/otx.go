package ioc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const otxBaseURL = "https://otx.alienvault.com/api/v1"

type otxProvider struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string // overridden by tests; otxBaseURL in production
}

func newOTXProvider(cfg Config) *otxProvider {
	return &otxProvider{
		apiKey:     cfg.APIKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    otxBaseURL,
	}
}

func (p *otxProvider) LookupIP(ctx context.Context, ip string) (*Result, error) {
	return p.lookup(ctx, "IPv4", ip, "ip")
}
func (p *otxProvider) LookupDomain(ctx context.Context, domain string) (*Result, error) {
	return p.lookup(ctx, "domain", domain, "domain")
}
func (p *otxProvider) LookupURL(ctx context.Context, u string) (*Result, error) {
	return p.lookup(ctx, "url", u, "url")
}
func (p *otxProvider) LookupHash(ctx context.Context, hash string) (*Result, error) {
	return p.lookup(ctx, "file", hash, "hash")
}
func (p *otxProvider) LookupCVE(ctx context.Context, cveID string) (*Result, error) {
	return p.lookup(ctx, "cve", cveID, "cve")
}

// otxGeneralResponse mirrors the fields of OTX's /indicators/{type}/{value}/general
// response actually used by this provider -- not a full schema, just what's consumed.
type otxGeneralResponse struct {
	Indicator string `json:"indicator"`
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		} `json:"pulses"`
		Related struct {
			Alienvault struct {
				Adversary       []string `json:"adversary"`
				MalwareFamilies []string `json:"malware_families"`
				Industries      []string `json:"industries"`
			} `json:"alienvault"`
		} `json:"related"`
	} `json:"pulse_info"`
}

func (p *otxProvider) lookup(ctx context.Context, otxType, value, resultType string) (*Result, error) {
	reqURL := fmt.Sprintf("%s/indicators/%s/%s/general", p.baseURL, otxType, url.PathEscape(value))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ioc/otx: build request: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ioc/otx: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &Result{Indicator: value, Type: resultType, Provider: "otx", Confidence: ConfidenceUnknown}, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ioc/otx: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ioc/otx: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var raw otxGeneralResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("ioc/otx: parse response: %w", err)
	}

	pulseNames := make([]string, 0, len(raw.PulseInfo.Pulses))
	for _, pulse := range raw.PulseInfo.Pulses {
		pulseNames = append(pulseNames, pulse.Name)
	}

	confidence := ConfidenceUnknown
	switch {
	case raw.PulseInfo.Count >= 3:
		confidence = ConfidenceHigh
	case raw.PulseInfo.Count >= 1:
		confidence = ConfidenceLow
	}

	return &Result{
		Indicator:       value,
		Type:            resultType,
		Provider:        "otx",
		PulseCount:      raw.PulseInfo.Count,
		PulseNames:      pulseNames,
		MalwareFamilies: raw.PulseInfo.Related.Alienvault.MalwareFamilies,
		AdversaryNames:  raw.PulseInfo.Related.Alienvault.Adversary,
		Industries:      raw.PulseInfo.Related.Alienvault.Industries,
		Confidence:      confidence,
		RawResponse:     json.RawMessage(body),
	}, nil
}
