// Package forcepointdlp is a Forcepoint DLP incident evidence client.
//
// UNVERIFIED against a live tenant -- see docs/dlp-mastery-qa-log.md.
// Research (WebSearch, 2026-10-18; see
// docs/superpowers/plans/2026-10-18-dlp-vendor-forcepoint-symantec.md for
// citations) confirmed the auth flow (a 2-step refresh-token then
// access-token exchange against /dlp/rest/v1/auth/{refresh-token,
// access-token}, requiring a local Application-type administrator
// account) and the incidents endpoint shape (POST /dlp/rest/v1/incidents,
// filters-mode request body, max 10,000 rows per response, exactly one of
// INCIDENTS or DISCOVERY per call). It did NOT confirm the exact JSON
// field names in an incident response record, the token's cache lifetime,
// or the exact date-range filter parameter name -- the request/response
// shapes below are this package's best-effort implementation of the
// documented general pattern, flagged here so nobody mistakes "builds and
// passes httptest" for "proven against the real API." Same lab-gated
// posture as internal/vendors/trellixdlp.
package forcepointdlp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Config holds one Forcepoint DLP Manager client's credentials.
type Config struct {
	BaseURL  string // DLP Manager host:port, e.g. "https://dlpmgr.example.com:9443"
	Username string
	Password string
}

// Client is a Forcepoint DLP incidents client.
type Client struct {
	RefreshTokenURL string
	AccessTokenURL  string
	IncidentsURL    string
	httpClient      *http.Client

	username, password string
	mu                 sync.Mutex
	cachedAccessToken  string
	tokenExpiresAt     time.Time
}

func New(cfg Config) *Client {
	return &Client{
		RefreshTokenURL: cfg.BaseURL + "/dlp/rest/v1/auth/refresh-token",
		AccessTokenURL:  cfg.BaseURL + "/dlp/rest/v1/auth/access-token",
		IncidentsURL:    cfg.BaseURL + "/dlp/rest/v1/incidents",
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		username:        cfg.Username,
		password:        cfg.Password,
	}
}

func (c *Client) refreshToken(ctx context.Context) (string, error) {
	body, _ := json.Marshal(map[string]string{"username": c.username, "password": c.password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RefreshTokenURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("forcepointdlp refresh token: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("forcepointdlp refresh token: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.RefreshToken == "" {
		return "", fmt.Errorf("forcepointdlp refresh token: unexpected response: %s", data)
	}
	return out.RefreshToken, nil
}

// accessToken returns a cached access token when still valid, caching for
// a conservative fixed 15-minute duration -- no confirmed token lifetime
// was found, so this is a best-effort default, not a documented value.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedAccessToken != "" && time.Now().Before(c.tokenExpiresAt) {
		return c.cachedAccessToken, nil
	}

	refreshTok, err := c.refreshToken(ctx)
	if err != nil {
		return "", err
	}

	body, _ := json.Marshal(map[string]string{"refreshToken": refreshTok})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.AccessTokenURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("forcepointdlp access token: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("forcepointdlp access token: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("forcepointdlp access token: unexpected response: %s", data)
	}
	c.cachedAccessToken = out.AccessToken
	c.tokenExpiresAt = time.Now().Add(15 * time.Minute)
	return c.cachedAccessToken, nil
}

// Incident is one normalized Forcepoint DLP incident. Field names are
// this package's best-effort mapping -- see the package doc comment's
// unverified-schema warning.
type Incident struct {
	ID         string
	Timestamp  time.Time
	Policy     string
	Department string
	RiskLevel  string
	Severity   string
	Action     string
	Status     string
	RawJSON    json.RawMessage
}

type incidentsResponse struct {
	Incidents []json.RawMessage `json:"incidents"`
}

// QueryDLPIncidents lists DLP incidents in [start, end]. Returns an empty
// slice, never an error, when there are no incidents in the window.
func (c *Client) QueryDLPIncidents(ctx context.Context, start, end time.Time) ([]Incident, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}

	reqBody, _ := json.Marshal(map[string]any{
		// Always INCIDENTS, never DISCOVERY -- this method's own name
		// (QueryDLPIncidents) is the contract; a Discovery-incidents query
		// is a different method this package does not offer today.
		"type": "INCIDENTS",
		"filters": map[string]any{
			"dateRange": map[string]string{
				"start": start.UTC().Format(time.RFC3339),
				"end":   end.UTC().Format(time.RFC3339),
			},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.IncidentsURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("forcepointdlp query incidents: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("forcepointdlp query incidents: permission denied (HTTP %d, does this account have DLP incident license/role, and is it an Application-type administrator account?): %s", resp.StatusCode, data)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("forcepointdlp query incidents: HTTP %d: %s", resp.StatusCode, data)
	}

	var out incidentsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("forcepointdlp: parse incidents response: %w", err)
	}
	incidents := make([]Incident, 0, len(out.Incidents))
	for _, raw := range out.Incidents {
		inc, ok := parseIncident(raw)
		if ok {
			incidents = append(incidents, inc)
		}
	}
	return incidents, nil
}

func parseIncident(raw json.RawMessage) (Incident, bool) {
	var rec struct {
		ID         string `json:"id"`
		Timestamp  string `json:"timestamp"`
		Policy     string `json:"policy"`
		Department string `json:"department"`
		RiskLevel  string `json:"riskLevel"`
		Severity   string `json:"severity"`
		Action     string `json:"action"`
		Status     string `json:"status"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Incident{}, false
	}
	ts, err := time.Parse(time.RFC3339, rec.Timestamp)
	if err != nil {
		return Incident{}, false
	}
	return Incident{
		ID: rec.ID, Timestamp: ts, Policy: rec.Policy, Department: rec.Department,
		RiskLevel: rec.RiskLevel, Severity: rec.Severity, Action: rec.Action, Status: rec.Status,
		RawJSON: raw,
	}, true
}

// TestConnection is a smoke test: queries incidents with no expectation of
// any results, succeeding as long as the API call itself succeeds.
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.QueryDLPIncidents(ctx, time.Now().Add(-time.Hour), time.Now())
	return err
}
