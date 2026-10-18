// Package trellixdlp is a Trellix Data Loss Prevention evidence client.
//
// UNVERIFIED against a live tenant or an official Trellix DLP incident API
// reference -- see docs/dlp-mastery-qa-log.md. Research (WebSearch,
// 2026-10-18; see docs/superpowers/plans/2026-10-18-dlp-vendor-connectors.md
// for citations) confirmed the general shape -- a regional Events API v2
// (`type=incidents`), a Trellix-IAM client-credentials grant with
// license-scoped JWT tokens, Basic-auth credential submission -- but did
// NOT confirm the exact response envelope/field names for a DLP incident
// record, nor which of Trellix's conflicting documented token-endpoint
// domains/versions (iam.cloud.trellix.com v1.0 vs. legacy
// iam.mcafee-cloud.com v1.1) is current. Both the request shape and the
// Incident struct below are this package's best-effort implementation of
// the documented general pattern, flagged here so nobody mistakes "builds
// and passes httptest" for "proven against the real API."
//
// This is the same lab-gated posture internal/vendors/purview and
// internal/vendors/defender's own AnalyzedEmail work already follow before
// their respective tenant access existed.
package trellixdlp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config holds one Trellix API client's credentials.
type Config struct {
	ClientID     string
	ClientSecret string
}

// Client is a Trellix DLP incidents client. Token fetch is local to this
// package (not internal/platform/msauth.EntraTokenSource) because Trellix's
// client-credentials grant uses HTTP Basic auth for the client
// id/secret, not Entra's form-encoded client_secret field -- different
// grant mechanics, not a stylistic choice.
type Client struct {
	// TokenURL/EventsURL default to the most-recently-documented Trellix
	// domain as of this package's research date (see package doc) --
	// unverified, overridable for tests and for whichever region/version a
	// real account turns out to need.
	TokenURL   string
	EventsURL  string
	httpClient *http.Client

	clientID, clientSecret string
	mu                     sync.Mutex
	cachedToken            string
	tokenExpiresAt         time.Time
}

func New(cfg Config) *Client {
	return &Client{
		TokenURL:     "https://iam.cloud.trellix.com/iam/v1.0/token",
		EventsURL:    "https://arevents.manage.trellix.com/eventservice/api/v2/events",
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
	}
}

func (c *Client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedToken != "" && time.Now().Before(c.tokenExpiresAt) {
		return c.cachedToken, nil
	}

	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("trellixdlp token: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("trellixdlp token: HTTP %d: %s", resp.StatusCode, data)
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("trellixdlp token: unexpected response: %s", data)
	}
	c.cachedToken = out.AccessToken
	c.tokenExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn-60) * time.Second)
	return c.cachedToken, nil
}

// Incident is one normalized Trellix DLP incident. Field names are this
// package's best-effort mapping of the general Events API shape -- see the
// package doc comment's unverified-schema warning.
type Incident struct {
	ID         string
	Timestamp  time.Time
	Severity   string
	PolicyName string
	Action     string
	Status     string
	RawJSON    json.RawMessage
}

type eventsResponse struct {
	Events []json.RawMessage `json:"events"`
}

// QueryDLPIncidents lists DLP incidents in [start, end]. Returns an empty
// slice, never an error, when there are no incidents in the window.
func (c *Client) QueryDLPIncidents(ctx context.Context, start, end time.Time) ([]Incident, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"type":  {"incidents"},
		"start": {start.UTC().Format(time.RFC3339)},
		"end":   {end.UTC().Format(time.RFC3339)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.EventsURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trellixdlp query incidents: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("trellixdlp query incidents: permission denied (HTTP %d, does this client's license/scope include DLP incident events?): %s", resp.StatusCode, data)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("trellixdlp query incidents: HTTP %d: %s", resp.StatusCode, data)
	}

	var out eventsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("trellixdlp: parse events response: %w", err)
	}
	incidents := make([]Incident, 0, len(out.Events))
	for _, raw := range out.Events {
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
		Severity   string `json:"severity"`
		PolicyName string `json:"policyName"`
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
		ID: rec.ID, Timestamp: ts, Severity: rec.Severity,
		PolicyName: rec.PolicyName, Action: rec.Action, Status: rec.Status,
		RawJSON: raw,
	}, true
}

// TestConnection is a smoke test: queries incidents with no expectation of
// any results, succeeding as long as the API call itself succeeds.
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.QueryDLPIncidents(ctx, time.Now().Add(-time.Hour), time.Now())
	return err
}
