// Package symantecdlp is a Symantec (Broadcom) DLP incident evidence
// client.
//
// UNVERIFIED against a live tenant -- see docs/dlp-mastery-qa-log.md.
// Research (WebSearch, 2026-10-18; see
// docs/superpowers/plans/2026-10-18-dlp-vendor-forcepoint-symantec.md for
// citations) confirmed Symantec DLP's REST-adjacent integrations use
// forms-based username/password authentication against the Enforce
// server -- not OAuth -- and that incidents are filterable by earliest
// time, status, severity and incident type with a default page size of
// 50. It also confirmed a real operational risk: the service account can
// lock after repeated failed logins (documented default: 6 attempts, 60
// minute lockout) -- this client must never retry a login after a
// rejected attempt. It did NOT confirm the exact login endpoint path,
// the session-token/cookie mechanics after a successful login, the exact
// incident-list endpoint path or response field names, or which of
// Symantec's two documented API generations (the 15.7+ REST API vs. the
// 16+ "Incident Reporting and Update API") a given license maps to. The
// request/response shapes below are this package's best-effort
// implementation of the documented general pattern -- same lab-gated
// posture as internal/vendors/trellixdlp.
package symantecdlp

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

// Config holds one Symantec DLP Enforce server client's credentials.
type Config struct {
	BaseURL  string // Enforce server host:port, e.g. "https://enforce.example.com"
	Username string
	Password string
}

// Client is a Symantec DLP incidents client.
type Client struct {
	LoginURL     string
	IncidentsURL string
	httpClient   *http.Client

	username, password string
	mu                 sync.Mutex
	cachedSessionToken string
	sessionExpiresAt   time.Time
}

func New(cfg Config) *Client {
	return &Client{
		LoginURL:     cfg.BaseURL + "/ProtectManager/webservices/v2/authenticate",
		IncidentsURL: cfg.BaseURL + "/ProtectManager/webservices/v2/incidents",
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		username:     cfg.Username,
		password:     cfg.Password,
	}
}

// login returns a cached session token when still valid, caching for a
// conservative fixed 15-minute duration -- no confirmed session lifetime
// was found, so this is a best-effort default, not a documented value.
// It never retries internally: a rejected login is returned to the
// caller immediately, since the documented account-lockout risk (default
// 6 failed attempts) makes an automatic retry actively dangerous.
func (c *Client) login(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedSessionToken != "" && time.Now().Before(c.sessionExpiresAt) {
		return c.cachedSessionToken, nil
	}

	form := url.Values{"username": {c.username}, "password": {c.password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.LoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("symantecdlp login: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("symantecdlp login: HTTP %d: %s", resp.StatusCode, data)
	}

	var out struct {
		SessionToken string `json:"sessionToken"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.SessionToken == "" {
		return "", fmt.Errorf("symantecdlp login: unexpected response: %s", data)
	}
	c.cachedSessionToken = out.SessionToken
	c.sessionExpiresAt = time.Now().Add(15 * time.Minute)
	return c.cachedSessionToken, nil
}

// Incident is one normalized Symantec DLP incident. Field names are this
// package's best-effort mapping -- see the package doc comment's
// unverified-schema warning.
type Incident struct {
	ID            string
	DetectionDate time.Time
	Status        string
	Severity      string
	IncidentType  string
	RawJSON       json.RawMessage
}

type incidentsResponse struct {
	Incidents []json.RawMessage `json:"incidents"`
}

// QueryDLPIncidents lists DLP incidents in [start, end]. Returns an empty
// slice, never an error, when there are no incidents in the window.
func (c *Client) QueryDLPIncidents(ctx context.Context, start, end time.Time) ([]Incident, error) {
	token, err := c.login(ctx)
	if err != nil {
		return nil, err
	}

	// The exact post-login session mechanics (cookie vs. header vs. query
	// param) are unconfirmed -- see the package doc comment. This client's
	// best-effort guess is a query parameter, since no header convention
	// was found in the researched integration references.
	q := url.Values{
		"sessionToken": {token},
		"earliestTime": {start.UTC().Format(time.RFC3339)},
		"latestTime":   {end.UTC().Format(time.RFC3339)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.IncidentsURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("symantecdlp query incidents: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("symantecdlp query incidents: permission denied (HTTP %d, does this account have the DLP incident license/role/permission?): %s", resp.StatusCode, data)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("symantecdlp query incidents: HTTP %d: %s", resp.StatusCode, data)
	}

	var out incidentsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("symantecdlp: parse incidents response: %w", err)
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
		IncidentID    string `json:"incidentId"`
		DetectionDate string `json:"detectionDate"`
		Status        string `json:"status"`
		Severity      string `json:"severity"`
		IncidentType  string `json:"incidentType"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Incident{}, false
	}
	ts, err := time.Parse(time.RFC3339, rec.DetectionDate)
	if err != nil {
		return Incident{}, false
	}
	return Incident{
		ID: rec.IncidentID, DetectionDate: ts, Status: rec.Status,
		Severity: rec.Severity, IncidentType: rec.IncidentType,
		RawJSON: raw,
	}, true
}

// TestConnection is a smoke test: queries incidents with no expectation of
// any results, succeeding as long as the API call itself succeeds.
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.QueryDLPIncidents(ctx, time.Now().Add(-time.Hour), time.Now())
	return err
}
