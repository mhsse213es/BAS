package detectverify

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

// crowdstrikeTokenSource fetches and caches a CrowdStrike Falcon OAuth2
// client-credentials token. Structurally identical to entraTokenSource
// (same cache-until-60s-left rule) but without an Entra-style scope
// parameter — the token grants whatever scopes the API client was
// provisioned with in the Falcon console.
type crowdstrikeTokenSource struct {
	clientID, clientSecret string
	tokenURL               string // overridable in tests; defaults to <baseURL>/oauth2/token
	httpClient             *http.Client

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

func newCrowdStrikeTokenSource(baseURL, clientID, clientSecret string) *crowdstrikeTokenSource {
	return &crowdstrikeTokenSource{
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenURL:     strings.TrimRight(baseURL, "/") + "/oauth2/token",
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Token returns a cached token when it has more than 60s left, else fetches
// a fresh one via the client-credentials grant.
func (c *crowdstrikeTokenSource) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != "" && time.Now().Before(c.expiresAt) {
		return c.cached, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdstrike token: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("crowdstrike token: HTTP %d: %s", resp.StatusCode, data)
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("crowdstrike token: unexpected response: %s", data)
	}

	c.cached = out.AccessToken
	c.expiresAt = time.Now().Add(time.Duration(out.ExpiresIn-60) * time.Second)
	return c.cached, nil
}
