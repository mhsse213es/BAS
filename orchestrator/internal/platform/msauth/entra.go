package msauth

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

// EntraTokenSource fetches and caches an Entra ID (Azure AD) OAuth2
// client-credentials token for one (tenant, client, scope) triple. Shared by
// every Microsoft-family connector in this codebase (Sentinel in
// internal/detectverify, Defender in internal/vendors/defender) — they
// differ only in scope (api.loganalytics.io vs graph.microsoft.com vs
// api.securitycenter.microsoft.com).
type EntraTokenSource struct {
	tenantID, clientID, clientSecret, scope string
	TokenURL                                string // overridable in tests; defaults to login.microsoftonline.com
	httpClient                              *http.Client

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

func NewEntraTokenSource(tenantID, clientID, clientSecret, scope string) *EntraTokenSource {
	return &EntraTokenSource{
		tenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
		scope:        scope,
		TokenURL:     "https://login.microsoftonline.com/" + tenantID + "/oauth2/v2.0/token",
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Token returns a cached token when it has more than 60s left, else fetches
// a fresh one via the client-credentials grant.
func (e *EntraTokenSource) Token(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cached != "" && time.Now().Before(e.expiresAt) {
		return e.cached, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {e.clientID},
		"client_secret": {e.clientSecret},
		"scope":         {e.scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("entra token: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("entra token: HTTP %d: %s", resp.StatusCode, data)
	}

	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("entra token: unexpected response: %s", data)
	}

	e.cached = out.AccessToken
	e.expiresAt = time.Now().Add(time.Duration(out.ExpiresIn-60) * time.Second)
	return e.cached, nil
}
