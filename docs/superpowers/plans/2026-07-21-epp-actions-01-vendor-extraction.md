# EPP Response Actions — Plan 1: Vendor Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move CrowdStrike's and Defender's auth/API code out of `internal/detectverify` into new `internal/vendors/crowdstrike` and `internal/vendors/defender` packages, with `detectverify` becoming a thin consumer, so response-action code (a later plan) never has to live inside a package whose whole promise today is "read-only." Zero behavior change — every existing `detectverify` test must still pass.

**Architecture:** Pure refactor, no new capability. A shared `internal/platform/msauth` package holds the Entra (Azure AD) client-credentials token source, since it's genuinely used by three call sites once Defender moves out (Sentinel stays in `detectverify`, Defender moves to `internal/vendors/defender`). CrowdStrike's token source has exactly one consumer and stays local to `internal/vendors/crowdstrike`.

**Tech Stack:** Go 1.26, stdlib `net/http`/`net/http/httptest` only — no new dependencies.

## Global Constraints

- This is Plan 1 of 4 for the EPP Response Actions feature (spec: `docs/superpowers/specs/2026-07-21-epp-response-actions-design.md`). This plan only extracts existing code into new packages — it adds no isolate/kill/quarantine capability. Plans 2-4 (device resolution + response actions, the `internal/actions` package + DB + permissions + API, and the UI) come after this one ships.
- No behavior change. Every test in `internal/detectverify` that exists today must still exist (moved or equivalent) and pass after this plan, unchanged in what it asserts.
- Module path: `github.com/audspect/bas`.

---

### Task 1: Extract shared Entra OAuth token source into `internal/platform/msauth`

**Files:**
- Create: `orchestrator/internal/platform/msauth/entra.go`
- Create: `orchestrator/internal/platform/msauth/entra_test.go`
- Delete: `orchestrator/internal/detectverify/entra_auth.go`
- Delete: `orchestrator/internal/detectverify/entra_auth_test.go`
- Modify: `orchestrator/internal/detectverify/sentinel.go`
- Modify: `orchestrator/internal/detectverify/sentinel_test.go:24`

**Interfaces:**
- Produces: `msauth.EntraTokenSource` (exported `TokenURL string` field for test overrides — it must be exported because, after this task, both `internal/detectverify` and a later task's `internal/vendors/defender` construct and override it from outside the `msauth` package), `msauth.NewEntraTokenSource(tenantID, clientID, clientSecret, scope string) *EntraTokenSource`, `(*EntraTokenSource).Token(ctx context.Context) (string, error)`.

- [ ] **Step 1: Create the `msauth` package**

Create `orchestrator/internal/platform/msauth/entra.go`:
```go
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
```

- [ ] **Step 2: Create the test, moved from `detectverify/entra_auth_test.go` with renamed symbols**

Create `orchestrator/internal/platform/msauth/entra_test.go`:
```go
package msauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEntraTokenSource_FetchesAndCaches(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", r.FormValue("grant_type"))
		}
		if r.FormValue("scope") != "https://api.loganalytics.io/.default" {
			t.Errorf("scope = %q", r.FormValue("scope"))
		}
		w.Write([]byte(`{"access_token":"tok-1","expires_in":3600}`))
	}))
	defer srv.Close()

	ts := NewEntraTokenSource("tenant-1", "client-1", "secret-1", "https://api.loganalytics.io/.default")
	ts.TokenURL = srv.URL

	tok, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("token = %q, want tok-1", tok)
	}

	tok2, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if tok2 != "tok-1" {
		t.Fatalf("cached token = %q, want tok-1", tok2)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (the second Token() call should reuse the cache)", calls)
	}
}

func TestEntraTokenSource_HTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	ts := NewEntraTokenSource("tenant-1", "client-1", "bad-secret", "scope")
	ts.TokenURL = srv.URL

	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("expected an error from a 401 token response")
	}
}
```

- [ ] **Step 3: Run the new package's tests**

Run: `go test ./internal/platform/msauth/... -v` (from `orchestrator/`)
Expected: `PASS`, both tests green.

- [ ] **Step 4: Delete the old files**

```bash
rm orchestrator/internal/detectverify/entra_auth.go
rm orchestrator/internal/detectverify/entra_auth_test.go
```

- [ ] **Step 5: Update `sentinel.go` to consume `msauth`**

In `orchestrator/internal/detectverify/sentinel.go`, find:
```go
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// sentinelConnector queries Microsoft Sentinel's underlying Log Analytics
// workspace for SecurityAlert rows mentioning the run's host in the
// requested window. Authenticates via Entra client-credentials.
type sentinelConnector struct {
	queryURL   string // overridable in tests; defaults to the Log Analytics API
	tokens     *entraTokenSource
	httpClient *http.Client
}

func newSentinelConnector(cfg Config) *sentinelConnector {
	return &sentinelConnector{
		queryURL: "https://api.loganalytics.io/v1/workspaces/" + cfg.WorkspaceID + "/query",
		tokens: newEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://api.loganalytics.io/.default"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}
```
Replace with:
```go
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/platform/msauth"
)

// sentinelConnector queries Microsoft Sentinel's underlying Log Analytics
// workspace for SecurityAlert rows mentioning the run's host in the
// requested window. Authenticates via Entra client-credentials.
type sentinelConnector struct {
	queryURL   string // overridable in tests; defaults to the Log Analytics API
	tokens     *msauth.EntraTokenSource
	httpClient *http.Client
}

func newSentinelConnector(cfg Config) *sentinelConnector {
	return &sentinelConnector{
		queryURL: "https://api.loganalytics.io/v1/workspaces/" + cfg.WorkspaceID + "/query",
		tokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://api.loganalytics.io/.default"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}
```

- [ ] **Step 6: Update `sentinel_test.go`'s token URL override**

In `orchestrator/internal/detectverify/sentinel_test.go`, find:
```go
	c.tokens.tokenURL = tokenURL
```
Replace with:
```go
	c.tokens.TokenURL = tokenURL
```

- [ ] **Step 7: Run detectverify's tests**

Run: `go test ./internal/detectverify/... -v` (from `orchestrator/`)
Expected: `PASS` — all Sentinel tests green, `entra_auth_test.go`'s two tests are gone from this package (they now live in and pass under `internal/platform/msauth`), CrowdStrike/Defender/QRadar/Splunk tests unaffected by this step.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/platform/msauth orchestrator/internal/detectverify/sentinel.go orchestrator/internal/detectverify/sentinel_test.go
git rm orchestrator/internal/detectverify/entra_auth.go orchestrator/internal/detectverify/entra_auth_test.go
git commit -m "refactor(detectverify): extract shared Entra OAuth token source into internal/platform/msauth"
```

---

### Task 2: Extract CrowdStrike client into `internal/vendors/crowdstrike`

**Files:**
- Create: `orchestrator/internal/vendors/crowdstrike/client.go`
- Create: `orchestrator/internal/vendors/crowdstrike/client_test.go`
- Create: `orchestrator/internal/vendors/crowdstrike/auth.go`
- Create: `orchestrator/internal/vendors/crowdstrike/auth_test.go`
- Modify: `orchestrator/internal/detectverify/crowdstrike.go` (becomes a thin wrapper)
- Delete: `orchestrator/internal/detectverify/crowdstrike_auth.go`
- Modify: `orchestrator/internal/detectverify/crowdstrike_test.go` (updated to exercise the thin wrapper against the new package)
- Delete: `orchestrator/internal/detectverify/crowdstrike_auth_test.go`

**Interfaces:**
- Produces: `crowdstrike.Config{BaseURL, ClientID, ClientSecret string}`, `crowdstrike.Client`, `crowdstrike.New(cfg Config) *Client`, `crowdstrike.Alert{AlertID, RuleName string; Timestamp time.Time; Severity string; Techniques []string; RawJSON json.RawMessage}`, `crowdstrike.AlertQuery{Hostname string; WindowStart, WindowEnd time.Time}`, `(*Client).QueryAlerts(ctx, AlertQuery) ([]Alert, error)`, `(*Client).TestConnection(ctx) error`. `Client` exposes `QueryURL`, `DetailURL string` and its embedded token source's `TokenURL string` as exported fields for test overrides (same reasoning as Task 1 — `detectverify`'s test file overrides them from outside this package).
- Consumes: nothing from earlier tasks.

- [ ] **Step 1: Create the CrowdStrike auth file** (moved from `detectverify/crowdstrike_auth.go`, symbols exported, single consumer so it stays local to this package — not moved to `msauth`)

Create `orchestrator/internal/vendors/crowdstrike/auth.go`:
```go
package crowdstrike

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

// tokenSource fetches and caches a CrowdStrike Falcon OAuth2
// client-credentials token. The token grants whatever scopes the API client
// was provisioned with in the Falcon console.
type tokenSource struct {
	clientID, clientSecret string
	TokenURL               string // overridable in tests; defaults to <baseURL>/oauth2/token
	httpClient             *http.Client

	mu        sync.Mutex
	cached    string
	expiresAt time.Time
}

func newTokenSource(baseURL, clientID, clientSecret string) *tokenSource {
	return &tokenSource{
		clientID:     clientID,
		clientSecret: clientSecret,
		TokenURL:     strings.TrimRight(baseURL, "/") + "/oauth2/token",
		httpClient:   &http.Client{Timeout: 15 * time.Second},
	}
}

// Token returns a cached token when it has more than 60s left, else fetches
// a fresh one via the client-credentials grant.
func (c *tokenSource) Token(ctx context.Context) (string, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
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
```

- [ ] **Step 2: Create the auth test, moved from `detectverify/crowdstrike_auth_test.go`**

Create `orchestrator/internal/vendors/crowdstrike/auth_test.go`:
```go
package crowdstrike

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenSource_FetchesAndCaches(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", r.FormValue("grant_type"))
		}
		w.Write([]byte(`{"access_token":"tok-1","expires_in":1800}`))
	}))
	defer srv.Close()

	ts := newTokenSource("https://api.crowdstrike.com", "client-1", "secret-1")
	ts.TokenURL = srv.URL

	tok, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("token = %q, want tok-1", tok)
	}

	tok2, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("Token (cached): %v", err)
	}
	if tok2 != "tok-1" {
		t.Fatalf("cached token = %q, want tok-1", tok2)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (the second Token() call should reuse the cache)", calls)
	}
}

func TestTokenSource_HTTPErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errors":[{"message":"invalid client"}]}`))
	}))
	defer srv.Close()

	ts := newTokenSource("https://api.crowdstrike.com", "client-1", "bad-secret")
	ts.TokenURL = srv.URL

	if _, err := ts.Token(context.Background()); err == nil {
		t.Fatal("expected an error from a 401 token response")
	}
}
```

- [ ] **Step 3: Create the client (alert query), moved from `detectverify/crowdstrike.go`'s query/parse logic, with `Verify`/`matchAlerts` stripped out — verdict-matching stays in `detectverify`, this package only fetches and normalizes alerts**

Create `orchestrator/internal/vendors/crowdstrike/client.go`:
```go
package crowdstrike

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config holds the connection settings for one CrowdStrike Falcon tenant.
type Config struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
}

// Alert is one CrowdStrike Falcon alert, normalized for detectverify's
// vendor-agnostic matching logic.
type Alert struct {
	AlertID    string
	RuleName   string
	Timestamp  time.Time
	Severity   string
	Techniques []string
	RawJSON    json.RawMessage
}

// AlertQuery scopes an alert search to one host and time window.
type AlertQuery struct {
	Hostname    string
	WindowStart time.Time
	WindowEnd   time.Time
}

// Client is a CrowdStrike Falcon API client. QueryURL/DetailURL are
// exported so tests outside this package (internal/detectverify) can point
// them at an httptest.Server.
type Client struct {
	QueryURL   string // defaults to <baseURL>/alerts/queries/alerts/v2
	DetailURL  string // defaults to <baseURL>/alerts/entities/alerts/v2
	tokens     *tokenSource
	httpClient *http.Client
}

func New(cfg Config) *Client {
	base := strings.TrimRight(cfg.BaseURL, "/")
	return &Client{
		QueryURL:   base + "/alerts/queries/alerts/v2",
		DetailURL:  base + "/alerts/entities/alerts/v2",
		tokens:     newTokenSource(cfg.BaseURL, cfg.ClientID, cfg.ClientSecret),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// TokenURL exposes the underlying token source's overridable URL for tests.
func (c *Client) TokenURL() *string { return &c.tokens.TokenURL }

func (c *Client) QueryAlerts(ctx context.Context, q AlertQuery) ([]Alert, error) {
	ids, err := c.queryAlertIDs(ctx, buildFQLFilter(q))
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	data, err := c.fetchAlertDetails(ctx, ids)
	if err != nil {
		return nil, err
	}
	return parseAlerts(data)
}

func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.queryAlertIDs(ctx, "")
	return err
}

func buildFQLFilter(q AlertQuery) string {
	host := escapeFQL(q.Hostname)
	return fmt.Sprintf(
		`device.hostname:'%s'+created_timestamp:>'%s'+created_timestamp:<'%s'`,
		host, q.WindowStart.UTC().Format(time.RFC3339), q.WindowEnd.UTC().Format(time.RFC3339))
}

func (c *Client) queryAlertIDs(ctx context.Context, filter string) ([]string, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("limit", "100")
	if filter != "" {
		q.Set("filter", filter)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.QueryURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike query alerts: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("crowdstrike query alerts: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		Resources []string `json:"resources"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("crowdstrike: parse query response: %w", err)
	}
	return out.Resources, nil
}

func (c *Client) fetchAlertDetails(ctx context.Context, ids []string) ([]byte, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string][]string{"composite_ids": ids})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.DetailURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike fetch alert details: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("crowdstrike fetch alert details: HTTP %d: %s", resp.StatusCode, data)
	}
	return data, nil
}

func parseAlerts(data []byte) ([]Alert, error) {
	var resp struct {
		Resources []struct {
			CompositeID      string `json:"composite_id"`
			Name             string `json:"name"`
			DisplayName      string `json:"display_name"`
			Severity         int    `json:"severity"`
			CreatedTimestamp string `json:"created_timestamp"`
			Behaviors        []struct {
				TechniqueID string `json:"technique_id"`
			} `json:"behaviors"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("crowdstrike: parse alert details: %w", err)
	}
	var out []Alert
	for _, r := range resp.Resources {
		ts, _ := time.Parse(time.RFC3339, r.CreatedTimestamp)
		var techniques []string
		for _, b := range r.Behaviors {
			if b.TechniqueID != "" {
				techniques = append(techniques, b.TechniqueID)
			}
		}
		name := r.Name
		if name == "" {
			name = r.DisplayName
		}
		a := Alert{
			AlertID:    r.CompositeID,
			RuleName:   name,
			Timestamp:  ts,
			Severity:   strconv.Itoa(r.Severity),
			Techniques: techniques,
		}
		raw, _ := json.Marshal(map[string]any{
			"alertId": a.AlertID, "ruleName": a.RuleName, "timestamp": a.Timestamp,
			"severity": a.Severity, "techniques": a.Techniques,
		})
		a.RawJSON = raw
		out = append(out, a)
	}
	return out, nil
}

func escapeFQL(s string) string {
	return strings.ReplaceAll(s, `'`, `\'`)
}
```

- [ ] **Step 4: Create the client test, adapted from `detectverify/crowdstrike_test.go` to exercise `QueryAlerts`/`TestConnection` directly instead of through `Verify`**

Create `orchestrator/internal/vendors/crowdstrike/client_test.go`:
```go
package crowdstrike

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func tokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":1800}`))
	}))
}

func newTestClient(t *testing.T, tokenURL, apiURL string) *Client {
	t.Helper()
	c := New(Config{BaseURL: "https://api.crowdstrike.com", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	c.QueryURL = apiURL + "/alerts/queries/alerts/v2"
	c.DetailURL = apiURL + "/alerts/entities/alerts/v2"
	return c
}

func TestQueryAlerts_TechniqueTaggedAlert_Returned(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	alertTime := time.Date(2026, 7, 17, 10, 0, 20, 0, time.UTC)
	var detailCalled bool
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/alerts/queries/alerts/v2":
			json.NewEncoder(w).Encode(map[string]any{"resources": []string{"a1", "a2"}})
		case r.Method == http.MethodPost && r.URL.Path == "/alerts/entities/alerts/v2":
			detailCalled = true
			json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{
				{
					"composite_id": "a1", "name": "Suspicious PowerShell", "severity": 80,
					"created_timestamp": alertTime.Format(time.RFC3339),
					"behaviors":         []map[string]any{{"technique_id": "T1059.001"}},
				},
				{
					"composite_id": "a2", "name": "Generic Alert", "severity": 20,
					"created_timestamp": alertTime.Add(time.Second).Format(time.RFC3339),
					"behaviors":         []map[string]any{},
				},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer apiSrv.Close()

	c := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	alerts, err := c.QueryAlerts(context.Background(), AlertQuery{
		Hostname: "HOST1", WindowStart: alertTime.Add(-time.Hour), WindowEnd: alertTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if !detailCalled {
		t.Fatal("expected the detail endpoint to be called when resources is non-empty")
	}
	if len(alerts) != 2 {
		t.Fatalf("alerts = %+v, want 2", alerts)
	}
	if alerts[0].AlertID != "a1" || len(alerts[0].Techniques) != 1 || alerts[0].Techniques[0] != "T1059.001" {
		t.Fatalf("alerts[0] = %+v, want a1 tagged with T1059.001", alerts[0])
	}
}

func TestQueryAlerts_NoResources_SkipsDetail(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var detailCalled bool
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/alerts/queries/alerts/v2":
			json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
		case r.Method == http.MethodPost && r.URL.Path == "/alerts/entities/alerts/v2":
			detailCalled = true
			json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{}})
		}
	}))
	defer apiSrv.Close()

	c := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	alerts, err := c.QueryAlerts(context.Background(), AlertQuery{Hostname: "HOST1"})
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("alerts = %+v, want none", alerts)
	}
	if detailCalled {
		t.Fatal("detail endpoint should not be called when the query returns no resources")
	}
}

func TestQueryAlerts_QueryHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer apiSrv.Close()

	c := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	if _, err := c.QueryAlerts(context.Background(), AlertQuery{Hostname: "HOST1"}); err == nil {
		t.Fatal("expected an error from a 500 query response")
	}
}

func TestTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
	}))
	defer apiSrv.Close()

	c := newTestClient(t, tokenSrv.URL, apiSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
```

- [ ] **Step 5: Run the new package's tests**

Run: `go test ./internal/vendors/crowdstrike/... -v` (from `orchestrator/`)
Expected: `PASS`, all four tests green.

- [ ] **Step 6: Rewrite `detectverify/crowdstrike.go` as a thin wrapper**

Replace the entire contents of `orchestrator/internal/detectverify/crowdstrike.go` with:
```go
package detectverify

import (
	"context"

	"github.com/audspect/bas/internal/vendors/crowdstrike"
)

// crowdstrikeConnector adapts internal/vendors/crowdstrike's alert query to
// detectverify's Connector interface. Response actions (isolate/kill/
// quarantine) live on crowdstrike.Client directly and are consumed by
// internal/actions (a later plan), never by this package.
type crowdstrikeConnector struct {
	client *crowdstrike.Client
}

func newCrowdStrikeConnector(cfg Config) *crowdstrikeConnector {
	return &crowdstrikeConnector{
		client: crowdstrike.New(crowdstrike.Config{
			BaseURL: cfg.BaseURL, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		}),
	}
}

func (c *crowdstrikeConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	alerts, err := c.client.QueryAlerts(ctx, crowdstrike.AlertQuery{
		Hostname: req.HostName, WindowStart: req.WindowStart, WindowEnd: req.WindowEnd,
	})
	if err != nil {
		return VerifyResult{}, err
	}
	normalized := make([]normalizedAlert, 0, len(alerts))
	for _, a := range alerts {
		normalized = append(normalized, normalizedAlert{
			AlertID: a.AlertID, RuleName: a.RuleName, Timestamp: a.Timestamp,
			Severity: a.Severity, Techniques: a.Techniques, RawJSON: a.RawJSON,
		})
	}
	return matchAlerts(req, normalized), nil
}

func (c *crowdstrikeConnector) TestConnection(ctx context.Context) error {
	return c.client.TestConnection(ctx)
}
```

- [ ] **Step 7: Rewrite `detectverify/crowdstrike_test.go` to exercise the thin wrapper**

Replace the entire contents of `orchestrator/internal/detectverify/crowdstrike_test.go` with:
```go
package detectverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestCrowdStrikeConnector(t *testing.T, tokenURL, apiURL string) *crowdstrikeConnector {
	t.Helper()
	c := newCrowdStrikeConnector(Config{Provider: "crowdstrike", BaseURL: "https://api.crowdstrike.com", ClientID: "c1", ClientSecret: "s1"})
	*c.client.TokenURL() = tokenURL
	c.client.QueryURL = apiURL + "/alerts/queries/alerts/v2"
	c.client.DetailURL = apiURL + "/alerts/entities/alerts/v2"
	return c
}

func TestCrowdStrikeVerify_TechniqueTaggedAlert_Detected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	stepTime := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(20 * time.Second)
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/alerts/queries/alerts/v2":
			json.NewEncoder(w).Encode(map[string]any{"resources": []string{"a1", "a2"}})
		case r.Method == http.MethodPost && r.URL.Path == "/alerts/entities/alerts/v2":
			json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{
				{
					"composite_id": "a1", "name": "Suspicious PowerShell", "severity": 80,
					"created_timestamp": alertTime.Format(time.RFC3339),
					"behaviors":         []map[string]any{{"technique_id": "T1059.001"}},
				},
				{
					"composite_id": "a2", "name": "Generic Alert", "severity": 20,
					"created_timestamp": alertTime.Add(time.Second).Format(time.RFC3339),
					"behaviors":         []map[string]any{},
				},
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer apiSrv.Close()

	c := newTestCrowdStrikeConnector(t, tokenSrv.URL, apiSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{
		TechniqueID: "T1059.001", HostName: "HOST1", StepExecutedAt: stepTime,
		WindowStart: stepTime.Add(-2 * time.Minute), WindowEnd: stepTime.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high", result)
	}
	if result.DetectionLatency != 20*time.Second {
		t.Fatalf("DetectionLatency = %v, want 20s", result.DetectionLatency)
	}
	if len(result.MatchedAlerts) != 2 {
		t.Fatalf("MatchedAlerts = %+v, want 2", result.MatchedAlerts)
	}
}

func TestCrowdStrikeVerify_NoResources_NotDetected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
	}))
	defer apiSrv.Close()

	c := newTestCrowdStrikeConnector(t, tokenSrv.URL, apiSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
}

func TestCrowdStrikeVerify_QueryHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer apiSrv.Close()

	c := newTestCrowdStrikeConnector(t, tokenSrv.URL, apiSrv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from a 500 query response, not a fabricated NotDetected")
	}
}

func TestCrowdStrikeTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
	}))
	defer apiSrv.Close()

	c := newTestCrowdStrikeConnector(t, tokenSrv.URL, apiSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
```
Note: `tokenMock` is already defined in `sentinel_test.go` (same `detectverify` package) — this file reuses it rather than redefining it.

- [ ] **Step 8: Delete the old CrowdStrike auth files**

```bash
rm orchestrator/internal/detectverify/crowdstrike_auth.go
rm orchestrator/internal/detectverify/crowdstrike_auth_test.go
```

- [ ] **Step 9: Run detectverify's tests**

Run: `go test ./internal/detectverify/... -v` (from `orchestrator/`)
Expected: `PASS` — all four rewritten CrowdStrike tests green, everything else unaffected.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/vendors/crowdstrike orchestrator/internal/detectverify/crowdstrike.go orchestrator/internal/detectverify/crowdstrike_test.go
git rm orchestrator/internal/detectverify/crowdstrike_auth.go orchestrator/internal/detectverify/crowdstrike_auth_test.go
git commit -m "refactor(detectverify): extract CrowdStrike client into internal/vendors/crowdstrike"
```

---

### Task 3: Extract Defender client into `internal/vendors/defender`

**Files:**
- Create: `orchestrator/internal/vendors/defender/client.go`
- Create: `orchestrator/internal/vendors/defender/client_test.go`
- Modify: `orchestrator/internal/detectverify/defenderxdr.go` (becomes a thin wrapper)
- Modify: `orchestrator/internal/detectverify/defenderxdr_test.go` (updated to exercise the thin wrapper against the new package)

**Interfaces:**
- Consumes: `msauth.EntraTokenSource`/`msauth.NewEntraTokenSource` (Task 1).
- Produces: `defender.Config{TenantID, ClientID, ClientSecret string}`, `defender.Client`, `defender.New(cfg Config) *Client`, `defender.Alert{ID, RuleName string; Timestamp time.Time; Severity string; Techniques []string; DeviceDNSName string; RawJSON json.RawMessage}`, `(*Client).QueryAlerts(ctx, start, end time.Time) ([]Alert, error)`, `(*Client).TestConnection(ctx) error`. `Client.BaseURL string` and its token source's `TokenURL string` are exported for test overrides.

- [ ] **Step 1: Create the Defender client** (moved from `detectverify/defenderxdr.go`, using `msauth`; `Verify`'s host-filtering and verdict logic stays in `detectverify` — this package returns every alert in the window, unfiltered by host, since host-filtering is verification-specific and a later response-action consumer of this package won't need it)

Create `orchestrator/internal/vendors/defender/client.go`:
```go
package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/audspect/bas/internal/platform/msauth"
)

// Config holds the connection settings for one Defender/Entra tenant.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

// Alert is one Defender XDR alert, normalized for detectverify's
// vendor-agnostic matching logic. DeviceDNSName is kept (rather than
// filtered here) so detectverify's host-matching stays in detectverify.
type Alert struct {
	ID            string
	RuleName      string
	Timestamp     time.Time
	Severity      string
	Techniques    []string
	DeviceDNSName string
	RawJSON       json.RawMessage
}

// Client is a Microsoft Graph security-alerts API client. BaseURL is
// exported so tests outside this package (internal/detectverify) can point
// it at an httptest.Server.
type Client struct {
	BaseURL    string // defaults to https://graph.microsoft.com/v1.0
	tokens     *msauth.EntraTokenSource
	httpClient *http.Client
}

func New(cfg Config) *Client {
	return &Client{
		BaseURL: "https://graph.microsoft.com/v1.0",
		tokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://graph.microsoft.com/.default"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// TokenURL exposes the underlying token source's overridable URL for tests.
func (c *Client) TokenURL() *string { return &c.tokens.TokenURL }

type graphAlert struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	CreatedDateTime string   `json:"createdDateTime"`
	Techniques      []string `json:"techniques"`
	Evidence        []struct {
		DeviceDNSName string `json:"deviceDnsName"`
	} `json:"evidence"`
}

type graphAlertsResponse struct {
	Value []json.RawMessage `json:"value"`
}

func (c *Client) QueryAlerts(ctx context.Context, start, end time.Time) ([]Alert, error) {
	raws, err := c.queryRaw(ctx, start, end)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, raw := range raws {
		var ga graphAlert
		if err := json.Unmarshal(raw, &ga); err != nil {
			continue
		}
		ts, _ := time.Parse(time.RFC3339, ga.CreatedDateTime)
		a := Alert{
			ID: ga.ID, RuleName: ga.Title, Timestamp: ts, Severity: ga.Severity,
			Techniques: ga.Techniques, RawJSON: raw,
		}
		if len(ga.Evidence) > 0 {
			a.DeviceDNSName = ga.Evidence[0].DeviceDNSName
		}
		out = append(out, a)
	}
	return out, nil
}

func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.queryRaw(ctx, time.Now().Add(-time.Hour), time.Now())
	return err
}

func (c *Client) queryRaw(ctx context.Context, start, end time.Time) ([]json.RawMessage, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf("createdDateTime ge %s and createdDateTime le %s",
		start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	reqURL := c.BaseURL + "/security/alerts_v2?" + url.Values{"$filter": {filter}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("defender xdr query: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("defender xdr query: HTTP %d: %s", resp.StatusCode, data)
	}
	var out graphAlertsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("defender xdr: parse response: %w", err)
	}
	return out.Value, nil
}
```

- [ ] **Step 2: Create the client test, adapted from `detectverify/defenderxdr_test.go` to exercise `QueryAlerts` directly (host-filtering assertions move to Step 4's rewritten `detectverify` test, since that's where host-filtering now lives)**

Create `orchestrator/internal/vendors/defender/client_test.go`:
```go
package defender

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func tokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func newTestClient(t *testing.T, tokenURL, graphURL string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	c.BaseURL = graphURL
	return c
}

func TestQueryAlerts_ReturnsNormalizedAlerts(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	alertTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Suspicious process", "severity": "high",
					"createdDateTime": alertTime.Format(time.RFC3339),
					"techniques":      []string{"T1055"},
					"evidence":        []map[string]any{{"deviceDnsName": "HOST1"}},
				},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	alerts, err := c.QueryAlerts(context.Background(), alertTime.Add(-time.Hour), alertTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts)
	}
	if alerts[0].ID != "alert-1" || alerts[0].DeviceDNSName != "HOST1" || len(alerts[0].Techniques) != 1 {
		t.Fatalf("alerts[0] = %+v, want alert-1/HOST1/[T1055]", alerts[0])
	}
}

func TestQueryAlerts_GraphHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	if _, err := c.QueryAlerts(context.Background(), time.Now().Add(-time.Hour), time.Now()); err == nil {
		t.Fatal("expected an error from a 403 Graph response")
	}
}

func TestTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}
```

- [ ] **Step 3: Run the new package's tests**

Run: `go test ./internal/vendors/defender/... -v` (from `orchestrator/`)
Expected: `PASS`, all three tests green.

- [ ] **Step 4: Rewrite `detectverify/defenderxdr.go` as a thin wrapper (host-filtering and verdict logic stay here)**

Replace the entire contents of `orchestrator/internal/detectverify/defenderxdr.go` with:
```go
package detectverify

import (
	"context"
	"strings"

	"github.com/audspect/bas/internal/vendors/defender"
)

// defenderXDRConnector adapts internal/vendors/defender's alert query to
// detectverify's Connector interface, applying host-filtering (a
// verification-specific concern the vendor client doesn't know about).
// Response actions (isolate/kill/quarantine) live on defender.Client
// directly and are consumed by internal/actions (a later plan), never by
// this package.
type defenderXDRConnector struct {
	client *defender.Client
}

func newDefenderXDRConnector(cfg Config) *defenderXDRConnector {
	return &defenderXDRConnector{
		client: defender.New(defender.Config{
			TenantID: cfg.TenantID, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		}),
	}
}

func (d *defenderXDRConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	alerts, err := d.client.QueryAlerts(ctx, req.WindowStart, req.WindowEnd)
	if err != nil {
		return VerifyResult{}, err
	}
	normalized := make([]normalizedAlert, 0, len(alerts))
	for _, a := range alerts {
		if !alertMentionsHost(a.DeviceDNSName, req.HostName) {
			continue
		}
		normalized = append(normalized, normalizedAlert{
			AlertID: a.ID, RuleName: a.RuleName, Timestamp: a.Timestamp,
			Severity: a.Severity, Techniques: a.Techniques,
			InvestigationURL: "https://security.microsoft.com/alerts/" + a.ID,
			RawJSON:          a.RawJSON,
		})
	}
	return matchAlerts(req, normalized), nil
}

// alertMentionsHost reports whether deviceDNSName matches hostName. When
// hostName is empty (agent has no known hostname) every alert is accepted —
// better to over-match at medium confidence than silently verify nothing.
func alertMentionsHost(deviceDNSName, hostName string) bool {
	if hostName == "" {
		return true
	}
	return strings.EqualFold(deviceDNSName, hostName)
}

func (d *defenderXDRConnector) TestConnection(ctx context.Context) error {
	return d.client.TestConnection(ctx)
}
```

- [ ] **Step 5: Rewrite `detectverify/defenderxdr_test.go` to exercise the thin wrapper, keeping the host-filtering assertions here**

Replace the entire contents of `orchestrator/internal/detectverify/defenderxdr_test.go` with:
```go
package detectverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestDefenderXDRConnector(t *testing.T, tokenURL, graphURL string) *defenderXDRConnector {
	t.Helper()
	c := newDefenderXDRConnector(Config{Provider: "microsoft_defender", TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.client.TokenURL() = tokenURL
	c.client.BaseURL = graphURL
	return c
}

func TestDefenderXDRVerify_HostMatchedTechniqueTaggedAlert_Detected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	stepTime := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	alertTime := stepTime.Add(2 * time.Minute)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Suspicious process", "severity": "high",
					"createdDateTime": alertTime.Format(time.RFC3339),
					"techniques":      []string{"T1055"},
					"evidence":        []map[string]any{{"deviceDnsName": "HOST1"}},
				},
				{
					"id": "alert-2", "title": "Unrelated host alert", "severity": "low",
					"createdDateTime": alertTime.Format(time.RFC3339),
					"techniques":      []string{"T1055"},
					"evidence":        []map[string]any{{"deviceDnsName": "OTHERHOST"}},
				},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestDefenderXDRConnector(t, tokenSrv.URL, graphSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{
		TechniqueID: "T1055", HostName: "HOST1", StepExecutedAt: stepTime,
		WindowStart: stepTime.Add(-2 * time.Minute), WindowEnd: stepTime.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high", result)
	}
	if len(result.MatchedAlerts) != 1 || result.MatchedAlerts[0].AlertID != "alert-1" {
		t.Fatalf("MatchedAlerts = %+v, want only alert-1 (the OTHERHOST alert must be filtered out)", result.MatchedAlerts)
	}
}

func TestDefenderXDRVerify_NoMatchingHost_NotDetected(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "alert-1", "createdDateTime": time.Now().Format(time.RFC3339), "evidence": []map[string]any{{"deviceDnsName": "OTHERHOST"}}},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestDefenderXDRConnector(t, tokenSrv.URL, graphSrv.URL)
	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1055", HostName: "HOST1", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
}

func TestDefenderXDRVerify_GraphHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	c := newTestDefenderXDRConnector(t, tokenSrv.URL, graphSrv.URL)
	if _, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1055", StepExecutedAt: time.Now()}); err == nil {
		t.Fatal("expected an error from a 403 Graph response, not a fabricated NotDetected")
	}
}
```

- [ ] **Step 6: Run detectverify's full test suite**

Run: `go test ./internal/detectverify/... -v` (from `orchestrator/`)
Expected: `PASS` — every test in the package green, including QRadar/Splunk (untouched by this plan).

- [ ] **Step 7: Run the whole module's build and vet as a final sanity check**

Run: `go build ./... && go vet ./...` (from `orchestrator/`)
Expected: no errors — confirms no other file in the module referenced the now-deleted unexported symbols (`entraTokenSource`, `crowdstrikeTokenSource`, etc.).

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/vendors/defender orchestrator/internal/detectverify/defenderxdr.go orchestrator/internal/detectverify/defenderxdr_test.go
git commit -m "refactor(detectverify): extract Defender client into internal/vendors/defender"
```

---

## Self-Review Notes

**Spec coverage:** this plan covers only the spec's "Why move vendor code out of detectverify" architecture requirement — the foundation for Plans 2-4. Device resolution, Isolate/Release/KillProcess/QuarantineFile, the `actions` package, DB tables, permissions, and API routes are explicitly out of scope here and covered by later plans.

**Placeholder scan:** none — every step contains complete file content or an exact command with expected output.

**Type/name consistency:** `crowdstrike.Client.TokenURL()` and `defender.Client.TokenURL()` both return `*string` (a pointer to the exported field) rather than exposing the field directly, since the field lives on an unexported inner `tokenSource`/`msauth.EntraTokenSource` value reached through an exported accessor — Task 2 and Task 3's test files both use this same `*c.client.TokenURL() = tokenURL` pattern consistently. `msauth.EntraTokenSource.TokenURL` is a directly exported field (no accessor needed) since `EntraTokenSource` itself is exported and used directly by both `detectverify/sentinel.go` and `vendors/defender/client.go`.

**Deviation from the spec worth flagging to the user:** the spec said "No shared `internal/platform/auth`... each vendor's `auth.go` just moves as-is into its own vendor package." Task 1 introduces `internal/platform/msauth` anyway — reading `entra_auth.go`'s doc comment during planning revealed it's already shared by Sentinel (staying in `detectverify`) and Defender XDR (moving to `internal/vendors/defender`), so "move as-is into its own vendor package" doesn't have a single valid destination. This is a small, narrowly-scoped exception (one file, one real shared consumer today) — not a reopening of the broader "no `platform/` package" scope decision.
