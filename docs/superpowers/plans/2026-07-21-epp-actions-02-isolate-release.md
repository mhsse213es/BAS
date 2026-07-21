# EPP Response Actions — Plan 2: Device Resolution + Isolate/Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `internal/vendors/crowdstrike` and `internal/vendors/defender` the ability to resolve a hostname to a vendor device ID (cached) and to isolate/release that device from the network — the two response actions with stable, well-documented, single-call vendor APIs.

**Architecture:** Each vendor's `Client` gains a small in-memory, TTL-cached `ResolveDevice(ctx, hostname) (deviceID string, err error)` plus `Isolate`/`Release` methods that take the resolved device ID and return the vendor's own request/trace ID for audit purposes. No shared cache abstraction — each vendor package gets its own ~10-line cache, matching the design decision that a third vendor (not yet planned) is the trigger for extracting one, not two.

**Tech Stack:** Go 1.26, stdlib `net/http`/`net/http/httptest` only.

## Global Constraints

- This is Plan 2 of 5 for EPP Response Actions (spec: `docs/superpowers/specs/2026-07-21-epp-response-actions-design.md`). Plan 1 (vendor extraction, commits `d3328c1`/`f581127`/`84ecbd5`) is done. Plan 3 (KillProcess/QuarantineFile — CrowdStrike RTR + Defender Live Response/StopAndQuarantineFile), Plan 4 (`internal/actions` package + DB + permissions + API), and Plan 5 (UI) come after this one.
- Device cache TTL: 15 minutes (per spec — "TTL-cached (15 minutes, same pattern as the existing `ioc_enrichment` cache) so a large fleet doesn't hammer a rate-limited device-lookup endpoint").
- No behavior change to existing `Verify`/`QueryAlerts`/`TestConnection` methods or their tests — this plan only adds new methods.
- Module path: `github.com/audspect/bas`.
- **Endpoint confidence note (for the implementer):** CrowdStrike's `devices-actions/v2` contain/lift_containment endpoints and Defender's `machines/{id}/isolate`/`unisolate` endpoints are long-stable, well-documented vendor APIs — implemented here with normal confidence, not the "needs live verification" caveat that will apply to Plan 3's RTR/Live-Response work. Still confirm against current vendor docs before pointing this at a production tenant for the first time, as with any third-party integration.

---

### Task 1: Device resolution + Isolate/Release for CrowdStrike

**Files:**
- Modify: `orchestrator/internal/vendors/crowdstrike/client.go`
- Modify: `orchestrator/internal/vendors/crowdstrike/client_test.go`

**Interfaces:**
- Consumes: nothing new — reuses `Client.tokens`, `Client.httpClient` already defined in Plan 1.
- Produces: `(*Client).ResolveDevice(ctx context.Context, hostname string) (string, error)`, `(*Client).Isolate(ctx context.Context, deviceID string) (string, error)`, `(*Client).Release(ctx context.Context, deviceID string) (string, error)` — all consumed by Plan 4's `internal/actions` package. `Client.DeviceQueryURL`, `Client.ActionURL string` exported for test overrides (same pattern as `QueryURL`/`DetailURL`).

- [ ] **Step 1: Write the failing tests**

Add to the end of `orchestrator/internal/vendors/crowdstrike/client_test.go` (after the existing `TestTestConnection_Success` function, same file, same package):
```go

func newTestClientWithDeviceAndActionURLs(t *testing.T, tokenURL, deviceURL, actionURL string) *Client {
	t.Helper()
	c := New(Config{BaseURL: "https://api.crowdstrike.com", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	c.DeviceQueryURL = deviceURL
	c.ActionURL = actionURL
	return c
}

func TestResolveDevice_FindsAndCaches(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var queryCalls int
	deviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryCalls++
		if r.URL.Query().Get("filter") != `hostname:'HOST1'` {
			t.Errorf("filter = %q", r.URL.Query().Get("filter"))
		}
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{"device-123"}})
	}))
	defer deviceSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, deviceSrv.URL, "")
	id, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice: %v", err)
	}
	if id != "device-123" {
		t.Fatalf("id = %q, want device-123", id)
	}

	// Second call within the TTL must hit the cache, not the API again.
	id2, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice (cached): %v", err)
	}
	if id2 != "device-123" {
		t.Fatalf("cached id = %q, want device-123", id2)
	}
	if queryCalls != 1 {
		t.Fatalf("queryCalls = %d, want 1 (second ResolveDevice should reuse the cache)", queryCalls)
	}
}

func TestResolveDevice_NoMatch_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	deviceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resources": []string{}})
	}))
	defer deviceSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, deviceSrv.URL, "")
	if _, err := c.ResolveDevice(context.Background(), "NOHOST"); err == nil {
		t.Fatal("expected an error when no device matches the hostname")
	}
}

func TestIsolate_SendsContainAction(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotActionName string
	var gotBody map[string][]string
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotActionName = r.URL.Query().Get("action_name")
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"trace_id": "trace-abc"}})
	}))
	defer actionSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, "", actionSrv.URL)
	traceID, err := c.Isolate(context.Background(), "device-123")
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if traceID != "trace-abc" {
		t.Fatalf("traceID = %q, want trace-abc", traceID)
	}
	if gotActionName != "contain" {
		t.Fatalf("action_name = %q, want contain", gotActionName)
	}
	if len(gotBody["ids"]) != 1 || gotBody["ids"][0] != "device-123" {
		t.Fatalf("body ids = %v, want [device-123]", gotBody["ids"])
	}
}

func TestRelease_SendsLiftContainmentAction(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotActionName string
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotActionName = r.URL.Query().Get("action_name")
		json.NewEncoder(w).Encode(map[string]any{"meta": map[string]any{"trace_id": "trace-def"}})
	}))
	defer actionSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, "", actionSrv.URL)
	traceID, err := c.Release(context.Background(), "device-123")
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if traceID != "trace-def" {
		t.Fatalf("traceID = %q, want trace-def", traceID)
	}
	if gotActionName != "lift_containment" {
		t.Fatalf("action_name = %q, want lift_containment", gotActionName)
	}
}

func TestDeviceAction_VendorReportsError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{"message": "device not found"}}})
	}))
	defer actionSrv.Close()

	c := newTestClientWithDeviceAndActionURLs(t, tokenSrv.URL, "", actionSrv.URL)
	if _, err := c.Isolate(context.Background(), "device-999"); err == nil {
		t.Fatal("expected an error when the vendor response body carries an errors[] entry")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vendors/crowdstrike/... -run 'TestResolveDevice|TestIsolate|TestRelease|TestDeviceAction' -v` (from `orchestrator/`)
Expected: compile failure — `ResolveDevice`, `Isolate`, `Release`, `DeviceQueryURL`, `ActionURL` are undefined on `Client`.

- [ ] **Step 3: Implement device resolution and Isolate/Release**

In `orchestrator/internal/vendors/crowdstrike/client.go`, find:
```go
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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)
```

Find:
```go
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
```
Replace with:
```go
// deviceCacheEntry is one hostname's cached device-ID resolution.
type deviceCacheEntry struct {
	deviceID  string
	expiresAt time.Time
}

// deviceCacheTTL matches the existing ioc_enrichment cache's TTL philosophy
// — long enough that a large fleet doesn't hammer a rate-limited endpoint,
// short enough that a device re-image or hostname change isn't stale for
// long.
const deviceCacheTTL = 15 * time.Minute

// Client is a CrowdStrike Falcon API client. QueryURL/DetailURL/
// DeviceQueryURL/ActionURL are exported so tests outside this package
// (internal/detectverify) can point them at an httptest.Server.
type Client struct {
	QueryURL       string // defaults to <baseURL>/alerts/queries/alerts/v2
	DetailURL      string // defaults to <baseURL>/alerts/entities/alerts/v2
	DeviceQueryURL string // defaults to <baseURL>/devices/queries/devices/v1
	ActionURL      string // defaults to <baseURL>/devices/entities/devices-actions/v2
	tokens         *tokenSource
	httpClient     *http.Client

	deviceCacheMu sync.Mutex
	deviceCache   map[string]deviceCacheEntry
}

func New(cfg Config) *Client {
	base := strings.TrimRight(cfg.BaseURL, "/")
	return &Client{
		QueryURL:       base + "/alerts/queries/alerts/v2",
		DetailURL:      base + "/alerts/entities/alerts/v2",
		DeviceQueryURL: base + "/devices/queries/devices/v1",
		ActionURL:      base + "/devices/entities/devices-actions/v2",
		tokens:         newTokenSource(cfg.BaseURL, cfg.ClientID, cfg.ClientSecret),
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		deviceCache:    make(map[string]deviceCacheEntry),
	}
}
```

Find:
```go
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.queryAlertIDs(ctx, "")
	return err
}
```
Add immediately after it:
```go

// ResolveDevice returns hostname's CrowdStrike device ID (the "aid" the
// response-action endpoints require), caching the result for
// deviceCacheTTL. This is a prerequisite for mutation, not verification —
// QueryAlerts never calls this; only Isolate/Release (and, in a later plan,
// KillProcess/QuarantineFile) do.
func (c *Client) ResolveDevice(ctx context.Context, hostname string) (string, error) {
	c.deviceCacheMu.Lock()
	if e, ok := c.deviceCache[hostname]; ok && time.Now().Before(e.expiresAt) {
		c.deviceCacheMu.Unlock()
		return e.deviceID, nil
	}
	c.deviceCacheMu.Unlock()

	token, err := c.tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("filter", fmt.Sprintf(`hostname:'%s'`, escapeFQL(hostname)))
	q.Set("limit", "1")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.DeviceQueryURL+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdstrike resolve device: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("crowdstrike resolve device: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		Resources []string `json:"resources"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("crowdstrike: parse device query response: %w", err)
	}
	if len(out.Resources) == 0 {
		return "", fmt.Errorf("crowdstrike: no device found for hostname %q", hostname)
	}
	deviceID := out.Resources[0]

	c.deviceCacheMu.Lock()
	c.deviceCache[hostname] = deviceCacheEntry{deviceID: deviceID, expiresAt: time.Now().Add(deviceCacheTTL)}
	c.deviceCacheMu.Unlock()
	return deviceID, nil
}

// Isolate network-contains deviceID (Falcon's "contain" action), returning
// the vendor's trace ID for the audit trail.
func (c *Client) Isolate(ctx context.Context, deviceID string) (string, error) {
	return c.deviceAction(ctx, "contain", deviceID)
}

// Release lifts network containment on deviceID.
func (c *Client) Release(ctx context.Context, deviceID string) (string, error) {
	return c.deviceAction(ctx, "lift_containment", deviceID)
}

func (c *Client) deviceAction(ctx context.Context, actionName, deviceID string) (string, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string][]string{"ids": {deviceID}})
	reqURL := c.ActionURL + "?" + url.Values{"action_name": {actionName}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdstrike device action %s: %w", actionName, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("crowdstrike device action %s: HTTP %d: %s", actionName, resp.StatusCode, data)
	}
	var out struct {
		Meta struct {
			TraceID string `json:"trace_id"`
		} `json:"meta"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("crowdstrike: parse device action response: %w", err)
	}
	if len(out.Errors) > 0 {
		return "", fmt.Errorf("crowdstrike device action %s: %s", actionName, out.Errors[0].Message)
	}
	return out.Meta.TraceID, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/vendors/crowdstrike/... -v` (from `orchestrator/`)
Expected: `PASS` — all tests green, including the pre-existing alert-query tests from Plan 1 (unaffected by this change).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/vendors/crowdstrike/client.go orchestrator/internal/vendors/crowdstrike/client_test.go
git commit -m "feat(vendors/crowdstrike): add device resolution and isolate/release"
```

---

### Task 2: Device resolution + Isolate/Release for Defender

**Files:**
- Modify: `orchestrator/internal/vendors/defender/client.go`
- Modify: `orchestrator/internal/vendors/defender/client_test.go`

**Interfaces:**
- Consumes: `msauth.NewEntraTokenSource` (Plan 1) — a *second* token source with a different OAuth scope, since Defender's machine-action API (`api.securitycenter.microsoft.com`) is a separate resource from the Graph API (`graph.microsoft.com`) already used for alerts, even though both authenticate against the same Entra tenant/app registration.
- Produces: `(*Client).ResolveDevice(ctx context.Context, hostname string) (string, error)`, `(*Client).Isolate(ctx context.Context, deviceID string) (string, error)`, `(*Client).Release(ctx context.Context, deviceID string) (string, error)` — consumed by Plan 4. `Client.ActionBaseURL string` and `(*Client).ActionTokenURL() *string` exported for test overrides.

- [ ] **Step 1: Write the failing tests**

Add to the end of `orchestrator/internal/vendors/defender/client_test.go` (after the existing `TestTestConnection_Success` function, same file, same package):
```go

func newTestClientWithActionURLs(t *testing.T, tokenURL, actionTokenURL, actionBaseURL string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	*c.ActionTokenURL() = actionTokenURL
	c.ActionBaseURL = actionBaseURL
	return c
}

func TestResolveDevice_FindsAndCaches(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var queryCalls int
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryCalls++
		if r.URL.Query().Get("$filter") != "computerDnsName eq 'HOST1'" {
			t.Errorf("$filter = %q", r.URL.Query().Get("$filter"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"id": "machine-123", "computerDnsName": "HOST1"}},
		})
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	id, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice: %v", err)
	}
	if id != "machine-123" {
		t.Fatalf("id = %q, want machine-123", id)
	}

	id2, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice (cached): %v", err)
	}
	if id2 != "machine-123" {
		t.Fatalf("cached id = %q, want machine-123", id2)
	}
	if queryCalls != 1 {
		t.Fatalf("queryCalls = %d, want 1 (second ResolveDevice should reuse the cache)", queryCalls)
	}
}

func TestResolveDevice_NoMatch_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	if _, err := c.ResolveDevice(context.Background(), "NOHOST"); err == nil {
		t.Fatal("expected an error when no machine matches the hostname")
	}
}

func TestIsolate_CallsIsolateEndpoint(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath string
	var gotBody map[string]any
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "action-abc"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	actionID, err := c.Isolate(context.Background(), "machine-123")
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if actionID != "action-abc" {
		t.Fatalf("actionID = %q, want action-abc", actionID)
	}
	if gotPath != "/machines/machine-123/isolate" {
		t.Fatalf("path = %q, want /machines/machine-123/isolate", gotPath)
	}
	if gotBody["IsolationType"] != "Full" {
		t.Fatalf("body = %v, want IsolationType=Full", gotBody)
	}
}

func TestRelease_CallsUnisolateEndpoint(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath string
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"id": "action-def"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	actionID, err := c.Release(context.Background(), "machine-123")
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if actionID != "action-def" {
		t.Fatalf("actionID = %q, want action-def", actionID)
	}
	if gotPath != "/machines/machine-123/unisolate" {
		t.Fatalf("path = %q, want /machines/machine-123/unisolate", gotPath)
	}
}

func TestMachineAction_HTTPError_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	if _, err := c.Isolate(context.Background(), "machine-999"); err == nil {
		t.Fatal("expected an error from a 403 machine action response")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vendors/defender/... -run 'TestResolveDevice|TestIsolate|TestRelease|TestMachineAction' -v` (from `orchestrator/`)
Expected: compile failure — `ResolveDevice`, `Isolate`, `Release`, `ActionBaseURL`, `ActionTokenURL` are undefined on `Client`.

- [ ] **Step 3: Implement device resolution and Isolate/Release**

In `orchestrator/internal/vendors/defender/client.go`, find:
```go
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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/platform/msauth"
)
```

Find:
```go
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
```
Replace with:
```go
// deviceCacheEntry is one hostname's cached device-ID resolution.
type deviceCacheEntry struct {
	deviceID  string
	expiresAt time.Time
}

// deviceCacheTTL matches the existing ioc_enrichment cache's TTL philosophy.
const deviceCacheTTL = 15 * time.Minute

// Client is a Microsoft Graph security-alerts API client plus a Defender
// for Endpoint machine-actions API client. These are two different
// Microsoft resources (graph.microsoft.com vs api.securitycenter.microsoft.com)
// under the same Entra tenant/app registration, so each needs its own OAuth
// scope and therefore its own token source, even though both are "Defender".
// BaseURL/ActionBaseURL are exported so tests outside this package
// (internal/detectverify) can point them at an httptest.Server.
type Client struct {
	BaseURL       string // defaults to https://graph.microsoft.com/v1.0
	ActionBaseURL string // defaults to https://api.securitycenter.microsoft.com/api
	tokens        *msauth.EntraTokenSource
	actionTokens  *msauth.EntraTokenSource
	httpClient    *http.Client

	deviceCacheMu sync.Mutex
	deviceCache   map[string]deviceCacheEntry
}

func New(cfg Config) *Client {
	return &Client{
		BaseURL:       "https://graph.microsoft.com/v1.0",
		ActionBaseURL: "https://api.securitycenter.microsoft.com/api",
		tokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://graph.microsoft.com/.default"),
		actionTokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://api.securitycenter.microsoft.com/.default"),
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		deviceCache: make(map[string]deviceCacheEntry),
	}
}

// TokenURL exposes the alerts token source's overridable URL for tests.
func (c *Client) TokenURL() *string { return &c.tokens.TokenURL }

// ActionTokenURL exposes the machine-actions token source's overridable URL
// for tests — separate from TokenURL because it is a different token
// source with a different OAuth scope.
func (c *Client) ActionTokenURL() *string { return &c.actionTokens.TokenURL }
```

Find:
```go
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.queryRaw(ctx, time.Now().Add(-time.Hour), time.Now())
	return err
}
```
Add immediately after it:
```go

// ResolveDevice returns hostname's Defender machine ID (the ID the
// machine-actions endpoints require), caching the result for
// deviceCacheTTL. This is a prerequisite for mutation, not verification —
// QueryAlerts never calls this; only Isolate/Release (and, in a later plan,
// KillProcess/QuarantineFile) do.
func (c *Client) ResolveDevice(ctx context.Context, hostname string) (string, error) {
	c.deviceCacheMu.Lock()
	if e, ok := c.deviceCache[hostname]; ok && time.Now().Before(e.expiresAt) {
		c.deviceCacheMu.Unlock()
		return e.deviceID, nil
	}
	c.deviceCacheMu.Unlock()

	token, err := c.actionTokens.Token(ctx)
	if err != nil {
		return "", err
	}
	filter := fmt.Sprintf("computerDnsName eq '%s'", escapeODataString(hostname))
	reqURL := c.ActionBaseURL + "/machines?" + url.Values{"$filter": {filter}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("defender resolve device: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("defender resolve device: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("defender: parse machines response: %w", err)
	}
	if len(out.Value) == 0 {
		return "", fmt.Errorf("defender: no machine found for hostname %q", hostname)
	}
	deviceID := out.Value[0].ID

	c.deviceCacheMu.Lock()
	c.deviceCache[hostname] = deviceCacheEntry{deviceID: deviceID, expiresAt: time.Now().Add(deviceCacheTTL)}
	c.deviceCacheMu.Unlock()
	return deviceID, nil
}

// Isolate fully network-isolates deviceID, returning the machine action ID
// for the audit trail.
func (c *Client) Isolate(ctx context.Context, deviceID string) (string, error) {
	return c.machineAction(ctx, deviceID, "isolate", map[string]any{
		"Comment": "Isolated by Audspect BAS response action", "IsolationType": "Full",
	})
}

// Release lifts isolation on deviceID.
func (c *Client) Release(ctx context.Context, deviceID string) (string, error) {
	return c.machineAction(ctx, deviceID, "unisolate", map[string]any{
		"Comment": "Released by Audspect BAS response action",
	})
}

func (c *Client) machineAction(ctx context.Context, deviceID, verb string, body map[string]any) (string, error) {
	token, err := c.actionTokens.Token(ctx)
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(body)
	reqURL := c.ActionBaseURL + "/machines/" + deviceID + "/" + verb
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("defender machine action %s: %w", verb, err)
	}
	defer resp.Body.Close()
	respData, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("defender machine action %s: HTTP %d: %s", verb, resp.StatusCode, respData)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respData, &out); err != nil {
		return "", fmt.Errorf("defender: parse machine action response: %w", err)
	}
	return out.ID, nil
}

// escapeODataString escapes a value for embedding in an OData $filter
// string literal, per the OData convention of doubling single quotes.
func escapeODataString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/vendors/defender/... -v` (from `orchestrator/`)
Expected: `PASS` — all tests green, including the pre-existing alert-query tests from Plan 1 (unaffected by this change).

- [ ] **Step 5: Run detectverify's tests as a regression check** (Defender's `Client` struct changed shape; `detectverify/defenderxdr.go` and its test construct one)

Run: `go test ./internal/detectverify/... -v` (from `orchestrator/`)
Expected: `PASS` — `newTestDefenderXDRConnector` only touches `c.client.TokenURL()` and `c.client.BaseURL`, both untouched by this task's changes, so nothing here should break.

- [ ] **Step 6: Run the whole module's build and vet as a final sanity check**

Run: `go build ./... && go vet ./...` (from `orchestrator/`)
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/vendors/defender/client.go orchestrator/internal/vendors/defender/client_test.go
git commit -m "feat(vendors/defender): add device resolution and isolate/release"
```

---

## Self-Review Notes

**Spec coverage:** this plan covers the "device resolution belongs in Response... TTL-cached" and half of the "Isolate/Release" action requirements from the spec's Architecture section, for both in-scope vendors (CrowdStrike, Defender). KillProcess/QuarantineFile are explicitly deferred to Plan 3 (see the split rationale at the top of this document). The `internal/actions` package that will call these methods, the safety rails (Admin-only permission, enrolled-agent-only targeting, mandatory reason), and the UI are Plans 4-5.

**Placeholder scan:** none — every step contains complete code or an exact command with expected output.

**Type/name consistency:** both vendors expose the identical trio `ResolveDevice(ctx, hostname string) (string, error)`, `Isolate(ctx, deviceID string) (string, error)`, `Release(ctx, deviceID string) (string, error)` — this symmetry is deliberate and is what will let Plan 4's `internal/actions` package dispatch to either vendor through the same call shape despite them being different types (no shared Go interface is declared for this — `internal/actions` will hold a small vendor-specific switch, matching this plan's already-established "no `dispatcher/` package" decision from the spec). `deviceCacheEntry`/`deviceCacheTTL` are duplicated identically in both vendor packages (intentional — see Architecture).
