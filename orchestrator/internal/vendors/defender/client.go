package defender

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
