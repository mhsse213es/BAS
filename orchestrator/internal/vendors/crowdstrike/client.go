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
	"sync"
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
// DeviceQueryURL/ActionURL/RTRSessionURL/RTRCommandURL are exported so
// tests outside this package (internal/detectverify) can point them at an
// httptest.Server.
type Client struct {
	QueryURL       string // defaults to <baseURL>/alerts/queries/alerts/v2
	DetailURL      string // defaults to <baseURL>/alerts/entities/alerts/v2
	DeviceQueryURL string // defaults to <baseURL>/devices/queries/devices/v1
	ActionURL      string // defaults to <baseURL>/devices/entities/devices-actions/v2
	RTRSessionURL  string // defaults to <baseURL>/real-time-response/entities/sessions/v1
	RTRCommandURL  string // defaults to <baseURL>/real-time-response/entities/active-responder-command/v1
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
		RTRSessionURL:  base + "/real-time-response/entities/sessions/v1",
		RTRCommandURL:  base + "/real-time-response/entities/active-responder-command/v1",
		tokens:         newTokenSource(cfg.BaseURL, cfg.ClientID, cfg.ClientSecret),
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		deviceCache:    make(map[string]deviceCacheEntry),
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

// KillProcess runs Falcon RTR's "kill" responder command for pid on
// deviceID, via a short-lived RTR session. Returns the vendor's
// cloud_request_id — this acknowledges the vendor accepted the command, not
// that it has finished executing (see Global Constraints: no polling to
// completion).
func (c *Client) KillProcess(ctx context.Context, deviceID string, pid int) (string, error) {
	return c.runRTRCommand(ctx, deviceID, "kill", fmt.Sprintf("kill %d", pid))
}

// QuarantineFile runs Falcon RTR's "rm" responder command against filePath
// on deviceID. CrowdStrike RTR has no command verb named "quarantine" —
// deletion via "rm" is the closest available responder action; confirm
// against current Falcon RTR command docs before relying on this in
// production (see Global Constraints).
func (c *Client) QuarantineFile(ctx context.Context, deviceID, filePath string) (string, error) {
	return c.runRTRCommand(ctx, deviceID, "rm", fmt.Sprintf(`rm "%s"`, filePath))
}

// runRTRCommand starts an RTR session on deviceID, sends one responder
// command, and best-effort closes the session (cleanup uses a fresh
// background context so a caller-cancelled ctx doesn't leave a dangling
// session).
func (c *Client) runRTRCommand(ctx context.Context, deviceID, baseCommand, commandString string) (string, error) {
	sessionID, err := c.startRTRSession(ctx, deviceID)
	if err != nil {
		return "", err
	}
	defer c.closeRTRSession(context.Background(), sessionID)

	return c.executeRTRCommand(ctx, deviceID, sessionID, baseCommand, commandString)
}

func (c *Client) startRTRSession(ctx context.Context, deviceID string) (string, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{"device_id": deviceID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RTRSessionURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdstrike start RTR session: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("crowdstrike start RTR session: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		Resources []struct {
			SessionID string `json:"session_id"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("crowdstrike: parse RTR session response: %w", err)
	}
	if len(out.Resources) == 0 || out.Resources[0].SessionID == "" {
		return "", fmt.Errorf("crowdstrike: RTR session response did not include a session_id")
	}
	return out.Resources[0].SessionID, nil
}

func (c *Client) executeRTRCommand(ctx context.Context, deviceID, sessionID, baseCommand, commandString string) (string, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{
		"base_command": baseCommand, "command_string": commandString,
		"session_id": sessionID, "device_id": deviceID,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RTRCommandURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("crowdstrike RTR command %s: %w", baseCommand, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("crowdstrike RTR command %s: HTTP %d: %s", baseCommand, resp.StatusCode, data)
	}
	var out struct {
		CloudRequestID string `json:"cloud_request_id"`
		Errors         []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("crowdstrike: parse RTR command response: %w", err)
	}
	if len(out.Errors) > 0 {
		return "", fmt.Errorf("crowdstrike RTR command %s: %s", baseCommand, out.Errors[0].Message)
	}
	if out.CloudRequestID == "" {
		return "", fmt.Errorf("crowdstrike: RTR command response did not include a cloud_request_id")
	}
	return out.CloudRequestID, nil
}

// closeRTRSession is best-effort cleanup — a failure to close a session
// leaves it to expire on its own on CrowdStrike's side, so errors here are
// not surfaced to the caller (the response action itself already
// succeeded or failed by the time this runs).
func (c *Client) closeRTRSession(ctx context.Context, sessionID string) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return
	}
	reqURL := c.RTRSessionURL + "?" + url.Values{"session_id": {sessionID}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
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
