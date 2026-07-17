package detectverify

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

// crowdstrikeConnector queries CrowdStrike Falcon's Alerts v2 API for alerts
// mentioning the run's host in the requested window. Unlike Sentinel/Splunk
// (rows returned in one call) or QRadar (poll a single search), Falcon's
// Alerts API is query-then-detail: list matching alert IDs, then fetch the
// full alert objects for those IDs.
type crowdstrikeConnector struct {
	queryURL   string // overridable in tests; defaults to <baseURL>/alerts/queries/alerts/v2
	detailURL  string // overridable in tests; defaults to <baseURL>/alerts/entities/alerts/v2
	tokens     *crowdstrikeTokenSource
	httpClient *http.Client
}

func newCrowdStrikeConnector(cfg Config) *crowdstrikeConnector {
	base := strings.TrimRight(cfg.BaseURL, "/")
	return &crowdstrikeConnector{
		queryURL:   base + "/alerts/queries/alerts/v2",
		detailURL:  base + "/alerts/entities/alerts/v2",
		tokens:     newCrowdStrikeTokenSource(cfg.BaseURL, cfg.ClientID, cfg.ClientSecret),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *crowdstrikeConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	ids, err := c.queryAlertIDs(ctx, buildFQLFilter(req))
	if err != nil {
		return VerifyResult{}, err
	}
	if len(ids) == 0 {
		return VerifyResult{Verdict: VerdictNotDetected}, nil
	}
	data, err := c.fetchAlertDetails(ctx, ids)
	if err != nil {
		return VerifyResult{}, err
	}
	alerts, err := parseCrowdStrikeAlerts(data)
	if err != nil {
		return VerifyResult{}, err
	}
	return matchAlerts(req, alerts), nil
}

func (c *crowdstrikeConnector) TestConnection(ctx context.Context) error {
	_, err := c.queryAlertIDs(ctx, "")
	return err
}

func buildFQLFilter(req VerifyRequest) string {
	host := escapeFQL(req.HostName)
	return fmt.Sprintf(
		`device.hostname:'%s'+created_timestamp:>'%s'+created_timestamp:<'%s'`,
		host, req.WindowStart.UTC().Format(time.RFC3339), req.WindowEnd.UTC().Format(time.RFC3339))
}

func (c *crowdstrikeConnector) queryAlertIDs(ctx context.Context, filter string) ([]string, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("limit", "100")
	if filter != "" {
		q.Set("filter", filter)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.queryURL+"?"+q.Encode(), nil)
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

func (c *crowdstrikeConnector) fetchAlertDetails(ctx context.Context, ids []string) ([]byte, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string][]string{"composite_ids": ids})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.detailURL, bytes.NewReader(body))
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

func parseCrowdStrikeAlerts(data []byte) ([]normalizedAlert, error) {
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
	var out []normalizedAlert
	for _, r := range resp.Resources {
		ts, _ := time.Parse(time.RFC3339, r.CreatedTimestamp)
		var techniques []string
		for _, b := range r.Behaviors {
			if b.TechniqueID != "" {
				techniques = append(techniques, b.TechniqueID)
			}
		}
		a := normalizedAlert{
			AlertID:          r.CompositeID,
			RuleName:         firstNonEmpty(r.Name, r.DisplayName),
			Timestamp:        ts,
			Severity:         strconv.Itoa(r.Severity),
			Techniques:       techniques,
			InvestigationURL: "",
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
