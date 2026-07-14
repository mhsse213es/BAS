package detectverify

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

type logAnalyticsResponse struct {
	Tables []struct {
		Columns []struct {
			Name string `json:"name"`
		} `json:"columns"`
		Rows [][]any `json:"rows"`
	} `json:"tables"`
}

func (s *sentinelConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	kql := fmt.Sprintf(
		`SecurityAlert | where TimeGenerated between (datetime(%s) .. datetime(%s)) | where ExtendedProperties has "%s" or ExtendedProperties has "%s" | project TimeGenerated, AlertName, AlertSeverity, SystemAlertId, Techniques`,
		req.WindowStart.UTC().Format(time.RFC3339), req.WindowEnd.UTC().Format(time.RFC3339),
		escapeKQLString(req.HostName), escapeKQLString(req.HostIP))
	data, err := s.query(ctx, kql)
	if err != nil {
		return VerifyResult{}, err
	}
	alerts, err := parseLogAnalyticsAlerts(data)
	if err != nil {
		return VerifyResult{}, err
	}
	return matchAlerts(req, alerts), nil
}

func (s *sentinelConnector) TestConnection(ctx context.Context) error {
	_, err := s.query(ctx, "SecurityAlert | take 1")
	return err
}

func (s *sentinelConnector) query(ctx context.Context, kql string) ([]byte, error) {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"query": kql})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.queryURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sentinel query: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("sentinel query: HTTP %d: %s", resp.StatusCode, data)
	}
	return data, nil
}

func parseLogAnalyticsAlerts(data []byte) ([]normalizedAlert, error) {
	var resp logAnalyticsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("sentinel: parse response: %w", err)
	}
	if len(resp.Tables) == 0 {
		return nil, nil
	}
	table := resp.Tables[0]
	col := map[string]int{}
	for i, c := range table.Columns {
		col[c.Name] = i
	}
	var out []normalizedAlert
	for _, row := range table.Rows {
		a := normalizedAlert{}
		if i, ok := col["TimeGenerated"]; ok && i < len(row) {
			if ts, ok := row[i].(string); ok {
				a.Timestamp, _ = time.Parse(time.RFC3339, ts)
			}
		}
		if i, ok := col["AlertName"]; ok && i < len(row) {
			a.RuleName, _ = row[i].(string)
		}
		if i, ok := col["AlertSeverity"]; ok && i < len(row) {
			a.Severity, _ = row[i].(string)
		}
		if i, ok := col["SystemAlertId"]; ok && i < len(row) {
			a.AlertID, _ = row[i].(string)
		}
		if i, ok := col["Techniques"]; ok && i < len(row) {
			if techs, ok := row[i].(string); ok && techs != "" {
				a.Techniques = strings.Split(techs, ",")
				for j := range a.Techniques {
					a.Techniques[j] = strings.TrimSpace(a.Techniques[j])
				}
			}
		}
		a.InvestigationURL = "https://portal.azure.com/#view/Microsoft_Azure_Security_Insights/AlertBlade/alertId/" + a.AlertID
		raw, _ := json.Marshal(map[string]any{
			"alertId": a.AlertID, "ruleName": a.RuleName, "timestamp": a.Timestamp,
			"severity": a.Severity, "techniques": a.Techniques,
		})
		a.RawJSON = raw
		out = append(out, a)
	}
	return out, nil
}

func escapeKQLString(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
