package siem

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// QRadarClient queries IBM QRadar via the Ariel REST API.
// Auth: SEC token (preferred) or HTTP Basic (username:password).
type QRadarClient struct {
	baseURL    string
	token      string
	username   string
	password   string
	httpClient *http.Client
}

func newQRadarClient(cfg Config) *QRadarClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify},
	}
	return &QRadarClient{
		baseURL:    strings.TrimRight(cfg.ConsoleURL, "/"),
		token:      cfg.Token,
		username:   cfg.Username,
		password:   cfg.Password,
		httpClient: &http.Client{Timeout: 60 * time.Second, Transport: tr},
	}
}

// Ping verifies connectivity by calling the /api/system/about endpoint.
func (c *QRadarClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/console/restapi/api/system/about", nil)
	if err != nil {
		return err
	}
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", "17.0")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("qradar ping: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("qradar: authentication failed — check SEC token or credentials")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("qradar: HTTP %d from %s", resp.StatusCode, c.baseURL)
	}
	return nil
}

// QueryAlerts searches for events on agentIP between windowStart and windowEnd.
// Returns up to maxAlerts normalised SIEMAlert records.
// Uses AQL: events from sourceip or destinationip matching the agent's IP in the time window.
func (c *QRadarClient) QueryAlerts(ctx context.Context, agentIP string, windowStart, windowEnd time.Time, maxAlerts int) ([]SIEMAlert, error) {
	startMs := windowStart.UnixMilli()
	endMs := windowEnd.UnixMilli()

	aql := fmt.Sprintf(
		`SELECT starttime, CATEGORYNAME(highLevelCategory) AS category,
		        sourceip, destinationip, username, QIDNAME(qid) AS event_name,
		        RULENAME(creeventlist) AS rule_name, severity,
		        "Process Name (custom)" AS process_name,
		        "Command (custom)" AS command
		   FROM events
		  WHERE (sourceip = '%s' OR destinationip = '%s')
		    AND starttime >= %d AND starttime <= %d
		  ORDER BY starttime ASC
		  LIMIT %d`,
		agentIP, agentIP, startMs, endMs, maxAlerts,
	)

	searchID, err := c.startSearch(ctx, aql)
	if err != nil {
		return nil, err
	}
	if err := c.waitForSearch(ctx, searchID, 45*time.Second); err != nil {
		return nil, err
	}
	return c.fetchResults(ctx, searchID)
}

func (c *QRadarClient) startSearch(ctx context.Context, aql string) (string, error) {
	body := url.Values{"query_expression": []string{aql}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/console/restapi/api/ariel/searches",
		strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", "17.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("qradar start search: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("qradar search submit HTTP %d: %s", resp.StatusCode, string(raw))
	}
	var result struct {
		SearchID string `json:"search_id"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.SearchID == "" {
		return "", fmt.Errorf("qradar: could not parse search_id from response: %s", string(raw))
	}
	return result.SearchID, nil
}

func (c *QRadarClient) waitForSearch(ctx context.Context, searchID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx,
			http.MethodGet,
			c.baseURL+"/console/restapi/api/ariel/searches/"+searchID, nil)
		c.setAuth(req)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Version", "17.0")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		var status struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&status)
		resp.Body.Close()
		if status.Status == "COMPLETED" {
			return nil
		}
		if status.Status == "ERROR" || status.Status == "CANCELLED" {
			return fmt.Errorf("qradar search %s ended with status %s", searchID, status.Status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("qradar search %s timed out after %v", searchID, timeout)
}

func (c *QRadarClient) fetchResults(ctx context.Context, searchID string) ([]SIEMAlert, error) {
	req, _ := http.NewRequestWithContext(ctx,
		http.MethodGet,
		c.baseURL+"/console/restapi/api/ariel/searches/"+searchID+"/results", nil)
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Version", "17.0")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qradar fetch results: %w", err)
	}
	defer resp.Body.Close()

	// QRadar returns {"events": [...]} for event searches.
	var raw struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("qradar decode results: %w", err)
	}

	alerts := make([]SIEMAlert, 0, len(raw.Events))
	for _, ev := range raw.Events {
		a := SIEMAlert{
			EventID:     strField(ev, "eventid"),
			RuleName:    strField(ev, "rule_name"),
			Category:    strField(ev, "category"),
			Severity:    strField(ev, "severity"),
			SourceIP:    strField(ev, "sourceip"),
			DestIP:      strField(ev, "destinationip"),
			Username:    strField(ev, "username"),
			ProcessName: strField(ev, "process_name"),
			CommandLine: strField(ev, "command"),
			Message:     strField(ev, "event_name"),
			RawFields:   ev,
		}
		// QRadar timestamps are epoch-millisecond integers in the "starttime" field.
		if ts, ok := ev["starttime"]; ok {
			switch v := ts.(type) {
			case float64:
				a.Timestamp = time.UnixMilli(int64(v)).UTC()
			case json.Number:
				if ms, err := v.Int64(); err == nil {
					a.Timestamp = time.UnixMilli(ms).UTC()
				}
			}
		}
		alerts = append(alerts, a)
	}
	return alerts, nil
}

func (c *QRadarClient) setAuth(req *http.Request) {
	if c.token != "" {
		req.Header.Set("SEC", c.token)
	} else if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}
}

func strField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
