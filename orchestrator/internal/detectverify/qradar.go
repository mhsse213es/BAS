package detectverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// qradarConnector queries IBM QRadar's Ariel Query Language API for events
// mentioning the run's host in the requested window. Ariel searches are
// asynchronous: submit an AQL query, poll until COMPLETED, then fetch
// results — unlike Sentinel/Splunk's single-call query APIs.
type qradarConnector struct {
	baseURL      string // overridable in tests; QRadar console base URL
	secToken     string
	httpClient   *http.Client
	pollInterval time.Duration // overridable in tests to avoid slow polling
	maxPolls     int           // hard cap so a stuck search can't loop forever
}

func newQRadarConnector(cfg Config) *qradarConnector {
	return &qradarConnector{
		baseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		secToken:     cfg.APIToken,
		httpClient:   httpClientFor(cfg, 30*time.Second),
		pollInterval: 2 * time.Second,
		maxPolls:     30,
	}
}

func (q *qradarConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	aql := buildQRadarAQL(req)
	searchID, err := q.submitSearch(ctx, aql)
	if err != nil {
		return VerifyResult{}, err
	}
	if err := q.pollUntilDone(ctx, searchID); err != nil {
		return VerifyResult{}, err
	}
	data, err := q.fetchResults(ctx, searchID)
	if err != nil {
		return VerifyResult{}, err
	}
	alerts, err := parseQRadarEvents(data, q.baseURL)
	if err != nil {
		return VerifyResult{}, err
	}
	return matchAlerts(req, alerts), nil
}

func (q *qradarConnector) TestConnection(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q.baseURL+"/api/system/about", nil)
	if err != nil {
		return err
	}
	q.setHeaders(req)
	resp, err := q.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("qradar test connection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("qradar test connection: HTTP %d: %s", resp.StatusCode, data)
	}
	return nil
}

func buildQRadarAQL(req VerifyRequest) string {
	host := escapeAQL(req.HostName)
	ip := escapeAQL(req.HostIP)
	return fmt.Sprintf(
		`SELECT QIDNAME(qid) AS rulename, magnitude, starttime, mitre_technique FROM events `+
			`WHERE (sourceip='%s' OR destinationip='%s' OR sourceip='%s' OR destinationip='%s') `+
			`START %d STOP %d`,
		ip, ip, host, host, req.WindowStart.UnixMilli(), req.WindowEnd.UnixMilli())
}

func (q *qradarConnector) setHeaders(req *http.Request) {
	req.Header.Set("SEC", q.secToken)
	req.Header.Set("Version", "20.0")
	req.Header.Set("Accept", "application/json")
}

func (q *qradarConnector) submitSearch(ctx context.Context, aql string) (string, error) {
	form := url.Values{}
	form.Set("query_expression", aql)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, q.baseURL+"/api/ariel/searches", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	q.setHeaders(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := q.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("qradar submit search: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		if strings.Contains(string(data), "mitre_technique") && strings.Contains(string(data), "does not exist") {
			return "", fmt.Errorf("qradar submit search: HTTP %d: %s -- mitre_technique is not a built-in QRadar event field; "+
				"create a Custom Event Property named exactly \"mitre_technique\" (Admin > Custom Event Properties) mapping your "+
				"ATT&CK-tagged rules, or this connector's technique matching will never see a result", resp.StatusCode, data)
		}
		return "", fmt.Errorf("qradar submit search: HTTP %d: %s", resp.StatusCode, data)
	}
	var out struct {
		SearchID string `json:"search_id"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("qradar: parse submit response: %w", err)
	}
	return out.SearchID, nil
}

func (q *qradarConnector) pollUntilDone(ctx context.Context, searchID string) error {
	for i := 0; i < q.maxPolls; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, q.baseURL+"/api/ariel/searches/"+searchID, nil)
		if err != nil {
			return err
		}
		q.setHeaders(req)
		resp, err := q.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("qradar poll search: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("qradar poll search: HTTP %d: %s", resp.StatusCode, data)
		}
		var out struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return fmt.Errorf("qradar: parse poll response: %w", err)
		}
		switch out.Status {
		case "COMPLETED":
			return nil
		case "ERROR", "CANCELED":
			return fmt.Errorf("qradar search %s failed: status=%s", searchID, out.Status)
		}
		time.Sleep(q.pollInterval)
	}
	return fmt.Errorf("qradar search %s: timed out waiting for completion", searchID)
}

func (q *qradarConnector) fetchResults(ctx context.Context, searchID string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q.baseURL+"/api/ariel/searches/"+searchID+"/results", nil)
	if err != nil {
		return nil, err
	}
	q.setHeaders(req)
	resp, err := q.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qradar fetch results: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("qradar fetch results: HTTP %d: %s", resp.StatusCode, data)
	}
	return data, nil
}

func parseQRadarEvents(data []byte, baseURL string) ([]normalizedAlert, error) {
	var resp struct {
		Events []struct {
			StartTime      int64       `json:"starttime"`
			RuleName       string      `json:"rulename"`
			Magnitude      json.Number `json:"magnitude"`
			MitreTechnique string      `json:"mitre_technique"`
		} `json:"events"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("qradar: parse results: %w", err)
	}
	var out []normalizedAlert
	for _, e := range resp.Events {
		a := normalizedAlert{
			AlertID:          fmt.Sprintf("qradar-%d-%s", e.StartTime, e.RuleName),
			RuleName:         e.RuleName,
			Timestamp:        time.UnixMilli(e.StartTime).UTC(),
			Severity:         e.Magnitude.String(),
			InvestigationURL: baseURL + "/console/qradar/jsp/QRadar.jsp",
		}
		if e.MitreTechnique != "" {
			a.Techniques = []string{e.MitreTechnique}
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

func escapeAQL(s string) string {
	return strings.ReplaceAll(s, `'`, `''`)
}
