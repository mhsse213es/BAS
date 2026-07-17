package detectverify

import (
	"bufio"
	"bytes"
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

// splunkConnector queries a Splunk Enterprise Security instance's `notable`
// index (the standard ES alert index) for rows mentioning the run's host in
// the requested window, via the REST search-export endpoint. Authenticates
// with a bearer token (Splunk HEC/auth token or session key).
//
// TLS verification is disabled by default, matching the MISP connector —
// on-prem Splunk management ports commonly present self-signed certs.
type splunkConnector struct {
	exportURL  string // overridable in tests; defaults to <baseURL>/services/search/jobs/export
	uiBase     string // overridable in tests; defaults to baseURL
	token      string
	httpClient *http.Client
}

func newSplunkConnector(cfg Config) *splunkConnector {
	base := strings.TrimRight(cfg.BaseURL, "/")
	return &splunkConnector{
		exportURL: base + "/services/search/jobs/export",
		uiBase:    base,
		token:     cfg.APIToken,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

func (s *splunkConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	spl := buildSplunkSearch(req)
	data, err := s.search(ctx, spl, req.WindowStart, req.WindowEnd)
	if err != nil {
		return VerifyResult{}, err
	}
	alerts, err := parseSplunkResults(data, s.uiBase)
	if err != nil {
		return VerifyResult{}, err
	}
	return matchAlerts(req, alerts), nil
}

func (s *splunkConnector) TestConnection(ctx context.Context) error {
	_, err := s.search(ctx, "| makeresults", time.Now().Add(-time.Minute), time.Now())
	return err
}

func buildSplunkSearch(req VerifyRequest) string {
	host := escapeSplunk(req.HostName)
	ip := escapeSplunk(req.HostIP)
	return fmt.Sprintf(
		`search index=notable (dest="%s" OR src="%s" OR dest_ip="%s" OR src_ip="%s")`,
		host, host, ip, ip)
}

func (s *splunkConnector) search(ctx context.Context, spl string, earliest, latest time.Time) ([]byte, error) {
	form := url.Values{}
	form.Set("search", spl)
	form.Set("earliest_time", earliest.UTC().Format(time.RFC3339))
	form.Set("latest_time", latest.UTC().Format(time.RFC3339))
	form.Set("output_mode", "json")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.exportURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("splunk search: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("splunk search: HTTP %d: %s", resp.StatusCode, data)
	}
	return data, nil
}

// splunkExportLine is one line of the export endpoint's newline-delimited
// JSON stream. Non-result lines (progress/status markers) omit "result" and
// are skipped.
type splunkExportLine struct {
	Result *splunkResultFields `json:"result"`
}

// splunkResultFields is the ES `notable` field mapping — see the design doc
// for why these specific field names.
type splunkResultFields struct {
	Time        string          `json:"_time"`
	RuleTitle   string          `json:"rule_title"`
	SearchName  string          `json:"search_name"`
	Source      string          `json:"source"`
	Severity    string          `json:"severity"`
	EventID     string          `json:"event_id"`
	CD          string          `json:"_cd"`
	MitreAttack json.RawMessage `json:"annotations.mitre_attack"`
}

func parseSplunkResults(data []byte, uiBase string) ([]normalizedAlert, error) {
	var out []normalizedAlert
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var l splunkExportLine
		if err := json.Unmarshal(line, &l); err != nil {
			return nil, fmt.Errorf("splunk: parse result line: %w", err)
		}
		if l.Result == nil {
			continue
		}
		r := l.Result
		a := normalizedAlert{
			AlertID:          firstNonEmpty(r.EventID, r.CD),
			RuleName:         firstNonEmpty(r.RuleTitle, r.SearchName, r.Source),
			Timestamp:        parseSplunkTime(r.Time),
			Severity:         r.Severity,
			Techniques:       parseMitreAttack(r.MitreAttack),
			InvestigationURL: uiBase + "/en-US/app/SplunkEnterpriseSecuritySuite/incident_review",
		}
		raw, _ := json.Marshal(map[string]any{
			"alertId": a.AlertID, "ruleName": a.RuleName, "timestamp": a.Timestamp,
			"severity": a.Severity, "techniques": a.Techniques,
		})
		a.RawJSON = raw
		out = append(out, a)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("splunk: read response: %w", err)
	}
	return out, nil
}

func parseMitreAttack(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil && single != "" {
		return []string{single}
	}
	return nil
}

func parseSplunkTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func escapeSplunk(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}
