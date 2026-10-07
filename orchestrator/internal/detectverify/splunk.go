package detectverify

import (
	"bufio"
	"bytes"
	"context"
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
// TLS verification is on by default; on-prem Splunk management ports
// commonly present self-signed certs, so operators opt out per-connector
// via Config.InsecureTLS rather than the connector deciding for them.
type splunkConnector struct {
	exportURL  string // overridable in tests; defaults to <baseURL>/services/search/jobs/export
	uiBase     string // overridable in tests; defaults to baseURL
	token      string
	httpClient *http.Client
}

func newSplunkConnector(cfg Config) *splunkConnector {
	base := strings.TrimRight(cfg.BaseURL, "/")
	return &splunkConnector{
		exportURL:  base + "/services/search/jobs/export",
		uiBase:     base,
		token:      cfg.APIToken,
		httpClient: httpClientFor(cfg, 30*time.Second),
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

// parseMitreAttack accepts every shape Splunk's mitre_attack_enrichment
// lookup has been documented to produce for annotations.mitre_attack: a
// flat list or single string of technique IDs (the original assumption
// here), or -- per Splunk's own docs, which describe sub-fields named
// annotations.mitre_attack.mitre_technique_id/mitre_tactic/etc. -- a single
// enrichment object or array of them, each carrying its technique id(s)
// under mitre_technique_id (itself a string or an array). The exact export
// shape wasn't confirmed against a live instance, so every form is tried
// rather than guessing one.
func parseMitreAttack(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil && len(list) > 0 {
		return list
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil && single != "" {
		return []string{single}
	}
	var objs []map[string]any
	if err := json.Unmarshal(raw, &objs); err == nil && len(objs) > 0 {
		return mitreIDsFromEnrichmentObjects(objs)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err == nil && len(obj) > 0 {
		return mitreIDsFromEnrichmentObjects([]map[string]any{obj})
	}
	return nil
}

func mitreIDsFromEnrichmentObjects(objs []map[string]any) []string {
	var out []string
	for _, o := range objs {
		switch v := o["mitre_technique_id"].(type) {
		case string:
			if v != "" {
				out = append(out, v)
			}
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok && s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
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
