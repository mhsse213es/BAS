package detectverify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// elasticAlertsPath is the search path for Elastic Security detection alerts.
// Alerts live in `.alerts-security.alerts-<space-id>`; the wildcard covers
// every space.
const elasticAlertsPath = "/.alerts-security.alerts-*/_search"

// elasticSearchQuery makes every search strict: a partial result or an
// unreadable/missing index must be an error, never an empty (NotDetected) one.
const elasticSearchQuery = "allow_partial_search_results=false&allow_no_indices=false&expand_wildcards=open,hidden"

// elasticErrBodyMax caps how much of a response body is echoed into errors.
const elasticErrBodyMax = 4 << 10

// elasticMaxPages bounds the search_after loop so a runaway query fails
// loudly rather than looping forever or silently truncating.
const elasticMaxPages = 50

// elasticConnector searches Elastic Security detection alerts directly via
// the Elasticsearch search API. Exactly one auth mode is configured:
// API key (Config.APIToken, sent as "Authorization: ApiKey <value>") or
// basic auth (Config.ClientID = username, Config.ClientSecret = password).
//
// Minimum supported version: Elastic Stack 8.x (alerts-as-data indices
// `.alerts-security.alerts-<space>`; 7.x used the legacy `.siem-signals-*`
// indices and is not supported).
//
// Host and window scoping are done server-side in the query; technique
// matching is left to matchAlerts. InvestigationURL is left empty: a Kibana
// deep link would need a Kibana base URL, which is not stored.
type elasticConnector struct {
	baseURL    string
	apiKey     string
	username   string
	password   string
	httpClient *http.Client
	pageSize   int // overridable in tests
	maxPages   int // overridable in tests
	authErr    error
}

func newElasticConnector(cfg Config) *elasticConnector {
	return &elasticConnector{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:     strings.TrimSpace(cfg.APIToken),
		username:   strings.TrimSpace(cfg.ClientID),
		password:   strings.TrimSpace(cfg.ClientSecret),
		httpClient: httpClientFor(cfg, 30*time.Second),
		pageSize:   500,
		maxPages:   elasticMaxPages,
		authErr:    ValidateElasticAuth(cfg),
	}
}

// ValidateElasticAuth enforces that exactly one auth mode is configured.
// Also used by the API create/update validation.
func ValidateElasticAuth(cfg Config) error {
	tok, user, pw := strings.TrimSpace(cfg.APIToken), strings.TrimSpace(cfg.ClientID), strings.TrimSpace(cfg.ClientSecret)
	hasKey := tok != ""
	hasBasic := user != "" || pw != ""
	switch {
	case hasKey && hasBasic:
		return fmt.Errorf("elastic: configure either an API key or username/password, not both")
	case !hasKey && !hasBasic:
		return fmt.Errorf("elastic: no credentials configured: set an API key or username and password")
	case !hasKey && (user == "" || pw == ""):
		return fmt.Errorf("elastic: basic auth requires both username and password")
	}
	return nil
}

func (e *elasticConnector) preflight() error {
	if e.authErr != nil {
		return e.authErr
	}
	if e.baseURL == "" {
		return fmt.Errorf("elastic: base URL is not configured")
	}
	return nil
}

func (e *elasticConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	if err := e.preflight(); err != nil {
		return VerifyResult{}, err
	}
	if strings.TrimSpace(req.HostName) == "" && net.ParseIP(strings.TrimSpace(req.HostIP)) == nil {
		return VerifyResult{}, fmt.Errorf("elastic: no host identity to scope the query")
	}
	var alerts []normalizedAlert
	var searchAfter []any
	for page := 0; ; page++ {
		if page >= e.maxPages {
			return VerifyResult{}, fmt.Errorf("elastic: alert query exceeded %d pages (%d alerts per page); refusing to judge on a truncated result", e.maxPages, e.pageSize)
		}
		hits, err := e.search(ctx, e.buildQuery(req, searchAfter))
		if err != nil {
			return VerifyResult{}, err
		}
		for _, h := range hits {
			a, err := normalizeElasticHit(h)
			if err != nil {
				return VerifyResult{}, err
			}
			alerts = append(alerts, a)
		}
		if len(hits) < e.pageSize {
			break
		}
		last := hits[len(hits)-1]
		if len(last.Sort) == 0 {
			return VerifyResult{}, fmt.Errorf("elastic: full page returned without sort values; cannot paginate")
		}
		searchAfter = last.Sort
	}
	return matchAlerts(req, alerts), nil
}

// TestConnection runs a size:0 search on the alerts index, which proves the
// credentials hold read privilege on it.
func (e *elasticConnector) TestConnection(ctx context.Context) error {
	if err := e.preflight(); err != nil {
		return err
	}
	_, err := e.search(ctx, map[string]any{"size": 0, "query": map[string]any{"match_all": map[string]any{}}})
	return err
}

func (e *elasticConnector) buildQuery(req VerifyRequest, searchAfter []any) map[string]any {
	tsRange := func(field string) map[string]any {
		return map[string]any{"range": map[string]any{field: map[string]any{
			"gte":    req.WindowStart.UTC().Format(time.RFC3339Nano),
			"lte":    req.WindowEnd.UTC().Format(time.RFC3339Nano),
			"format": "strict_date_optional_time",
		}}}
	}
	var hostShould []any
	if host := strings.TrimSpace(req.HostName); host != "" {
		hostShould = append(hostShould,
			map[string]any{"term": map[string]any{"host.name": map[string]any{"value": host, "case_insensitive": true}}},
			map[string]any{"term": map[string]any{"host.hostname": map[string]any{"value": host, "case_insensitive": true}}},
			// ECS host.name is often the FQDN while agents report the short name.
			map[string]any{"prefix": map[string]any{"host.name": map[string]any{"value": host + ".", "case_insensitive": true}}},
		)
	}
	// An invalid value against an ip field is a 400, so only send valid IPs.
	if ip := strings.TrimSpace(req.HostIP); net.ParseIP(ip) != nil {
		hostShould = append(hostShould, map[string]any{"term": map[string]any{"host.ip": ip}})
	}
	q := map[string]any{
		"size": e.pageSize,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			// @timestamp is when the rule ran; original_time is when the source
			// event happened. Either falling in the window counts.
			map[string]any{"bool": map[string]any{
				"should":               []any{tsRange("@timestamp"), tsRange("kibana.alert.original_time")},
				"minimum_should_match": 1,
			}},
			map[string]any{"bool": map[string]any{"should": hostShould, "minimum_should_match": 1}},
		}}},
		"sort": []any{
			map[string]any{"@timestamp": "asc"},
			map[string]any{"kibana.alert.uuid": "asc"},
		},
		"_source": []string{
			"@timestamp", "kibana.alert.uuid", "kibana.alert.rule.name", "kibana.alert.severity",
			"kibana.alert.rule.threat", "kibana.alert.workflow_status", "kibana.alert.original_time",
			"threat", "host.name", "host.hostname",
		},
	}
	if len(searchAfter) > 0 {
		q["search_after"] = searchAfter
	}
	return q
}

type elasticHit struct {
	ID     string          `json:"_id"`
	Source json.RawMessage `json:"_source"`
	Sort   []any           `json:"sort"`
}

func (e *elasticConnector) search(ctx context.Context, body map[string]any) ([]elasticHit, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+elasticAlertsPath+"?"+elasticSearchQuery, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if e.apiKey != "" {
		httpReq.Header.Set("Authorization", "ApiKey "+e.apiKey)
	} else {
		httpReq.SetBasicAuth(e.username, e.password)
	}
	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("elastic search alerts: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	snippet := data
	if len(snippet) > elasticErrBodyMax {
		snippet = append(append([]byte{}, snippet[:elasticErrBodyMax]...), "...(truncated)"...)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("elastic search alerts: authentication failed (HTTP 401): %s", snippet)
	case resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("elastic search alerts: credentials lack read privilege on .alerts-security.alerts-* (HTTP 403): %s", snippet)
	case resp.StatusCode >= 400:
		return nil, fmt.Errorf("elastic search alerts: HTTP %d: %s", resp.StatusCode, snippet)
	}
	var out struct {
		TimedOut bool `json:"timed_out"`
		Shards   struct {
			Total  int `json:"total"`
			Failed int `json:"failed"`
		} `json:"_shards"`
		Hits struct {
			Hits []elasticHit `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("elastic: parse search response: %w", err)
	}
	// A 200 can still be a partial or empty view; never let that read as
	// "no alerts".
	switch {
	case out.TimedOut:
		return nil, fmt.Errorf("elastic search alerts: search timed out; results are incomplete")
	case out.Shards.Failed > 0:
		return nil, fmt.Errorf("elastic search alerts: %d of %d shards failed; results are incomplete", out.Shards.Failed, out.Shards.Total)
	case out.Shards.Total == 0:
		return nil, fmt.Errorf("elastic: no Elastic Security alerts index visible to these credentials (check read privilege on .alerts-security.alerts-* and the Kibana space)")
	}
	return out.Hits.Hits, nil
}

// normalizeElasticHit maps one alert document to the shared shape. Techniques
// are the union of technique ids and subtechnique ids from the rule's threat
// mapping; matchAlerts decides what counts as a match.
func normalizeElasticHit(h elasticHit) (normalizedAlert, error) {
	var src map[string]any
	if err := json.Unmarshal(h.Source, &src); err != nil {
		return normalizedAlert{}, fmt.Errorf("elastic: malformed alert document %q: %w", h.ID, err)
	}

	a := normalizedAlert{
		AlertID:  h.ID,
		RuleName: elasticString(src, "kibana.alert.rule.name"),
		Severity: elasticString(src, "kibana.alert.severity"),
	}
	if u := elasticString(src, "kibana.alert.uuid"); u != "" {
		a.AlertID = u
	}
	for _, f := range []string{"@timestamp", "kibana.alert.original_time"} {
		if ts := elasticString(src, f); ts != "" {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				a.Timestamp = t
				break
			}
		}
	}
	seen := map[string]bool{}
	add := func(ids []string) {
		for _, id := range ids {
			if id != "" && !seen[id] {
				seen[id] = true
				a.Techniques = append(a.Techniques, id)
			}
		}
	}
	// Alert documents may carry flattened dotted keys or nested objects; the
	// rule threat mapping is an array of {technique:[{id, subtechnique:[{id}]}]}.
	add(elasticStrings(src, "kibana.alert.rule.threat.technique.id"))
	add(elasticStrings(src, "kibana.alert.rule.threat.technique.subtechnique.id"))
	// ECS threat.* (Elastic Defend alerts carry their ATT&CK ids here).
	add(elasticStrings(src, "threat.technique.id"))
	add(elasticStrings(src, "threat.technique.subtechnique.id"))
	for _, th := range elasticObjects(elasticLookup(src, "kibana.alert.rule.threat")) {
		for _, tech := range elasticObjects(th["technique"]) {
			add(elasticStrings(tech, "id"))
			for _, sub := range elasticObjects(tech["subtechnique"]) {
				add(elasticStrings(sub, "id"))
			}
		}
	}
	raw, _ := json.Marshal(map[string]any{
		"alertId": a.AlertID, "ruleName": a.RuleName, "timestamp": a.Timestamp,
		"severity": a.Severity, "techniques": a.Techniques,
		"workflowStatus": elasticString(src, "kibana.alert.workflow_status"),
	})
	a.RawJSON = raw
	return a, nil
}

// elasticLookup resolves a dotted path against either a flattened key or a
// nested object.
func elasticLookup(m map[string]any, path string) any {
	if v, ok := m[path]; ok {
		return v
	}
	parts := strings.Split(path, ".")
	for i := 1; i < len(parts); i++ {
		if sub, ok := m[strings.Join(parts[:i], ".")].(map[string]any); ok {
			return elasticLookup(sub, strings.Join(parts[i:], "."))
		}
	}
	return nil
}

func elasticStrings(m map[string]any, path string) []string {
	switch v := elasticLookup(m, path).(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func elasticString(m map[string]any, path string) string {
	if s := elasticStrings(m, path); len(s) > 0 {
		return s[0]
	}
	return ""
}

func elasticObjects(v any) []map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return []map[string]any{t}
	case []any:
		var out []map[string]any
		for _, x := range t {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}
