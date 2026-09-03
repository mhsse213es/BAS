package detectverify

import (
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

// trellixConnector queries the Trellix EDR Detections API
// (GET /edr/v2/detections) for detections matching the run's host within
// the requested window. Authenticates with a static Bearer token generated
// through Trellix's own EDR Credential Generator -- there is no confirmed
// OAuth2 client-credentials token-exchange endpoint in Trellix's public
// documentation, so (like splunk.go/qradar.go) this connector does not
// attempt to negotiate one; the operator supplies a ready token via
// Config.APIToken.
//
// The API has no server-side hostname filter, and "since" has no matching
// upper bound, so host and window-end scoping both happen client-side,
// after fetching. Detections are paginated (max 100/page per the API);
// Verify loops on offset until a page returns fewer than the page size.
type trellixConnector struct {
	baseURL    string // overridable in tests
	token      string
	httpClient *http.Client
	pageSize   int // overridable in tests to exercise pagination cheaply
}

func newTrellixConnector(cfg Config) *trellixConnector {
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.manage.trellix.com"
	}
	return &trellixConnector{
		baseURL:    strings.TrimRight(base, "/"),
		token:      cfg.APIToken,
		httpClient: httpClientFor(cfg, 30*time.Second),
		pageSize:   100,
	}
}

func (t *trellixConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	alerts, err := t.fetchDetections(ctx, req)
	if err != nil {
		return VerifyResult{}, err
	}
	return matchAlerts(req, alerts), nil
}

// TestConnection succeeds on any 2xx response, including an empty detection
// list -- it proves the token and base URL work, not that detections exist.
func (t *trellixConnector) TestConnection(ctx context.Context) error {
	_, err := t.queryPage(ctx, time.Now().Add(-time.Minute), 0)
	return err
}

// fetchDetections pages through /edr/v2/detections?since=<windowStart> until
// a page returns fewer than pageSize records, filtering each page to the
// requested host and window client-side (the API supports neither
// server-side). since alone should already guarantee the lower bound, but
// the WindowStart check is kept for robustness against a vendor API that
// doesn't enforce it exactly.
func (t *trellixConnector) fetchDetections(ctx context.Context, req VerifyRequest) ([]normalizedAlert, error) {
	var out []normalizedAlert
	offset := 0
	for {
		page, err := t.queryPage(ctx, req.WindowStart, offset)
		if err != nil {
			return nil, err
		}
		for _, d := range page {
			if d.HostName != req.HostName {
				continue
			}
			if d.DetectedAt.Before(req.WindowStart) || d.DetectedAt.After(req.WindowEnd) {
				continue
			}
			out = append(out, normalizeTrellixDetection(d))
		}
		if len(page) < t.pageSize {
			break
		}
		offset += t.pageSize
	}
	return out, nil
}

// trellixDetection is GET /edr/v2/detections's per-item response shape.
type trellixDetection struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	ProcessName string    `json:"processName"`
	HostName    string    `json:"hostName"`
	DetectedAt  time.Time `json:"detectedAt"`
	MitreAttack []string  `json:"mitreAttack"`
}

func (t *trellixConnector) queryPage(ctx context.Context, since time.Time, offset int) ([]trellixDetection, error) {
	u, err := url.Parse(t.baseURL + "/edr/v2/detections")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("since", since.UTC().Format(time.RFC3339))
	q.Set("limit", strconv.Itoa(t.pageSize))
	q.Set("offset", strconv.Itoa(offset))
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+t.token)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("trellix query detections: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("trellix query detections: authentication failed (HTTP 401): %s", data)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("trellix query detections: HTTP %d: %s", resp.StatusCode, data)
	}

	var out struct {
		Data []trellixDetection `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("trellix: parse detections response: %w", err)
	}
	return out.Data, nil
}

// normalizeTrellixDetection maps one Trellix detection to the shared shape.
// mitreAttack values are passed through unfiltered -- matchAlerts (via
// containsTechnique) decides what counts as a match, not this function.
// InvestigationURL is deliberately left empty: no per-detection Trellix
// console UI path is confirmed in public documentation, and this codebase's
// convention is to verify a URL before citing it, not construct a plausible
// guess.
func normalizeTrellixDetection(d trellixDetection) normalizedAlert {
	a := normalizedAlert{
		AlertID:    d.ID,
		RuleName:   d.ProcessName,
		Timestamp:  d.DetectedAt,
		Severity:   d.Severity,
		Techniques: d.MitreAttack,
	}
	raw, _ := json.Marshal(map[string]any{
		"alertId": a.AlertID, "ruleName": a.RuleName, "timestamp": a.Timestamp,
		"severity": a.Severity, "techniques": a.Techniques,
	})
	a.RawJSON = raw
	return a
}
