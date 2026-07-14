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

// defenderXDRConnector queries Microsoft Defender XDR's Graph security alerts
// API (alerts_v2) for alerts in the run's window whose evidence names the
// run's host. Authenticates via Entra client-credentials.
type defenderXDRConnector struct {
	baseURL    string // overridable in tests; defaults to Microsoft Graph
	tokens     *entraTokenSource
	httpClient *http.Client
}

func newDefenderXDRConnector(cfg Config) *defenderXDRConnector {
	return &defenderXDRConnector{
		baseURL: "https://graph.microsoft.com/v1.0",
		tokens: newEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://graph.microsoft.com/.default"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

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

func (d *defenderXDRConnector) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	raws, err := d.queryAlerts(ctx, req.WindowStart, req.WindowEnd)
	if err != nil {
		return VerifyResult{}, err
	}
	var alerts []normalizedAlert
	for _, raw := range raws {
		var ga graphAlert
		if err := json.Unmarshal(raw, &ga); err != nil {
			continue
		}
		if !alertMentionsHost(ga, req.HostName) {
			continue
		}
		ts, _ := time.Parse(time.RFC3339, ga.CreatedDateTime)
		alerts = append(alerts, normalizedAlert{
			AlertID:          ga.ID,
			RuleName:         ga.Title,
			Timestamp:        ts,
			Severity:         ga.Severity,
			Techniques:       ga.Techniques,
			InvestigationURL: "https://security.microsoft.com/alerts/" + ga.ID,
			RawJSON:          raw,
		})
	}
	return matchAlerts(req, alerts), nil
}

// alertMentionsHost reports whether ga's evidence names hostName. When
// hostName is empty (agent has no known hostname) every alert is accepted —
// better to over-match at medium confidence than silently verify nothing.
func alertMentionsHost(ga graphAlert, hostName string) bool {
	if hostName == "" {
		return true
	}
	for _, e := range ga.Evidence {
		if strings.EqualFold(e.DeviceDNSName, hostName) {
			return true
		}
	}
	return false
}

func (d *defenderXDRConnector) TestConnection(ctx context.Context) error {
	_, err := d.queryAlerts(ctx, time.Now().Add(-time.Hour), time.Now())
	return err
}

func (d *defenderXDRConnector) queryAlerts(ctx context.Context, start, end time.Time) ([]json.RawMessage, error) {
	token, err := d.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf("createdDateTime ge %s and createdDateTime le %s",
		start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	reqURL := d.baseURL + "/security/alerts_v2?" + url.Values{"$filter": {filter}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := d.httpClient.Do(req)
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
