package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/audspect/bas/internal/platform/msauth"
)

// Config holds the connection settings for one Defender/Entra tenant.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

// Alert is one Defender XDR alert, normalized for detectverify's
// vendor-agnostic matching logic. DeviceDNSName is kept (rather than
// filtered here) so detectverify's host-matching stays in detectverify.
type Alert struct {
	ID            string
	RuleName      string
	Timestamp     time.Time
	Severity      string
	Techniques    []string
	DeviceDNSName string
	RawJSON       json.RawMessage
}

// Client is a Microsoft Graph security-alerts API client. BaseURL is
// exported so tests outside this package (internal/detectverify) can point
// it at an httptest.Server.
type Client struct {
	BaseURL    string // defaults to https://graph.microsoft.com/v1.0
	tokens     *msauth.EntraTokenSource
	httpClient *http.Client
}

func New(cfg Config) *Client {
	return &Client{
		BaseURL: "https://graph.microsoft.com/v1.0",
		tokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://graph.microsoft.com/.default"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// TokenURL exposes the underlying token source's overridable URL for tests.
func (c *Client) TokenURL() *string { return &c.tokens.TokenURL }

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

func (c *Client) QueryAlerts(ctx context.Context, start, end time.Time) ([]Alert, error) {
	raws, err := c.queryRaw(ctx, start, end)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, raw := range raws {
		var ga graphAlert
		if err := json.Unmarshal(raw, &ga); err != nil {
			continue
		}
		ts, _ := time.Parse(time.RFC3339, ga.CreatedDateTime)
		a := Alert{
			ID: ga.ID, RuleName: ga.Title, Timestamp: ts, Severity: ga.Severity,
			Techniques: ga.Techniques, RawJSON: raw,
		}
		if len(ga.Evidence) > 0 {
			a.DeviceDNSName = ga.Evidence[0].DeviceDNSName
		}
		out = append(out, a)
	}
	return out, nil
}

func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.queryRaw(ctx, time.Now().Add(-time.Hour), time.Now())
	return err
}

func (c *Client) queryRaw(ctx context.Context, start, end time.Time) ([]json.RawMessage, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf("createdDateTime ge %s and createdDateTime le %s",
		start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	reqURL := c.BaseURL + "/security/alerts_v2?" + url.Values{"$filter": {filter}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
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
