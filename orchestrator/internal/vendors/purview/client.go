// Package purview is a Microsoft Purview DLP evidence client, built against
// the Office 365 Management Activity API's DLP.All content type -- the
// confirmed, documented path for DLP policy-match evidence (see
// docs/superpowers/plans/2026-10-18-dlp-vendor-connectors.md for citations).
//
// Lab-gated boundary, same posture as internal/vendors/defender's own
// AnalyzedEmail work before a Defender-for-O365 tenant existed (see
// docs/emailgw-mastery-qa-log.md item 1b): this client's request-building
// and response-mapping are proven against httptest only. No real Purview-
// licensed tenant has exercised this code -- see docs/dlp-mastery-qa-log.md.
package purview

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/audspect/bas/internal/platform/msauth"
)

// Config holds the connection settings for one tenant's Purview/O365
// Management API access.
type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

// Client is an Office 365 Management Activity API client scoped to the
// DLP.All content type.
type Client struct {
	// BaseURL defaults to https://manage.office.com/api/v1.0/{tenantId} --
	// overridable so tests point it at an httptest.Server, exactly like
	// defender.Client.BaseURL.
	BaseURL    string
	tokens     *msauth.EntraTokenSource
	httpClient *http.Client
}

func New(cfg Config) *Client {
	return &Client{
		BaseURL: "https://manage.office.com/api/v1.0/" + cfg.TenantID,
		tokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://manage.office.com/.default"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// TokenURL exposes the token source's overridable URL for tests.
func (c *Client) TokenURL() *string { return &c.tokens.TokenURL }

// DLPEvent is one normalized DLP.All audit record. Fields are drawn from
// Microsoft's published Office 365 Management Activity API DLP schema
// (base audit fields plus PolicyDetails) -- see the plan doc for the
// exact citation. RawJSON keeps the original record, same precedent as
// defender.Alert.RawJSON, for a caller that needs a field this struct
// doesn't surface.
type DLPEvent struct {
	ID           string
	Workload     string
	Operation    string
	CreationTime time.Time
	UserID       string
	ObjectID     string
	// PolicyName/RuleName/Actions are flattened from the first matched
	// policy/rule in PolicyDetails -- a DLP.All record can carry more than
	// one matched policy, but this client surfaces only the first,
	// consistent with every other DLP vocabulary in this codebase treating
	// one step's outcome as one verdict, not a list. A caller needing every
	// matched policy should read RawJSON directly.
	PolicyName string
	RuleName   string
	Actions    []string
	RawJSON    json.RawMessage
}

type contentRef struct {
	ContentURI string `json:"contentUri"`
}

type managementAPIError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// alreadyEnabledSubstring is the documented O365 Management API response
// text for starting a subscription that's already active -- matched
// case-insensitively as a conservative, honest heuristic (not a confirmed
// error code: Microsoft's own docs don't guarantee the code is stable
// across tenants/API versions). See EnsureSubscriptionStarted.
const alreadyEnabledSubstring = "already enabled"

// EnsureSubscriptionStarted idempotently starts the DLP.All content
// subscription. Starting an already-active subscription is treated as
// success, not failure -- this call is meant to be safe to make before
// every QueryDLPEvents call, not a one-time setup step a caller must
// sequence carefully.
func (c *Client) EnsureSubscriptionStarted(ctx context.Context) error {
	data, status, err := c.do(ctx, http.MethodPost, "/activity/feed/subscriptions/start?contentType=DLP.All", nil)
	if err != nil {
		return err
	}
	if status < 400 {
		return nil
	}
	var apiErr managementAPIError
	if json.Unmarshal(data, &apiErr) == nil && strings.Contains(strings.ToLower(apiErr.Error.Message), alreadyEnabledSubstring) {
		return nil
	}
	return permissionAwareError("purview ensure subscription started", status, data)
}

// QueryDLPEvents lists every DLP.All content blob created in [start, end]
// and fetches+normalizes each one's records. Returns an empty slice, never
// an error, when no content is available in the window.
func (c *Client) QueryDLPEvents(ctx context.Context, start, end time.Time) ([]DLPEvent, error) {
	q := url.Values{
		"contentType": {"DLP.All"},
		"startTime":   {start.UTC().Format("2006-01-02T15:04:05")},
		"endTime":     {end.UTC().Format("2006-01-02T15:04:05")},
	}
	data, status, err := c.do(ctx, http.MethodGet, "/activity/feed/subscriptions/content?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, permissionAwareError("purview query DLP events: list content", status, data)
	}
	var refs []contentRef
	if err := json.Unmarshal(data, &refs); err != nil {
		return nil, fmt.Errorf("purview: parse content list: %w", err)
	}

	var events []DLPEvent
	for _, ref := range refs {
		if ref.ContentURI == "" {
			continue
		}
		blob, status, err := c.doAbsolute(ctx, http.MethodGet, ref.ContentURI)
		if err != nil {
			return nil, err
		}
		if status >= 400 {
			return nil, permissionAwareError("purview query DLP events: fetch content", status, blob)
		}
		var raws []json.RawMessage
		if err := json.Unmarshal(blob, &raws); err != nil {
			return nil, fmt.Errorf("purview: parse content blob: %w", err)
		}
		for _, raw := range raws {
			ev, ok := parseDLPEvent(raw)
			if ok {
				events = append(events, ev)
			}
		}
	}
	return events, nil
}

func parseDLPEvent(raw json.RawMessage) (DLPEvent, bool) {
	var rec struct {
		ID            string `json:"Id"`
		Workload      string `json:"Workload"`
		Operation     string `json:"Operation"`
		CreationTime  string `json:"CreationTime"`
		UserID        string `json:"UserId"`
		ObjectID      string `json:"ObjectId"`
		PolicyDetails []struct {
			PolicyName string `json:"PolicyName"`
			Rules      []struct {
				RuleName string `json:"RuleName"`
				Actions  []struct {
					Action string `json:"Action"`
				} `json:"Actions"`
			} `json:"Rules"`
		} `json:"PolicyDetails"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return DLPEvent{}, false
	}
	// O365 management-API audit timestamps have no timezone suffix and are
	// documented as UTC.
	created, err := time.Parse("2006-01-02T15:04:05", rec.CreationTime)
	if err != nil {
		return DLPEvent{}, false
	}
	ev := DLPEvent{
		ID: rec.ID, Workload: rec.Workload, Operation: rec.Operation,
		CreationTime: created, UserID: rec.UserID, ObjectID: rec.ObjectID,
		RawJSON: raw,
	}
	if len(rec.PolicyDetails) > 0 {
		pd := rec.PolicyDetails[0]
		ev.PolicyName = pd.PolicyName
		if len(pd.Rules) > 0 {
			rule := pd.Rules[0]
			ev.RuleName = rule.RuleName
			for _, a := range rule.Actions {
				ev.Actions = append(ev.Actions, a.Action)
			}
		}
	}
	return ev, true
}

// TestConnection is a smoke test: lists content with no expectation of any
// results, succeeding as long as the API call itself succeeds.
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.QueryDLPEvents(ctx, time.Now().Add(-time.Hour), time.Now())
	return err
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) ([]byte, int, error) {
	return c.doAbsolute(ctx, method, c.BaseURL+path)
}

func (c *Client) doAbsolute(ctx context.Context, method, fullURL string) ([]byte, int, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("purview: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return data, resp.StatusCode, nil
}

// permissionAwareError names the specific application permission a 401/403
// most likely means is missing, mirroring defender.Client.SendMail's own
// "is X permission granted with admin consent" precedent.
func permissionAwareError(op string, status int, body []byte) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return fmt.Errorf("%s: permission denied (HTTP %d, is ActivityFeed.Read and ActivityFeed.ReadDlp application permission granted with tenant admin consent, and Unified Audit Logging enabled?): %s", op, status, body)
	}
	return fmt.Errorf("%s: HTTP %d: %s", op, status, body)
}
