package sentinelone

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Threat is one SentinelOne-detected threat record. Same schema-
// confidence caveat as Agent (see package doc comment): ID, AgentID,
// ComputerName, and CreatedAt are kept because they're needed for
// device/window correlation; IncidentStatus (unresolved/in_progress/
// resolved) and MitigationStatus (not_mitigated/mitigated/
// marked_as_benign) are corroborated by the archived PS-SentinelOne
// PowerShell module's own parameter validation sets; ClassificationName
// is corroborated more loosely (a Netskope plugin sample shows a
// similarly-named field). No source checked confirms a MITRE ATT&CK
// technique-ID field on this resource the way Defender's Alert exposes
// mitreTechniques -- internal/avsentinelone's bridge correlates by
// device+window+classification only, never by technique, because of
// this gap.
type Threat struct {
	ID                 string
	AgentID            string
	ComputerName       string
	IncidentStatus     string
	MitigationStatus   string
	ClassificationName string
	CreatedAt          time.Time
	RawJSON            json.RawMessage
}

// maxListThreatsPages bounds pagination, same precedent as maxListPages.
const maxListThreatsPages = 1000

// QueryThreats returns every threat whose createdAt falls within
// [start, end]. No SentinelOne server-side date-range filter parameter
// name is confirmed against any authoritative source -- this client
// best-effort sends createdAt__gte/createdAt__lte (the double-
// underscore filter convention corroborated by Stitchflow's own
// mention of an "updatedAt__gt" filter on a different endpoint), but
// always re-applies the [start, end] bound client-side on the parsed
// CreatedAt field regardless of whether the server honored it -- this
// is the only way to be correct independent of whatever the real
// filter parameter name turns out to be.
func (c *Client) QueryThreats(ctx context.Context, start, end time.Time) ([]Threat, error) {
	var out []Threat
	cursor := ""
	for range maxListThreatsPages {
		q := url.Values{
			"limit":          {"1000"},
			"createdAt__gte": {start.UTC().Format(time.RFC3339)},
			"createdAt__lte": {end.UTC().Format(time.RFC3339)},
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		reqURL := c.BaseURL + "/web/api/v2.1/threats?" + q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", c.authHeader())
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("sentinelone query threats: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, classifyAPIError(resp.StatusCode, data)
		}
		var parsed listResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, fmt.Errorf("sentinelone query threats: parse response: %w", err)
		}
		for _, raw := range parsed.Data {
			var gt struct {
				ID                 string `json:"id"`
				AgentID            string `json:"agentId"`
				ComputerName       string `json:"computerName"`
				IncidentStatus     string `json:"incidentStatus"`
				MitigationStatus   string `json:"mitigationStatus"`
				ClassificationName string `json:"classificationName"`
				CreatedAt          string `json:"createdAt"`
			}
			if err := json.Unmarshal(raw, &gt); err != nil {
				continue
			}
			createdAt, err := time.Parse(time.RFC3339, gt.CreatedAt)
			if err != nil {
				continue
			}
			if createdAt.Before(start) || createdAt.After(end) {
				continue
			}
			out = append(out, Threat{
				ID: gt.ID, AgentID: gt.AgentID, ComputerName: gt.ComputerName,
				IncidentStatus: gt.IncidentStatus, MitigationStatus: gt.MitigationStatus,
				ClassificationName: gt.ClassificationName, CreatedAt: createdAt, RawJSON: raw,
			})
		}
		if parsed.Pagination.NextCursor == "" {
			break
		}
		cursor = parsed.Pagination.NextCursor
	}
	return out, nil
}
