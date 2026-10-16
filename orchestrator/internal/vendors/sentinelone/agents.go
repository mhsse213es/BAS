package sentinelone

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

// Agent is one SentinelOne-managed endpoint record. Kept deliberately
// minimal: ID and ComputerName are the only fields corroborated with
// enough independent third-party agreement to ship as typed fields
// (see the package doc comment). Anything else a caller needs should
// come from RawJSON until it can be verified against a real tenant --
// unlike internal/vendors/defender's Machine type, there is no
// authoritative schema to expand this against yet.
type Agent struct {
	ID           string
	ComputerName string
	RawJSON      json.RawMessage
}

// listResponse is SentinelOne's documented-by-example list-endpoint
// envelope (data + pagination.nextCursor/totalItems), corroborated
// against Stitchflow's SentinelOne API guide's own worked example for
// a different endpoint (List Users) -- treated here as a platform-wide
// convention, not confirmed per-endpoint.
type listResponse struct {
	Data       []json.RawMessage `json:"data"`
	Pagination struct {
		NextCursor string `json:"nextCursor"`
		TotalItems int    `json:"totalItems"`
	} `json:"pagination"`
}

// maxListPages bounds pagination so a misbehaving or malicious cursor
// chain can't loop forever -- same bounded-policy precedent as
// internal/vendors/defender's maxListMachinesPages.
const maxListPages = 1000

// ListAgents returns the tenant's device inventory, following the
// cursor-based pagination convention (limit + cursor query params,
// pagination.nextCursor in the response) corroborated across multiple
// sources, until nextCursor is empty or maxListPages is reached. A
// response this client cannot classify as success is returned as a
// *ClassifiedError (see errors.go).
func (c *Client) ListAgents(ctx context.Context) ([]Agent, error) {
	var out []Agent
	cursor := ""
	for range maxListPages {
		q := url.Values{"limit": {"1000"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		reqURL := c.BaseURL + "/web/api/v2.1/agents?" + q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", c.authHeader())
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("sentinelone list agents: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			return nil, classifyAPIError(resp.StatusCode, data)
		}
		var parsed listResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, fmt.Errorf("sentinelone list agents: parse response: %w", err)
		}
		for _, raw := range parsed.Data {
			var ga struct {
				ID           string `json:"id"`
				ComputerName string `json:"computerName"`
			}
			if err := json.Unmarshal(raw, &ga); err != nil {
				continue
			}
			out = append(out, Agent{ID: ga.ID, ComputerName: ga.ComputerName, RawJSON: raw})
		}
		if parsed.Pagination.NextCursor == "" {
			break
		}
		cursor = parsed.Pagination.NextCursor
	}
	return out, nil
}

// ResolveDevice returns hostname's SentinelOne agent ID, caching the
// result for deviceCacheTTL. No SentinelOne hostname filter query
// parameter is confirmed against any source checked, so this matches
// client-side (case-insensitively) against ListAgents' own output
// rather than asserting an unconfirmed server-side filter -- correct
// regardless of what the real filter parameter name turns out to be,
// at the cost of fetching the full inventory on a cache miss.
func (c *Client) ResolveDevice(ctx context.Context, hostname string) (string, error) {
	c.deviceCacheMu.Lock()
	if e, ok := c.deviceCache[hostname]; ok && time.Now().Before(e.expiresAt) {
		c.deviceCacheMu.Unlock()
		return e.deviceID, nil
	}
	c.deviceCacheMu.Unlock()

	agents, err := c.ListAgents(ctx)
	if err != nil {
		return "", err
	}
	for _, a := range agents {
		if strings.EqualFold(a.ComputerName, hostname) {
			c.deviceCacheMu.Lock()
			c.deviceCache[hostname] = deviceCacheEntry{deviceID: a.ID, expiresAt: time.Now().Add(deviceCacheTTL)}
			c.deviceCacheMu.Unlock()
			return a.ID, nil
		}
	}
	return "", fmt.Errorf("sentinelone: no agent found for hostname %q", hostname)
}
