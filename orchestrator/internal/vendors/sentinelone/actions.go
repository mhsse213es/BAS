package sentinelone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Isolate fully network-isolates deviceID (a SentinelOne agent ID) via
// the real "disconnect" agent action, corroborated across multiple
// sources (Fortinet FortiSOAR's "Isolate Agent Network", Sumo Logic's
// "Disconnect from Network"). The request body shape
// ({"filter":{"ids":[...]}}) is corroborated by LimaCharlie's own
// description of SentinelOne agent/threat action endpoints generally
// expecting a filter object. SentinelOne's own action response is
// {"data":{"success":true}} with no distinct action ID the way
// Defender's machine actions return one -- Isolate/Release return
// deviceID itself as the audit-trail reference instead.
func (c *Client) Isolate(ctx context.Context, deviceID string) (string, error) {
	return c.agentAction(ctx, "disconnect", deviceID)
}

// Release lifts isolation on deviceID via the real "connect" agent
// action (the documented counterpart to Isolate's "disconnect").
func (c *Client) Release(ctx context.Context, deviceID string) (string, error) {
	return c.agentAction(ctx, "connect", deviceID)
}

func (c *Client) agentAction(ctx context.Context, verb, deviceID string) (string, error) {
	body, _ := json.Marshal(map[string]any{"filter": map[string]any{"ids": []string{deviceID}}})
	reqURL := c.BaseURL + "/web/api/v2.1/agents/actions/" + verb
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sentinelone agent action %s: %w", verb, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", classifyAPIError(resp.StatusCode, data)
	}
	return deviceID, nil
}

// QuarantineFile mitigates the SentinelOne threat identified by param
// using the real "quarantine" mitigation action. param is interpreted
// as a SentinelOne threat ID, not a file path or hash -- SentinelOne's
// real mitigation API (kill/quarantine/remediate/rollback-remediation,
// corroborated by ThreatQ's and Cybervigilance's SentinelOne
// integration docs) operates on an already-identified threat by its
// own ID, with no confirmed endpoint that mitigates an arbitrary file
// by path/hash the way Defender's StopAndQuarantineFile does. This is
// an intentional, documented deviation of the generic VendorClient
// interface's "param" meaning for this vendor -- same discipline as
// crowdstrike.Client.QuarantineFile's own doc comment explaining why
// "rm" approximates quarantine there. deviceID is accepted (to satisfy
// the shared VendorClient interface) but is not part of the outbound
// request: SentinelOne threat IDs are unique across the tenant, so the
// mitigate call does not need a device scope.
func (c *Client) QuarantineFile(ctx context.Context, deviceID, threatID string) (string, error) {
	return c.mitigateThreat(ctx, "quarantine", threatID)
}

// KillProcess is not supported for SentinelOne via its real REST API as
// currently understood: SentinelOne's mitigation actions operate on an
// already-identified threat by its own threat ID (see QuarantineFile),
// not on an arbitrary live OS process ID. No source checked (2026-10-16)
// confirms any SentinelOne endpoint that maps a raw pid to a specific
// threat ID, and approximating that mapping incorrectly would risk
// mitigating the wrong threat on a real customer endpoint -- a
// destructive action, unlike a read-only evidence query. This returns
// an explicit, clearly-worded error rather than guessing.
func (c *Client) KillProcess(ctx context.Context, deviceID string, pid int) (string, error) {
	return "", fmt.Errorf("sentinelone: KillProcess by raw process ID is not supported -- SentinelOne's real mitigation API operates on an already-identified threat ID (see QuarantineFile), not an arbitrary live process ID, and no confirmed endpoint maps one to the other")
}

func (c *Client) mitigateThreat(ctx context.Context, action, threatID string) (string, error) {
	body, _ := json.Marshal(map[string]any{"filter": map[string]any{"ids": []string{threatID}}})
	reqURL := c.BaseURL + "/web/api/v2.1/threats/mitigate/" + action
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sentinelone mitigate threat %s: %w", action, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", classifyAPIError(resp.StatusCode, data)
	}
	return threatID, nil
}
