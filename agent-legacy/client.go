package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Client is the legacy agent's HTTP client for enrollment/heartbeat --
// mirrors agent/agent.go's postJSONDecode pattern (X-Agent-Token header
// carries the shared secret; the orchestrator's existing auth middleware
// for these two endpoints is untouched, so this must match it exactly).
type Client struct {
	cfg        Config
	httpClient *http.Client
}

func NewClient(cfg Config) *Client {
	return &Client{cfg: cfg, httpClient: &http.Client{}}
}

func (c *Client) postJSON(path string, body interface{}, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.cfg.ServerURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.AgentSecret != "" {
		req.Header.Set("X-Agent-Token", c.cfg.AgentSecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server %d on %s", resp.StatusCode, path)
	}
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Enroll(id Identity) (EnrollResponse, error) {
	req := EnrollRequest{
		AgentID:      id.AgentID,
		Hostname:     id.Hostname,
		IPAddress:    id.IPAddress,
		OSVersion:    id.OSVersion,
		Username:     id.Username,
		EnvLabel:     c.cfg.EnvLabel,
		AgentVersion: agentVersion,
	}
	var resp EnrollResponse
	err := c.postJSON("/api/agents/enroll", req, &resp)
	return resp, err
}

func (c *Client) SendHeartbeat(id Identity, status string) (HeartbeatResponse, error) {
	hb := Heartbeat{
		AgentID:      id.AgentID,
		Hostname:     id.Hostname,
		IPAddress:    id.IPAddress,
		OSVersion:    id.OSVersion,
		Username:     id.Username,
		Status:       status,
		EnvLabel:     c.cfg.EnvLabel,
		AgentVersion: agentVersion,
	}
	var resp HeartbeatResponse
	err := c.postJSON("/api/heartbeat", hb, &resp)
	return resp, err
}

const agentVersion = "1.0.0-legacy"
