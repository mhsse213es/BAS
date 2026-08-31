package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Heartbeat struct {
	AgentID       string `json:"agentId"`
	Hostname      string `json:"hostname"`
	IPAddress     string `json:"ipAddress"`
	OSVersion     string `json:"osVersion"`
	Username      string `json:"username"`
	Status        string `json:"status"`
	EnvLabel      string `json:"envLabel"`
	BinaryHash    string `json:"binaryHash,omitempty"`
	AgentVersion  string `json:"agentVersion,omitempty"`
	SchemaVersion int    `json:"schemaVersion,omitempty"`

	ProtocolVersion int  `json:"protocolVersion,omitempty"`
	EmitsEvents     bool `json:"emitsEvents,omitempty"`

	SecurityProducts []string `json:"securityProducts,omitempty"`

	CurrentJobID string               `json:"currentJobId,omitempty"`
	JobProgress  HeartbeatJobProgress `json:"jobProgress,omitempty"`
}

// HeartbeatJobProgress carries per-job collection progress in a heartbeat.
type HeartbeatJobProgress struct {
	Stage            string `json:"stage"`
	TargetsCompleted int    `json:"targetsCompleted"`
	TargetsTotal     int    `json:"targetsTotal"`
	ProgressPercent  int    `json:"progressPercent"`
}

// HeartbeatResponse is returned by every POST /api/heartbeat.
type HeartbeatResponse struct {
	State  string     `json:"state"`
	Policy PolicyConf `json:"policy"`
}

// SendHeartbeat performs one heartbeat POST /api/heartbeat. Shared by the
// real agent and loadgen -- the single network-calling implementation.
func SendHeartbeat(ctx context.Context, client *http.Client, serverURL, agentSecret string, hb Heartbeat) (HeartbeatResponse, error) {
	var resp HeartbeatResponse
	data, err := json.Marshal(hb)
	if err != nil {
		return resp, fmt.Errorf("marshal heartbeat: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/heartbeat", bytes.NewReader(data))
	if err != nil {
		return resp, fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if agentSecret != "" {
		httpReq.Header.Set("X-Agent-Token", agentSecret)
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return resp, fmt.Errorf("POST /api/heartbeat: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		return resp, fmt.Errorf("server %d on /api/heartbeat", httpResp.StatusCode)
	}
	_ = json.NewDecoder(httpResp.Body).Decode(&resp)
	return resp, nil
}
