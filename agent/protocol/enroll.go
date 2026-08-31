package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// EnrollRequest is sent by the agent on first contact with the server.
type EnrollRequest struct {
	AgentID      string `json:"agentId"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ipAddress"`
	OSVersion    string `json:"osVersion"`
	Username     string `json:"username"`
	EnvLabel     string `json:"envLabel"`
	BinaryHash   string `json:"binaryHash,omitempty"`
	AgentVersion string `json:"agentVersion,omitempty"`

	PostureCatalog map[string][]PostureCheckMeta `json:"postureCatalog,omitempty"`
}

// PostureCheckMeta is one selectable posture check (no result — catalog only).
type PostureCheckMeta struct {
	ID          string `json:"id"`
	Phase       string `json:"phase"`
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
}

// EnrollResponse is returned by POST /api/agents/enroll.
type EnrollResponse struct {
	AgentID string     `json:"agentId"`
	State   string     `json:"state"`
	Policy  PolicyConf `json:"policy"`
	Trusted bool       `json:"trusted"`
}

// Enroll performs the pre-operation handshake against POST /api/agents/enroll.
// Shared by the real agent and loadgen -- this is the single network-calling
// implementation of enrollment; do not reimplement this call elsewhere.
func Enroll(ctx context.Context, client *http.Client, serverURL, agentSecret string, req EnrollRequest) (EnrollResponse, error) {
	var resp EnrollResponse
	data, err := json.Marshal(req)
	if err != nil {
		return resp, fmt.Errorf("marshal enroll request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/agents/enroll", bytes.NewReader(data))
	if err != nil {
		return resp, fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if agentSecret != "" {
		httpReq.Header.Set("X-Agent-Token", agentSecret)
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return resp, fmt.Errorf("POST /api/agents/enroll: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		return resp, fmt.Errorf("server %d on /api/agents/enroll", httpResp.StatusCode)
	}
	_ = json.NewDecoder(httpResp.Body).Decode(&resp) // non-fatal: old servers may return 200 with no body
	return resp, nil
}
