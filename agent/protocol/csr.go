package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// CSRRequest is sent by the agent to POST /api/agents/enroll-csr — the
// bootstrap CSR-submission endpoint served on the orchestrator's
// TLS-server-only :9444 listener. Mirrors EnrollRequest's role in
// enroll.go, but for the CSR-based mTLS bootstrap flow (spec Section 2)
// rather than the legacy shared-secret enrollment this coexists with
// during migration.
type CSRRequest struct {
	AgentID string `json:"agentId"`
	CSRPEM  string `json:"csrPem"`
}

// CSRResponse is returned by POST /api/agents/enroll-csr. CertPEM is the
// signed agent client certificate; CAPEM is the deployment CA root
// (returned again here as a convenience/consistency check even though the
// agent's installer already has it, per the spec's "never return a private
// key" invariant — only ever public material crosses this boundary).
type CSRResponse struct {
	CertPEM   string `json:"certPem"`
	CAPEM     string `json:"caPem"`
	ExpiresAt string `json:"expiresAt"`
}

// SubmitCSR performs the bootstrap CSR submission against
// POST {enrollURL}/api/agents/enroll-csr, authenticated with
// bootstrapSecret via X-Agent-Token (the same header shape Enroll already
// uses). The single network-calling implementation of this step — Task 10
// (bootstrap.go) and any future loadgen equivalent both call this, neither
// reimplements it.
func SubmitCSR(ctx context.Context, client *http.Client, enrollURL, bootstrapSecret string, req CSRRequest) (CSRResponse, error) {
	var resp CSRResponse
	data, err := json.Marshal(req)
	if err != nil {
		return resp, fmt.Errorf("marshal CSR request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL+"/api/agents/enroll-csr", bytes.NewReader(data))
	if err != nil {
		return resp, fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Agent-Token", bootstrapSecret)
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return resp, fmt.Errorf("POST /api/agents/enroll-csr: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		return resp, fmt.Errorf("server %d on /api/agents/enroll-csr", httpResp.StatusCode)
	}
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return resp, fmt.Errorf("decode CSR response: %w", err)
	}
	return resp, nil
}
