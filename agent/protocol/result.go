package protocol

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
)

// SignBody returns the hex-encoded HMAC-SHA256 of body keyed with secret.
// Used to sign result payloads so the orchestrator can detect tampered
// results. Moved from agent/integrity.go -- SelfHash (binary self-hashing)
// stayed there since it's OS-dependent and loadgen has no use for it.
func SignBody(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// SubmitResult performs one POST /api/scenarios/result, signing the body
// when agentSecret is set (X-Result-MAC), exactly as the real agent's
// postJSONDecode already special-cases this one path. Shared by the real
// agent and loadgen -- the single network-calling implementation. The real
// agent's own submitRunResult/spool durability logic wraps this; loadgen
// calls it directly since it has no durable-delivery requirement (a lost
// fake result is just a data point, not a real assessment).
func SubmitResult(ctx context.Context, client *http.Client, serverURL, agentSecret string, payload RawRunResult) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/scenarios/result", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if agentSecret != "" {
		req.Header.Set("X-Agent-Token", agentSecret)
		req.Header.Set("X-Result-MAC", SignBody(data, agentSecret))
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /api/scenarios/result: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server %d on /api/scenarios/result", resp.StatusCode)
	}
	return nil
}
