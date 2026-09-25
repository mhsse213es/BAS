package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// notifyServerUnenroll tells the server this endpoint is being uninstalled,
// best-effort. Called from svcUninstall on every platform before local state
// (service/unit/plist, config) is removed, since serverURL/secret are only
// readable from that local state. A failure here (offline machine,
// unreachable server) must never block uninstall — the server's own
// heartbeat-staleness monitor is the fallback, just slower (shows "offline"
// instead of immediately hiding the endpoint) — see
// internal/api.UnenrollAgent for what this sets server-side.
//
// No running Agent/Config exists at this point (this runs from the
// standalone --uninstall CLI path, not the long-running service process),
// so proxy credentials are resolved fresh via resolveProxyCredentials --
// the same env-var-first-then-platform-storage priority loadConfig uses,
// factored out specifically so this path can't drift from that one.
func notifyServerUnenroll(serverURL, secret, agentID string) error {
	if serverURL == "" || agentID == "" {
		return fmt.Errorf("missing serverURL or agentID")
	}
	data, err := json.Marshal(map[string]string{"agentId": agentID})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/agents/unenroll", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Agent-Token", secret)
	}
	proxyUser, proxyPassword := resolveProxyCredentials()
	cfg := Config{ServerURL: serverURL, ProxyUser: proxyUser, ProxyPassword: proxyPassword}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: proxyAwareNetDialContext(cfg), Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /api/agents/unenroll: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}
