package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// reportUninstallResult tells the server whether this agent's self-uninstall
// (triggered by command_uninstall_agent) succeeded, using the in-memory
// cfg/id this already-running process was started with -- unlike
// notifyServerUnenroll (called from the separate-process CLI --uninstall
// path), there is no need to re-read serverURL/secret from disk here.
// Reuses a.httpClient() (not a throwaway one) so it inherits the same proxy-aware
// Transport every other outbound call already gets via newAgent -- but this
// call sits on the blocking shutdown path (uninstallSelf runs it
// synchronously before exiting), so it keeps its own tighter 10s bound via
// a request-scoped context rather than inheriting a.httpClient()'s general 30s
// Timeout.
func reportUninstallResult(a *Agent, uninstallErr error) {
	body := map[string]any{"success": uninstallErr == nil}
	if uninstallErr != nil {
		body["error"] = uninstallErr.Error()
	}
	data, err := json.Marshal(body)
	if err != nil {
		log.Printf("[!] marshal uninstall result: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url := a.cfg().ServerURL + "/api/agents/" + a.id.AgentID + "/uninstall-result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		log.Printf("[!] build uninstall-result request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg().AgentSecret != "" {
		req.Header.Set("X-Agent-Token", a.cfg().AgentSecret)
	}
	resp, err := a.httpClient().Do(req)
	if err != nil {
		log.Printf("[!] POST uninstall-result: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("[!] uninstall-result: server returned %d", resp.StatusCode)
	}
}

// reportUninstallResultFn is an indirection over reportUninstallResult so
// tests can substitute a no-op stand-in instead of making a real HTTP call.
var reportUninstallResultFn = reportUninstallResult
