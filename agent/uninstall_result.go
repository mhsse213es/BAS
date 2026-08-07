package main

import (
	"bytes"
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
	url := a.cfg.ServerURL + "/api/agents/" + a.id.AgentID + "/uninstall-result"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		log.Printf("[!] build uninstall-result request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.AgentSecret != "" {
		req.Header.Set("X-Agent-Token", a.cfg.AgentSecret)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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
