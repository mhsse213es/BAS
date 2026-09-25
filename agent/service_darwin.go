//go:build darwin

package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	darwinPlistPath  = "/Library/LaunchDaemons/com.audspect.bas-agent.plist"
	darwinConfigDir  = "/etc/bas-agent"
	darwinConfigFile = "/etc/bas-agent/config"
)

func svcInstall(serverURL, envLabel, secret string) error {
	if _, err := os.Stat(darwinPlistPath); err == nil {
		return fmt.Errorf("bas-agent already installed — run --uninstall first")
	}

	if err := os.MkdirAll(darwinConfigDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	proxyUser := os.Getenv("BAS_PROXY_USER")
	if strings.ContainsAny(proxyUser, "\r\n") {
		return fmt.Errorf("BAS_PROXY_USER must not contain newlines")
	}
	proxyPassword := os.Getenv("BAS_PROXY_PASSWORD")
	// Base64-encoded, under a DIFFERENT key than the raw BAS_PROXY_PASSWORD
	// env var an operator can set directly -- systemd/launchd apply
	// shell-like unquoting to EnvironmentFile= values, which would silently
	// corrupt a password containing $, ", ', \, a leading #, or whitespace
	// if written raw. Base64 sidesteps that entirely. readProxyCredentials
	// below decodes it; loadConfig's own raw-env-var path is untouched and
	// still takes priority when an operator sets BAS_PROXY_PASSWORD
	// directly (not via this file).
	proxyPasswordB64 := base64.StdEncoding.EncodeToString([]byte(proxyPassword))
	cfg := fmt.Sprintf("BAS_SERVER_URL=%s\nBAS_ENV_LABEL=%s\nBAS_AGENT_SECRET=%s\nBAS_PROXY_USER=%s\nBAS_PROXY_PASSWORD_B64=%s\n",
		serverURL, envLabel, secret, proxyUser, proxyPasswordB64)
	if err := os.WriteFile(darwinConfigFile, []byte(cfg), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.audspect.bas-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/bas-agent</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>BAS_SERVER_URL</key>
        <string>%s</string>
        <key>BAS_ENV_LABEL</key>
        <string>%s</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/bas-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/bas-agent.log</string>
</dict>
</plist>
`, serverURL, envLabel)

	if err := os.WriteFile(darwinPlistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	if err := exec.Command("launchctl", "load", "-w", darwinPlistPath).Run(); err != nil {
		return fmt.Errorf("launchctl load: %w", err)
	}
	fmt.Println("[+] bas-agent launchd daemon installed and started.")
	return nil
}

func svcUninstall() error {
	// serverURL/secret must be read while the config file still exists --
	// capture them now, but notify only after the plist is actually
	// unloaded/removed below, so the server never learns "uninstalled"
	// before it's true.
	serverURL, _ := readServiceParams()
	secret := readAgentSecret()
	agentID := collectIdentity().AgentID

	_ = exec.Command("launchctl", "unload", darwinPlistPath).Run()
	_ = os.Remove(darwinPlistPath)
	fmt.Println("[+] bas-agent launchd daemon removed.")

	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline" -- now sent only after the plist is actually removed above.
	if err := notifyServerUnenroll(serverURL, secret, agentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}
	return nil
}

func readServiceParams() (serverURL, envLabel string) {
	data, err := os.ReadFile(darwinConfigFile)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BAS_SERVER_URL=") {
			serverURL = strings.TrimPrefix(line, "BAS_SERVER_URL=")
		}
		if strings.HasPrefix(line, "BAS_ENV_LABEL=") {
			envLabel = strings.TrimPrefix(line, "BAS_ENV_LABEL=")
		}
	}
	return serverURL, envLabel
}

// readAgentSecret reads BAS_AGENT_SECRET from the config file written at
// install time (svcInstall above) — needed for notifyServerUnenroll since
// the config isn't loaded into env vars during --uninstall.
func readAgentSecret() string {
	data, err := os.ReadFile(darwinConfigFile)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BAS_AGENT_SECRET=") {
			return strings.TrimPrefix(line, "BAS_AGENT_SECRET=")
		}
	}
	return ""
}

// readProxyCredentials reads BAS_PROXY_USER/BAS_PROXY_PASSWORD from the
// config file written at install time, mirroring readAgentSecret's rationale
// for the agent secret: a service-managed agent already has these injected
// as real env vars via EnvironmentFile=, but code that runs outside that
// context (or before the file exists) needs this fallback.
func readProxyCredentials() (user, password string) {
	data, err := os.ReadFile(darwinConfigFile)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "BAS_PROXY_USER="); ok {
			user = v
		} else if v, ok := strings.CutPrefix(line, "BAS_PROXY_PASSWORD_B64="); ok {
			if decoded, err := base64.StdEncoding.DecodeString(v); err == nil {
				password = string(decoded)
			}
		}
	}
	return user, password
}

// darwinLaunchdLabel matches the <key>Label</key> written into the plist by
// svcInstall above.
const darwinLaunchdLabel = "com.audspect.bas-agent"

// platformDisableAutoStart unloads the launchd job so it does not start at
// the endpoint's next boot. Unlike Linux/Windows, this must run BEFORE the
// process exits, not after: the launchd plist's KeepAlive=true restarts the
// job unconditionally on ANY exit (clean or not), so exiting first would
// just be relaunched before this had a chance to disable it. Note this call
// itself typically terminates the process as a side effect of unloading —
// that's expected; platformExitAfterStop below becomes a no-op in that case.
//
// Unloads by label (via `bootout`) rather than by plist path (the legacy
// `unload <path>` form) so this still works when the plist file has already
// been removed -- the case for the remote self-uninstall flow, where
// platformSelfUninstall (below) deletes the plist before this runs.
func platformDisableAutoStart() error {
	return exec.Command("launchctl", "bootout", "system/"+darwinLaunchdLabel).Run()
}

// platformSelfUninstall removes the plist so the daemon does not reload at
// the endpoint's next boot. Safe to call while running -- deleting the file
// has no effect on the currently-loaded job; platformDisableAutoStartFn
// (called by uninstallSelf right after this returns, and after the result
// is reported) is what actually unloads the running job, and now does so by
// label so it no longer depends on this file still existing at that point.
func platformSelfUninstall() error {
	if err := os.Remove(darwinPlistPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}
	return nil
}

// platformExitAfterStop ends this process. On macOS the disable step above
// usually already ended it — this is a fallback for the case where it did
// not (e.g. an older launchd that doesn't synchronously kill on unload).
func platformExitAfterStop() {
	os.Exit(0)
}
