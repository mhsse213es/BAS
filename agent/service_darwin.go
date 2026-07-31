//go:build darwin

package main

import (
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
	cfg := fmt.Sprintf("BAS_SERVER_URL=%s\nBAS_ENV_LABEL=%s\nBAS_AGENT_SECRET=%s\n", serverURL, envLabel, secret)
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
	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline". Must happen before the plist unload/removal below.
	serverURL, _ := readServiceParams()
	if err := notifyServerUnenroll(serverURL, readAgentSecret(), collectIdentity().AgentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}

	_ = exec.Command("launchctl", "unload", darwinPlistPath).Run()
	_ = os.Remove(darwinPlistPath)
	fmt.Println("[+] bas-agent launchd daemon removed.")
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

// platformDisableAutoStart unloads the launchd job with the persistent
// "-w" (disabled) flag, so it does not start at the endpoint's next boot.
// Unlike Linux/Windows, this must run BEFORE the process exits, not after:
// the launchd plist's KeepAlive=true restarts the job unconditionally on
// ANY exit (clean or not), so exiting first would just be relaunched before
// this had a chance to disable it. Note this call itself typically
// terminates the process as a side effect of unloading — that's expected;
// platformExitAfterStop below becomes a no-op in that case.
func platformDisableAutoStart() error {
	return exec.Command("launchctl", "unload", "-w", darwinPlistPath).Run()
}

// platformExitAfterStop ends this process. On macOS the disable step above
// usually already ended it — this is a fallback for the case where it did
// not (e.g. an older launchd that doesn't synchronously kill on unload).
func platformExitAfterStop() {
	os.Exit(0)
}
