//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	darwinPlistPath = "/Library/LaunchDaemons/com.audspect.bas-agent.plist"
	darwinConfigDir = "/etc/bas-agent"
	darwinConfigFile = "/etc/bas-agent/config"
)

func svcInstall(serverURL, envLabel string) error {
	if err := os.MkdirAll(darwinConfigDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	cfg := fmt.Sprintf("BAS_SERVER_URL=%s\nBAS_ENV_LABEL=%s\n", serverURL, envLabel)
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
