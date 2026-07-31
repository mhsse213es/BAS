package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	unitPath   = "/etc/systemd/system/bas-agent.service"
	configDir  = "/etc/bas-agent"
	configFile = "/etc/bas-agent/config"
)

func svcInstall(serverURL, envLabel, secret string) error {
	if _, err := os.Stat(unitPath); err == nil {
		return fmt.Errorf("bas-agent already installed — run --uninstall first")
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return fmt.Errorf("resolve symlink: %w", err)
	}

	destBin := "/usr/local/bin/bas-agent"
	data, err := os.ReadFile(selfPath)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}
	if err := os.WriteFile(destBin, data, 0755); err != nil {
		return fmt.Errorf("write binary to %s: %w", destBin, err)
	}
	fmt.Printf("[+] binary installed: %s\n", destBin)

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	cfg := fmt.Sprintf("BAS_SERVER_URL=%s\nBAS_ENV_LABEL=%s\nBAS_AGENT_SECRET=%s\n", serverURL, envLabel, secret)
	if err := os.WriteFile(configFile, []byte(cfg), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("[+] config written: %s\n", configFile)

	unit := fmt.Sprintf(`[Unit]
Description=BAS Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s
EnvironmentFile=%s
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=bas-agent

[Install]
WantedBy=multi-user.target
`, destBin, configFile)

	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write unit file: %w", err)
	}
	fmt.Printf("[+] unit file written: %s\n", unitPath)

	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "--now", "bas-agent.service").Run(); err != nil {
		return fmt.Errorf("systemctl enable --now: %w", err)
	}

	fmt.Println("[+] bas-agent.service installed and started.")
	fmt.Println("[+] View logs: journalctl -u bas-agent.service -f")
	return nil
}

func svcUninstall() error {
	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline". Must happen before the config file removal below.
	serverURL, _ := readServiceParams()
	if err := notifyServerUnenroll(serverURL, readAgentSecret(), collectIdentity().AgentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}

	_ = exec.Command("systemctl", "stop", "bas-agent.service").Run()
	_ = exec.Command("systemctl", "disable", "bas-agent.service").Run()
	_ = os.Remove(unitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("[+] bas-agent.service removed.")
	fmt.Printf("[!] Binary and config (%s) left in place — remove manually if no longer needed.\n", configDir)
	return nil
}

func readServiceParams() (serverURL, envLabel string) {
	data, err := os.ReadFile(configFile)
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
	data, err := os.ReadFile(configFile)
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

// platformDisableAutoStart removes bas-agent.service's boot-time enablement
// so it does not start at the endpoint's next boot. Best-effort: a failure
// here is logged by the caller (stopSelf) but does not block the stop
// itself — the process still exits now; it just isn't guaranteed to stay
// stopped across a reboot.
func platformDisableAutoStart() error {
	return exec.Command("systemctl", "disable", "bas-agent.service").Run()
}

// platformExitAfterStop ends this process. The systemd unit's
// Restart=on-failure policy does not fire on a clean exit (code 0), so no
// SCM-style handshake is needed here unlike Windows.
func platformExitAfterStop() {
	os.Exit(0)
}
