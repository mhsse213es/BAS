package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	unitPath   = "/etc/systemd/system/bas-agent.service"
	configDir  = "/etc/bas-agent"
	configFile = "/etc/bas-agent/config"
)

// svcInstall copies the binary, writes config, creates the systemd unit,
// and enables + starts the service. Requires root.
func svcInstall(serverURL, envLabel string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return fmt.Errorf("resolve symlink: %w", err)
	}

	destBin := "/usr/local/bin/bas-agent-linux"
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
	cfg := fmt.Sprintf("BAS_SERVER_URL=%s\nBAS_ENV_LABEL=%s\n", serverURL, envLabel)
	if err := os.WriteFile(configFile, []byte(cfg), 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("[+] config written: %s\n", configFile)

	unit := fmt.Sprintf(`[Unit]
Description=BAS Linux Agent
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

// svcUninstall stops, disables, and removes the systemd unit. Leaves binary and config intact.
func svcUninstall() error {
	_ = exec.Command("systemctl", "stop", "bas-agent.service").Run()
	_ = exec.Command("systemctl", "disable", "bas-agent.service").Run()
	_ = os.Remove(unitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("[+] bas-agent.service removed.")
	fmt.Printf("[!] Binary (%s) and config (%s) left in place — remove manually if no longer needed.\n",
		"/usr/local/bin/bas-agent-linux", configDir)
	return nil
}
