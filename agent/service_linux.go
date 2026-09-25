package main

import (
	"encoding/base64"
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
	// serverURL/secret must be read while the config file still exists --
	// capture them now, but notify only after the unit is actually removed
	// below, so the server never learns "uninstalled" before it's true.
	serverURL, _ := readServiceParams()
	secret := readAgentSecret()
	agentID := collectIdentity().AgentID

	_ = exec.Command("systemctl", "stop", "bas-agent.service").Run()
	_ = exec.Command("systemctl", "disable", "bas-agent.service").Run()
	_ = os.Remove(unitPath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("[+] bas-agent.service removed.")
	fmt.Printf("[!] Binary and config (%s) left in place — remove manually if no longer needed.\n", configDir)

	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline" -- now sent only after the unit is actually removed above.
	if err := notifyServerUnenroll(serverURL, secret, agentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall: %v\n", err)
	}
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

// readProxyCredentials reads BAS_PROXY_USER/BAS_PROXY_PASSWORD from the
// config file written at install time, mirroring readAgentSecret's rationale
// for the agent secret: a service-managed agent already has these injected
// as real env vars via EnvironmentFile=, but code that runs outside that
// context (or before the file exists) needs this fallback.
func readProxyCredentials() (user, password string) {
	data, err := os.ReadFile(configFile)
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

// platformDisableAutoStart removes bas-agent.service's boot-time enablement
// so it does not start at the endpoint's next boot. Best-effort: a failure
// here is logged by the caller (stopSelf) but does not block the stop
// itself — the process still exits now; it just isn't guaranteed to stay
// stopped across a reboot.
func platformDisableAutoStart() error {
	return exec.Command("systemctl", "disable", "bas-agent.service").Run()
}

// platformSelfUninstall removes the systemd unit's boot-time enablement and
// deletes its unit file, then reloads systemd's unit cache. It deliberately
// does NOT call `systemctl stop` on the unit the calling process belongs to
// -- that would send SIGTERM to this very process before it can report the
// result and exit cleanly. The process's own exit (via
// platformExitAfterStopFn -- os.Exit(0) on Linux, called right after this
// by uninstallSelf) is what actually stops it; Restart=on-failure does not
// fire on a clean exit. Matches svcUninstall's existing choice to leave the
// binary/config in place -- only the unit definition is removed here.
func platformSelfUninstall() error {
	if err := exec.Command("systemctl", "disable", "bas-agent.service").Run(); err != nil {
		fmt.Printf("[~] systemctl disable: %v\n", err)
	}
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove unit file: %w", err)
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		fmt.Printf("[~] systemctl daemon-reload: %v\n", err)
	}
	return nil
}

// platformExitAfterStop ends this process. The systemd unit's
// Restart=on-failure policy does not fire on a clean exit (code 0), so no
// SCM-style handshake is needed here unlike Windows.
func platformExitAfterStop() {
	os.Exit(0)
}
