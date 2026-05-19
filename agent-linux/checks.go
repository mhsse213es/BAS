package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SimCategory, SimCheck, Tech — identical to Windows agent for wire protocol compatibility.

type SimCategory struct {
	Phase  string     `json:"phase"`
	Checks []SimCheck `json:"checks"`
}

type SimCheck struct {
	ID           string    `json:"id"`
	Technique    Tech      `json:"technique"`
	Result       string    `json:"result"`       // pass | fail | skipped
	Severity     string    `json:"severity"`     // Critical | High | Medium | Low
	ThreatImpact string    `json:"threatImpact"`
	Details      string    `json:"details"`
	Remediation  string    `json:"remediation"`
	RawOutput    string    `json:"rawOutput,omitempty"`
	DurationMs   int64     `json:"durationMs"`
	ExecutedAt   time.Time `json:"executedAt"`
	Framework    string    `json:"framework"`
}

type Tech struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

// checkID produces the stable 8-hex-char task ID used to correlate results.
// Must match orchestrator's scenario.TaskID(techniqueID, name).
func checkID(techID, name string) string {
	h := sha256.Sum256([]byte(techID + name))
	return hex.EncodeToString(h[:])[:8]
}

// check builds a SimCheck, runs fn(), and records timing.
func check(techID, name, tactic, severity, threat, fix string,
	fn func() (result, details string)) SimCheck {

	start := time.Now()
	result, details := fn()
	return SimCheck{
		ID:           checkID(techID, name),
		Technique:    Tech{ID: techID, Name: name, Tactic: tactic},
		Result:       result,
		Severity:     severity,
		ThreatImpact: threat,
		Details:      details,
		Remediation:  fix,
		DurationMs:   time.Since(start).Milliseconds(),
		ExecutedAt:   time.Now(),
		Framework:    "custom",
	}
}

// ── Linux System Helpers ──────────────────────────────────────────────────────

// sysctl reads a kernel parameter from /proc/sys/... falling back to sysctl(8).
func sysctl(key string) string {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	data, err := os.ReadFile(path)
	if err == nil {
		return strings.TrimSpace(string(data))
	}
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// serviceActive returns true if the named systemd unit is in "active" running state.
func serviceActive(name string) bool {
	err := exec.Command("systemctl", "is-active", "--quiet", name).Run()
	return err == nil
}

// serviceEnabled returns true if the named systemd unit is enabled at boot.
func serviceEnabled(name string) bool {
	err := exec.Command("systemctl", "is-enabled", "--quiet", name).Run()
	return err == nil
}

// sshConfigValue returns the effective value for an sshd_config keyword.
// Checks /etc/ssh/sshd_config and all files under /etc/ssh/sshd_config.d/ (last-wins).
func sshConfigValue(keyword string) string {
	result := sshConfigValueInFile("/etc/ssh/sshd_config", keyword)
	entries, err := os.ReadDir("/etc/ssh/sshd_config.d")
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				if v := sshConfigValueInFile("/etc/ssh/sshd_config.d/"+e.Name(), keyword); v != "" {
					result = v
				}
			}
		}
	}
	return result
}

func sshConfigValueInFile(path, keyword string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	result := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], keyword) {
			result = fields[1]
		}
	}
	return result
}

// mountHasOption reports whether mountpoint is mounted with the given option
// by reading /proc/mounts.
func mountHasOption(mountpoint, option string) bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[1] == mountpoint {
			for _, opt := range strings.Split(fields[3], ",") {
				if opt == option {
					return true
				}
			}
		}
	}
	return false
}

// packageInstalled checks if a package is installed via dpkg.
func packageInstalled(name string) bool {
	out, err := exec.Command("dpkg", "-s", name).Output()
	return err == nil && strings.Contains(string(out), "Status: install ok installed")
}

// sudoHasOption checks if a config option is present in /etc/sudoers or /etc/sudoers.d/*.
func sudoHasOption(option string) bool {
	if data, err := os.ReadFile("/etc/sudoers"); err == nil {
		if strings.Contains(string(data), option) {
			return true
		}
	}
	entries, err := os.ReadDir("/etc/sudoers.d")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile("/etc/sudoers.d/" + e.Name())
		if err == nil && strings.Contains(string(data), option) {
			return true
		}
	}
	return false
}
