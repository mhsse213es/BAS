//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func captureSnapshot(runID string) *SystemSnapshot {
	s := newSnapshot(runID)

	// User crontab
	if out, err := snapCmd("crontab", "-l"); err == nil {
		s.Files["crontab:user"] = out
	}

	// System cron directories
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly"} {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				s.Lists["cron_dirs"] = append(s.Lists["cron_dirs"], filepath.Join(dir, e.Name()))
			}
		}
	}

	// Loaded systemd services
	if out, err := snapCmd("systemctl", "list-units", "--type=service", "--state=loaded",
		"--no-legend", "--plain", "--no-pager"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if f := strings.Fields(line); len(f) > 0 {
				s.Lists["services"] = append(s.Lists["services"], f[0])
			}
		}
	}

	// Temp directory contents (1 level — avoids scanning enormous trees)
	for _, dir := range []string{"/tmp", "/var/tmp"} {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				s.Lists["tmp_files"] = append(s.Lists["tmp_files"], filepath.Join(dir, e.Name()))
			}
		}
	}

	// Sensitive file contents
	paths := []string{"/etc/hosts", "/etc/rc.local", "/etc/sudoers"}
	if home := os.Getenv("HOME"); home != "" {
		for _, f := range []string{".bashrc", ".bash_profile", ".profile"} {
			paths = append(paths, filepath.Join(home, f))
		}
	}
	for _, path := range paths {
		if content, err := os.ReadFile(path); err == nil {
			s.Files[path] = content
		}
	}

	// iptables rules (requires root — skipped silently if not available)
	if out, err := snapCmd("iptables-save"); err == nil {
		s.Files["iptables"] = out
	}

	return s
}

func revertFromSnapshot(s *SystemSnapshot) []string {
	var reverted []string

	// ── File content restore ──────────────────────────────────────────────────
	for path, original := range s.Files {
		switch path {
		case "crontab:user":
			if current, err := snapCmd("crontab", "-l"); err == nil && !bytes.Equal(current, original) {
				cmd := exec.Command("crontab", "-")
				cmd.Stdin = bytes.NewReader(original)
				if cmd.Run() == nil {
					reverted = append(reverted, "crontab: user crontab restored")
				}
			}
		case "iptables":
			if current, err := snapCmd("iptables-save"); err == nil && !bytes.Equal(current, original) {
				cmd := exec.Command("iptables-restore")
				cmd.Stdin = bytes.NewReader(original)
				if cmd.Run() == nil {
					reverted = append(reverted, "iptables: rules restored")
				}
			}
		default:
			if current, err := os.ReadFile(path); err == nil && !bytes.Equal(current, original) {
				if os.WriteFile(path, original, 0644) == nil {
					reverted = append(reverted, "file restored: "+path)
				}
			}
		}
	}

	// ── Cron directories — remove newly added files ───────────────────────────
	origCron := toSet(s.Lists["cron_dirs"])
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly"} {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				full := filepath.Join(dir, e.Name())
				if !origCron[full] {
					if os.Remove(full) == nil {
						reverted = append(reverted, "cron removed: "+full)
					}
				}
			}
		}
	}

	// ── Services — stop and disable newly added ones ──────────────────────────
	origSvcs := toSet(s.Lists["services"])
	if out, err := snapCmd("systemctl", "list-units", "--type=service", "--state=loaded",
		"--no-legend", "--plain", "--no-pager"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if f := strings.Fields(line); len(f) > 0 && !origSvcs[f[0]] {
				exec.Command("systemctl", "stop", f[0]).Run()    //nolint
				exec.Command("systemctl", "disable", f[0]).Run() //nolint
				reverted = append(reverted, "service stopped: "+f[0])
			}
		}
	}

	// ── Temp files — remove newly added entries ───────────────────────────────
	origTmp := toSet(s.Lists["tmp_files"])
	for _, dir := range []string{"/tmp", "/var/tmp"} {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				full := filepath.Join(dir, e.Name())
				if !origTmp[full] {
					if os.Remove(full) == nil {
						reverted = append(reverted, "tmp removed: "+full)
					}
				}
			}
		}
	}

	return reverted
}

// diffRegistry is a no-op on POSIX — there is no registry to diff.
func diffRegistry(_, _ *SystemSnapshot) []string { return nil }
