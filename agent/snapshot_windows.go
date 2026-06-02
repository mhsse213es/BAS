//go:build windows

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

	// Scheduled tasks
	if out, err := snapCmd("schtasks", "/query", "/fo", "CSV", "/nh"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// CSV: "TaskName","NextRunTime","Status"
			fields := strings.SplitN(line, ",", 2)
			if len(fields) > 0 {
				name := strings.Trim(fields[0], `"`)
				s.Lists["schtasks"] = append(s.Lists["schtasks"], name)
			}
		}
	}

	// Services
	if out, err := snapCmd("sc", "query", "type=", "all", "state=", "all"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "SERVICE_NAME:") {
				name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "SERVICE_NAME:"))
				if name != "" {
					s.Lists["services"] = append(s.Lists["services"], name)
				}
			}
		}
	}

	// Registry Run keys (persistence locations)
	regKeys := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	for _, key := range regKeys {
		if out, err := snapCmd("reg", "query", key); err == nil {
			s.Files["reg:"+key] = out
		}
	}

	// Temp directories (1 level)
	tmpDirs := []string{os.TempDir(), `C:\Windows\Temp`}
	for _, dir := range tmpDirs {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				s.Lists["tmp_files"] = append(s.Lists["tmp_files"], filepath.Join(dir, e.Name()))
			}
		}
	}

	// Hosts file
	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
	if content, err := os.ReadFile(hostsPath); err == nil {
		s.Files[hostsPath] = content
	}

	// Firewall rules snapshot (netsh)
	if out, err := snapCmd("netsh", "advfirewall", "firewall", "show", "rule", "name=all"); err == nil {
		s.Files["firewall"] = out
	}

	// Startup folders
	startupDirs := []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
	}
	for _, dir := range startupDirs {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				s.Lists["startup"] = append(s.Lists["startup"], filepath.Join(dir, e.Name()))
			}
		}
	}

	return s
}

func revertFromSnapshot(s *SystemSnapshot) []string {
	var reverted []string

	// ── Hosts file restore ────────────────────────────────────────────────────
	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
	if original, ok := s.Files[hostsPath]; ok {
		if current, err := os.ReadFile(hostsPath); err == nil && !bytes.Equal(current, original) {
			if os.WriteFile(hostsPath, original, 0644) == nil {
				reverted = append(reverted, "file restored: "+hostsPath)
			}
		}
	}

	// ── Registry Run key restore ──────────────────────────────────────────────
	regKeys := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	for _, key := range regKeys {
		original, ok := s.Files["reg:"+key]
		if !ok {
			continue
		}
		current, err := snapCmd("reg", "query", key)
		if err != nil || bytes.Equal(current, original) {
			continue
		}
		// Parse original values into a set, then delete any new ones
		origValues := parseRegValues(original)
		currentValues := parseRegValues(current)
		for name := range currentValues {
			if !origValues[name] {
				cmd := exec.Command("reg", "delete", key, "/v", name, "/f")
				if cmd.Run() == nil {
					reverted = append(reverted, "registry removed: "+key+`\`+name)
				}
			}
		}
	}

	// ── Scheduled tasks — delete newly added ─────────────────────────────────
	origTasks := toSet(s.Lists["schtasks"])
	if out, err := snapCmd("schtasks", "/query", "/fo", "CSV", "/nh"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.SplitN(line, ",", 2)
			if len(fields) == 0 {
				continue
			}
			name := strings.Trim(fields[0], `"`)
			if !origTasks[name] {
				cmd := exec.Command("schtasks", "/delete", "/tn", name, "/f")
				if cmd.Run() == nil {
					reverted = append(reverted, "schtask deleted: "+name)
				}
			}
		}
	}

	// ── Services — stop and disable newly added ───────────────────────────────
	origSvcs := toSet(s.Lists["services"])
	if out, err := snapCmd("sc", "query", "type=", "all", "state=", "all"); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "SERVICE_NAME:") {
				continue
			}
			name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "SERVICE_NAME:"))
			if name != "" && !origSvcs[name] {
				exec.Command("sc", "stop", name).Run()                         //nolint
				exec.Command("sc", "config", name, "start=", "disabled").Run() //nolint
				reverted = append(reverted, "service stopped: "+name)
			}
		}
	}

	// ── Temp files — remove newly added ──────────────────────────────────────
	origTmp := toSet(s.Lists["tmp_files"])
	tmpDirs := []string{os.TempDir(), `C:\Windows\Temp`}
	for _, dir := range tmpDirs {
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

	// ── Startup folder — remove newly added files ─────────────────────────────
	origStartup := toSet(s.Lists["startup"])
	startupDirs := []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
	}
	for _, dir := range startupDirs {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, e := range entries {
				full := filepath.Join(dir, e.Name())
				if !origStartup[full] {
					if os.Remove(full) == nil {
						reverted = append(reverted, "startup removed: "+full)
					}
				}
			}
		}
	}

	return reverted
}

// parseRegValues extracts value names from `reg query` output into a set.
func parseRegValues(out []byte) map[string]bool {
	result := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "HKEY") || strings.HasPrefix(line, "!") {
			continue
		}
		// Format: "    ValueName    REG_SZ    data"
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			result[fields[0]] = true
		}
	}
	return result
}
