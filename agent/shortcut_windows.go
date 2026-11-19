//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Start Menu entries that bring the tray icon back on demand.
//
// The MSI installs "Audspect\Audspect Agent Status" (opens the status window) and a top-level
// "Audspect Agent" (starts the tray). The older setup program created
// "Audspect Agent - Show Tray Icon". The CLI install (--install) used to create nothing, so a machine
// installed that way had no way to start the tray by hand. All names are removed on uninstall.
const (
	trayShortcutName       = "Audspect Agent.lnk"
	legacyTrayShortcutName = "Audspect Agent - Show Tray Icon.lnk"
)

func startMenuProgramsDir() string {
	return filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs`)
}

// psQuote returns s as a PowerShell single-quoted literal.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// trayShortcutScript builds the PowerShell that writes the shortcut (WScript.Shell, no extra
// dependency). WindowStyle 7 starts it minimised; the tray detaches its console on start anyway.
func trayShortcutScript(shortcutPath, exePath string) string {
	return "$ws = New-Object -ComObject WScript.Shell\n" +
		"$s = $ws.CreateShortcut(" + psQuote(shortcutPath) + ")\n" +
		"$s.TargetPath = " + psQuote(exePath) + "\n" +
		"$s.Arguments = '--tray'\n" +
		"$s.WorkingDirectory = " + psQuote(filepath.Dir(exePath)) + "\n" +
		"$s.IconLocation = " + psQuote(exePath+",0") + "\n" +
		"$s.Description = 'Show the Audspect Agent tray icon'\n" +
		"$s.WindowStyle = 7\n" +
		"$s.Save()"
}

// createTrayShortcut writes the all-users "Audspect Agent" Start Menu shortcut for the CLI install.
// An existing shortcut (for example the MSI's) is left alone.
func createTrayShortcut(exePath string) error {
	path := filepath.Join(startMenuProgramsDir(), trayShortcutName)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", trayShortcutScript(path, exePath))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create start menu shortcut: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
