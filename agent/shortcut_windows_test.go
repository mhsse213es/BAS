//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestPSQuoteDoublesSingleQuotes(t *testing.T) {
	if got := psQuote(`C:\Program Files\O'Brien\bas_agent.exe`); got != `'C:\Program Files\O''Brien\bas_agent.exe'` {
		t.Fatalf("got %s", got)
	}
}

func TestTrayShortcutScriptTargetsTheTrayAndQuotesEveryPath(t *testing.T) {
	s := trayShortcutScript(`C:\ProgramData\Menu\Audspect Agent.lnk`, `C:\Program Files\BASAgent\bas_agent.exe`)
	for _, want := range []string{
		`CreateShortcut('C:\ProgramData\Menu\Audspect Agent.lnk')`,
		`$s.TargetPath = 'C:\Program Files\BASAgent\bas_agent.exe'`,
		`$s.Arguments = '--tray'`,
		`$s.WorkingDirectory = 'C:\Program Files\BASAgent'`,
		`$s.WindowStyle = 7`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script is missing %q\n%s", want, s)
		}
	}
}

func TestTrayShortcutNamesAreDistinct(t *testing.T) {
	if trayShortcutName == legacyTrayShortcutName {
		t.Fatal("the current and legacy shortcut names must differ so uninstall removes both")
	}
}
