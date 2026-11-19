//go:build windows

package main

import (
	"strings"
	"testing"
)

// Locations the static scan of the shipped Windows atomics found tests writing to (scripts/scenario-scan). Each would
// leave a machine disrupted if a test's own cleanup did not run.
func TestDefaultGuardRoots_CoverWhatTheScenarioScanFound(t *testing.T) {
	have := map[string]bool{}
	for _, r := range defaultGuardRoots() {
		have[strings.ToLower(r.String())] = true
	}
	for _, want := range []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies`, // NoRun, DisableTaskMgr, DisableRegistryTools
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`,
		`HKCU\Software\Policies\Microsoft`,
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, // RDP on or off
		`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`,
		`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`,
		`HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider`,
		`HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`,
		`HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger`, // ETW sessions switched off
		`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`,
		`HKLM\SYSTEM\CurrentControlSet\Services\W32Time`,
		`HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`, // proxy and security zones
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Winlogon`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels`, // event log channels switched off
		`HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`,
		`HKCU\Software\Microsoft\Active Setup\Installed Components`,
		`HKLM\SOFTWARE\Microsoft\.NETFramework`,
		`HKLM\SOFTWARE\Microsoft\Provisioning\Commands`,
		`HKCU\Software\Microsoft\Office\16.0\Excel\Security`, // macro security
		`HKCU\Software\Microsoft\Office\16.0\Word\Security`,
		`HKCU\Software\Microsoft\Office\16.0\Outlook\Security`,
		`HKCU\Software\Microsoft\Office\16.0\PowerPoint\Security`,
	} {
		if !have[strings.ToLower(want)] {
			t.Errorf("not protected: %s", want)
		}
	}
}

// A root inside another root is restored twice and reported twice.
func TestDefaultGuardRoots_DoNotOverlap(t *testing.T) {
	roots := defaultGuardRoots()
	for i, a := range roots {
		for j, b := range roots {
			if i != j && a.Hive == b.Hive && strings.HasPrefix(strings.ToLower(b.Path)+`\`, strings.ToLower(a.Path)+`\`) {
				t.Errorf("guard roots overlap: %s contains %s", a, b)
			}
		}
	}
}
