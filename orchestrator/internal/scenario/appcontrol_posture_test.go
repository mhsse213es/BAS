package scenario

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// appCtlFixture is one AppLocker effective-policy shape fed to the shipped
// posture script in place of a real Get-AppLockerPolicy call. Collections
// maps RuleCollectionType (Exe, Script, Dll, Msi, Appx) to EnforcementMode
// (NotConfigured, AuditOnly, Enabled); a type absent from the map is not
// configured. A nil Collections means no effective policy could be read.
type appCtlFixture struct {
	name        string
	collections map[string]string
	noPolicy    bool
	wantOutcome string // "PASS:" or "FAIL:" or "SKIP:" -- prefix the script must emit
	wantDetail  string // substring that must appear in the output
}

var appCtlFixtures = []appCtlFixture{
	{
		name:        "exe and script both enforced",
		collections: map[string]string{"Exe": "Enabled", "Script": "Enabled"},
		wantOutcome: "PASS:",
		wantDetail:  "Exe=Enabled Script=Enabled",
	},
	{
		name:        "exe enforced but script audit-only",
		collections: map[string]string{"Exe": "Enabled", "Script": "AuditOnly"},
		wantOutcome: "FAIL:",
		wantDetail:  "Script=AuditOnly",
	},
	{
		name:        "exe enforced, no script collection at all",
		collections: map[string]string{"Exe": "Enabled"},
		wantOutcome: "FAIL:",
		wantDetail:  "Script=NotConfigured",
	},
	{
		name:        "no effective policy readable",
		noPolicy:    true,
		wantOutcome: "FAIL:",
		wantDetail:  "Exe=NotConfigured",
	},
}

// TestAppControlPosture_EmitsEffectiveCoverageNotPresence drives the real
// shipped command text of the em-01 AppLocker step (not a copy) against
// fixture policies. Presence-only logic ("any rule collection exists" =>
// PASS) is the defect this pins: an audit-only script collection must never
// be reported as enforcement.
func TestAppControlPosture_EmitsEffectiveCoverageNotPresence(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("posture script is Windows PowerShell")
	}
	command := loadStepCommand(t,
		filepath.Join("..", "..", "..", "scenarios", "endpoint-mastery", "em-01-control-validation.yaml"),
		"Application control present")

	for _, fx := range appCtlFixtures {
		t.Run(fx.name, func(t *testing.T) {
			out := runPosturePowerShell(t, fixturePrelude(fx)+"\n"+command)
			if !strings.Contains(out, fx.wantOutcome) {
				t.Fatalf("output lacks %q:\n%s", fx.wantOutcome, out)
			}
			if !strings.Contains(out, fx.wantDetail) {
				t.Fatalf("output lacks detail %q:\n%s", fx.wantDetail, out)
			}
			if fx.wantOutcome == "PASS:" && strings.Contains(out, "FAIL:") {
				t.Fatalf("PASS fixture also emitted FAIL:\n%s", out)
			}
		})
	}
}

func fixturePrelude(fx appCtlFixture) string {
	var b strings.Builder
	b.WriteString("function Get-CimInstance { throw 'no WDAC in fixture' }\n")
	if fx.noPolicy {
		b.WriteString("function Get-AppLockerPolicy { throw 'no policy in fixture' }\n")
		return b.String()
	}
	b.WriteString("function Get-AppLockerPolicy { [CmdletBinding()] param([switch]$Effective)\n")
	var items []string
	for typ, mode := range fx.collections {
		items = append(items, fmt.Sprintf("[pscustomobject]@{ RuleCollectionType = '%s'; EnforcementMode = '%s'; Count = 1 }", typ, mode))
	}
	b.WriteString("  [pscustomobject]@{ RuleCollections = @(" + strings.Join(items, ", ") + ") }\n}\n")
	return b.String()
}

func loadStepCommand(t *testing.T, path, namePrefix string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Steps []struct {
			Name    string `yaml:"name"`
			Command string `yaml:"command"`
		} `yaml:"steps"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, s := range doc.Steps {
		if strings.HasPrefix(s.Name, namePrefix) {
			return s.Command
		}
	}
	t.Fatalf("no step with name prefix %q in %s", namePrefix, path)
	return ""
}

func runPosturePowerShell(t *testing.T, script string) string {
	t.Helper()
	out, _ := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput()
	return string(out)
}

// TestFullScanAppLocker_ServiceRunningIsNotEnforcement pins the full-scan
// AppLocker step: AppIDSvc running proves the service is up, not that any
// rule enforces. A running service must never produce PASS; a stopped one
// cannot enforce, so it must FAIL.
func TestFullScanAppLocker_ServiceRunningIsNotEnforcement(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("posture script is Windows PowerShell")
	}
	command := loadStepCommand(t,
		filepath.Join("..", "..", "..", "scenarios", "full-scan.yaml"),
		"Application Control (AppLocker)")

	cases := []struct {
		name, status, wantPrefix string
	}{
		{"service running is not enforcement", "Running", "SKIP:"},
		{"service stopped cannot enforce", "Stopped", "FAIL:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prelude := fmt.Sprintf("function Get-Service { [CmdletBinding()] param([string]$Name) [pscustomobject]@{ Name = $Name; Status = '%s' } }\n", c.status)
			out := runPosturePowerShell(t, prelude+command)
			if strings.Contains(out, "PASS:") {
				t.Fatalf("service state alone produced PASS:\n%s", out)
			}
			if !strings.Contains(out, c.wantPrefix) {
				t.Fatalf("output lacks %q:\n%s", c.wantPrefix, out)
			}
		})
	}
}
