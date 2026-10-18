package scenario

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// behavioralFixture is one controlled observation fed to a shipped
// behavioral step: the policy mode, service state, event-log readability,
// the number of matching block events, and whether the attempted binary
// ran (its marker reached stdout). The real command text is executed; only
// the cmdlets that touch AppLocker, services, the event log, and processes
// are stubbed, so nothing real is launched.
type behavioralFixture struct {
	name        string
	step        string // step name prefix
	exeMode     string // Exe collection mode: Enabled, AuditOnly, NotConfigured
	appIDState  string // Running or Stopped
	logReadable bool
	attr        int  // matching block events
	ran         bool // marker reached stdout
	exit        int
	wantOutcome string // APPCTL_OUTCOME value
	wantPrefix  string // PASS:, FAIL:, or SKIP:
}

const (
	indirectStep = "Application control indirect execution"
	altStep      = "Application control alternate binary"
	psPath       = `System32\WindowsPowerShell\v1.0\powershell.exe`
)

var behavioralFixtures = []behavioralFixture{
	{"indirect: enforced, blocked, one block event", indirectStep, "Enabled", "Running", true, 1, false, 1, "blocked_as_expected", "PASS:"},
	{"indirect: enforced but executed", indirectStep, "Enabled", "Running", true, 0, true, 0, "allowed_unexpectedly", "FAIL:"},
	{"indirect: audit-only and executed", indirectStep, "AuditOnly", "Running", true, 0, true, 0, "not_enforced", "FAIL:"},
	{"indirect: not executed, no block event", indirectStep, "Enabled", "Running", true, 0, false, 1, "inconclusive", "SKIP:"},
	{"indirect: event log unreadable", indirectStep, "Enabled", "Running", false, 0, false, 1, "inconclusive", "SKIP:"},
	{"indirect: AppIDSvc stopped", indirectStep, "Enabled", "Stopped", true, 0, false, 1, "not_applicable", "SKIP:"},
	{"indirect: ambiguous (two block events)", indirectStep, "Enabled", "Running", true, 2, false, 1, "inconclusive", "SKIP:"},
	{"alternate: renamed copy blocked, one event", altStep, "Enabled", "Running", true, 1, false, 1, "blocked_as_expected", "PASS:"},
	{"alternate: block event but Exe not Enabled", altStep, "NotConfigured", "Running", true, 1, false, 1, "inconclusive", "SKIP:"},
	{"alternate: renamed copy executed", altStep, "Enabled", "Running", true, 0, true, 0, "allowed_unexpectedly", "FAIL:"},
}


// TestAppControlBehavioral_OutcomeFromObservations drives the shipped
// behavioral step text through each controlled observation and checks the
// structured outcome and the verdict prefix the scoring path reads.
func TestAppControlBehavioral_OutcomeFromObservations(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral step is Windows PowerShell")
	}
	steps := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	for _, fx := range behavioralFixtures {
		t.Run(fx.name, func(t *testing.T) {
			command := loadStepCommand(t, steps, fx.step)
			out := runPosturePowerShell(t, behavioralPrelude(fx)+"\n"+command)
			if !strings.Contains(out, "APPCTL_OUTCOME: "+fx.wantOutcome) {
				t.Fatalf("want APPCTL_OUTCOME: %s\n%s", fx.wantOutcome, out)
			}
			if !strings.Contains(out, fx.wantPrefix) {
				t.Fatalf("want verdict prefix %s\n%s", fx.wantPrefix, out)
			}
			if strings.Count(out, "APPCTL_OUTCOME:") != 1 {
				t.Fatalf("expected exactly one APPCTL_OUTCOME line\n%s", out)
			}
		})
	}
}

// TestAppControlBehavioral_EveryStepEmitsStructuredOutcome is the static
// acceptance check: every behavioral step must declare the outcome marker,
// so no behavioral result can reach scoring as an unstructured verdict.
func TestAppControlBehavioral_EveryStepEmitsStructuredOutcome(t *testing.T) {
	steps := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	for _, name := range []string{indirectStep, altStep} {
		cmd := loadStepCommand(t, steps, name)
		if !strings.Contains(cmd, "APPCTL_OUTCOME:") {
			t.Errorf("step %q does not emit an APPCTL_OUTCOME line", name)
		}
		if !strings.Contains(cmd, "APPCTL_EVIDENCE:") {
			t.Errorf("step %q does not emit APPCTL_EVIDENCE", name)
		}
	}
}

func behavioralPrelude(fx behavioralFixture) string {
	eventPath := ""
	if fx.step == indirectStep {
		eventPath = `C:\` + psPath
	}
	ran := "$false"
	if fx.ran {
		ran = "$true"
	}
	logOK := "$false"
	if fx.logReadable {
		logOK = "$true"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "$global:BasExit = %d; $global:BasRan = %s; $global:BasAttr = %d; $global:BasLogOK = %s; $global:BasEventPath = '%s'\n",
		fx.exit, ran, fx.attr, logOK, eventPath)
	fmt.Fprintf(&b, "function Get-Service { [CmdletBinding()] param([string]$Name) [pscustomobject]@{ Name = $Name; Status = '%s' } }\n", fx.appIDState)
	fmt.Fprintf(&b, "function Get-AppLockerPolicy { [CmdletBinding()] param([switch]$Effective) [pscustomobject]@{ RuleCollections = @([pscustomobject]@{ RuleCollectionType = 'Exe'; EnforcementMode = '%s'; Count = 1 }) } }\n", fx.exeMode)
	b.WriteString("function Get-CimInstance { throw 'no WDAC in fixture' }\n")
	b.WriteString(`function Get-WinEvent { [CmdletBinding()] param($FilterHashtable)
  if (-not $global:BasLogOK) { throw 'channel disabled' }
  if ($global:BasAttr -gt 0) { 1..$global:BasAttr | ForEach-Object { [pscustomobject]@{ Message = "Blocked: $global:BasEventPath" } } }
}
`)
	b.WriteString(`function Start-Process { [CmdletBinding()] param($FilePath, $ArgumentList, $WindowStyle, [switch]$PassThru, [switch]$Wait, $RedirectStandardOutput)
  $global:BasCaptured = [regex]::Match([string]$ArgumentList, 'BAS-SIM-APPCTL-[0-9a-f]+').Value
  [pscustomobject]@{ ExitCode = $global:BasExit }
}
`)
	b.WriteString(`function Get-Content { [CmdletBinding()] param($Path) if ($global:BasRan) { $global:BasCaptured } else { '' } }
`)
	b.WriteString(`function Copy-Item { [CmdletBinding()] param($Path, $Destination, [switch]$Force) $global:BasEventPath = [string]$Destination }
`)
	return b.String()
}
