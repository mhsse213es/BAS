package scenario

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// lolbinPostureCommon stubs every cmdlet the posture tier reads. Each case
// sets the $global:BasLb* observations it needs; the command text is the
// shipped step, unmodified.
const lolbinPostureCommon = `
function Get-AppLockerPolicy { [CmdletBinding()] param([switch]$Effective)
  [pscustomobject]@{ RuleCollections = @([pscustomobject]@{ RuleCollectionType = 'Script'; EnforcementMode = $global:BasLbScript; Count = 1 }) }
}
function Get-ItemProperty { [CmdletBinding()] param($Path, $Name)
  if ($Path -like '*ScriptBlockLogging*') { $v = $global:BasLbScriptBlock } else { $v = $global:BasLbWsh }
  if ($null -eq $v) { return $null }
  [pscustomobject]@{ $Name = $v }
}
function Get-Service { [CmdletBinding()] param([string]$Name)
  if ($Name -eq 'WinRM') { return [pscustomobject]@{ Name = $Name; Status = $global:BasLbWinRM } }
  if ($Name -eq 'PSEXESVC' -and $global:BasLbPsexec) { return [pscustomobject]@{ Name = $Name; Status = $global:BasLbPsexec } }
  return $null
}
function Get-MpPreference { [CmdletBinding()] param()
  if ($global:BasLbNoDefender) { return $null }
  [pscustomobject]@{
    AttackSurfaceReductionRules_Ids = @($global:BasLbAsrId)
    AttackSurfaceReductionRules_Actions = @($global:BasLbAsrAct)
  }
}
`

type lolbinPostureCase struct {
	name       string
	step       string // step name prefix
	setup      string // $global:BasLb* assignments
	wantPrefix string
}

const asrRule = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"

var lolbinPostureCases = []lolbinPostureCase{
	{"script rules enforced", "LOLBin exposure: script interpreters",
		"$global:BasLbScript = 'Enabled'", "PASS:"},
	{"script rules audit-only", "LOLBin exposure: script interpreters",
		"$global:BasLbScript = 'AuditOnly'", "FAIL:"},

	{"ScriptBlock logging on", "Logging & detection: PowerShell ScriptBlock",
		"$global:BasLbScriptBlock = 1", "PASS:"},
	{"ScriptBlock logging absent", "Logging & detection: PowerShell ScriptBlock",
		"$global:BasLbScriptBlock = $null", "FAIL:"},

	{"no remote execution service running", "Execution surface",
		"$global:BasLbWinRM = 'Stopped'; $global:BasLbPsexec = $null", "PASS:"},
	{"WinRM running", "Execution surface",
		"$global:BasLbWinRM = 'Running'; $global:BasLbPsexec = $null", "FAIL:"},

	{"WSH disabled", "LOLBin integrity: Windows Script Host",
		"$global:BasLbWsh = 0", "PASS:"},
	{"WSH enabled by default", "LOLBin integrity: Windows Script Host",
		"$global:BasLbWsh = $null", "FAIL:"},

	{"Office child-process ASR in Block mode", "Parent-child protection",
		"$global:BasLbNoDefender = $false; $global:BasLbAsrId = '" + asrRule + "'; $global:BasLbAsrAct = 1", "PASS:"},
	{"Office child-process ASR in audit mode", "Parent-child protection",
		"$global:BasLbNoDefender = $false; $global:BasLbAsrId = '" + asrRule + "'; $global:BasLbAsrAct = 2", "FAIL:"},
	{"Office child-process ASR not configured", "Parent-child protection",
		"$global:BasLbNoDefender = $false; $global:BasLbAsrId = 'FFFFFFFF-0000-0000-0000-000000000000'; $global:BasLbAsrAct = 1", "FAIL:"},
	{"Defender preferences unavailable", "Parent-child protection",
		"$global:BasLbNoDefender = $true", "SKIP:"},
}

// TestLOLBinPostureTier_ShippedStepsReportState runs each posture step's
// shipped command against controlled observations and checks the verdict
// prefix. A posture step must never PASS on an unreadable or absent state.
func TestLOLBinPostureTier_ShippedStepsReportState(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("posture script is Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "lolbin-execution-coverage.yaml")
	for _, c := range lolbinPostureCases {
		t.Run(c.name, func(t *testing.T) {
			command := loadStepCommand(t, path, c.step)
			out := runPosturePowerShell(t, lolbinPostureCommon+"\n"+c.setup+"\n"+command)
			if !strings.Contains(out, c.wantPrefix) {
				t.Fatalf("want %s\n%s", c.wantPrefix, out)
			}
			if c.wantPrefix != "PASS:" && strings.Contains(out, "PASS:") {
				t.Fatalf("non-pass fixture emitted PASS:\n%s", out)
			}
		})
	}
}
