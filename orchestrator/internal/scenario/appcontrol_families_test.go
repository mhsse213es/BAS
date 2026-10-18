package scenario

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// familyFixture is one controlled observation for a V2 path family. The
// shipped step text runs unmodified; only the cmdlets that touch AppLocker,
// Defender, services, the event log, the file system, and processes are
// stubbed, so nothing real is launched and no policy is changed.
type familyFixture struct {
	name           string
	step           string // step name prefix
	rcType         string // AppLocker collection the step reads
	mode           string // enforcement mode of that collection
	appIDState     string // Running or Stopped (AppLocker control)
	logOK          bool   // event log readable
	attr           int    // matching block events
	ran            bool   // marker reached stdout
	sysmon         bool   // Sysmon recorded the attempt
	pwsh           string // pwsh.exe path, or "" when not installed
	noDefender     bool   // Get-MpPreference unavailable
	asrAction      int    // ASR rule action (1 block, 2 audit); 0 = not configured
	wantFamily     string // APPCTL_FAMILY value
	wantOutcome    string // APPCTL_OUTCOME value
	wantPrefix     string // PASS:, FAIL:, or SKIP:
	wantVisibility string // APPCTL_DETECTION result
}

const asrOfficeChildRule = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"

var familyFixtures = []familyFixture{
	// script_host_proxy
	{name: "script host: blocked, one block event, Sysmon visible", step: "Application control script host proxy",
		rcType: "Script", mode: "Enabled", appIDState: "Running", logOK: true, attr: 1, sysmon: true,
		wantFamily: "script_host_proxy", wantOutcome: "blocked_as_expected", wantPrefix: "PASS:", wantVisibility: "visible"},
	{name: "script host: executed under Enabled Script rules", step: "Application control script host proxy",
		rcType: "Script", mode: "Enabled", appIDState: "Running", logOK: true, ran: true, sysmon: true,
		wantFamily: "script_host_proxy", wantOutcome: "allowed_unexpectedly", wantPrefix: "FAIL:", wantVisibility: "visible"},
	{name: "script host: executed under audit-only Script rules", step: "Application control script host proxy",
		rcType: "Script", mode: "AuditOnly", appIDState: "Running", logOK: true, ran: true,
		wantFamily: "script_host_proxy", wantOutcome: "not_enforced", wantPrefix: "FAIL:", wantVisibility: "not_visible"},
	{name: "script host: not executed, no block event", step: "Application control script host proxy",
		rcType: "Script", mode: "Enabled", appIDState: "Running", logOK: true,
		wantFamily: "script_host_proxy", wantOutcome: "inconclusive", wantPrefix: "SKIP:", wantVisibility: "not_visible"},
	{name: "script host: AppIDSvc stopped", step: "Application control script host proxy",
		rcType: "Script", mode: "Enabled", appIDState: "Stopped", logOK: true,
		wantFamily: "script_host_proxy", wantOutcome: "not_applicable", wantPrefix: "SKIP:", wantVisibility: "not_visible"},
	{name: "script host: event log unreadable", step: "Application control script host proxy",
		rcType: "Script", mode: "Enabled", appIDState: "Running", logOK: false,
		wantFamily: "script_host_proxy", wantOutcome: "inconclusive", wantPrefix: "SKIP:", wantVisibility: "not_visible"},

	// alternate_ps_host
	{name: "pwsh: not installed on this host", step: "Application control alternate PowerShell host",
		rcType: "Exe", mode: "Enabled", appIDState: "Running", logOK: true,
		wantFamily: "alternate_ps_host", wantOutcome: "not_applicable", wantPrefix: "SKIP:", wantVisibility: "unknown"},
	{name: "pwsh: installed, blocked, one block event", step: "Application control alternate PowerShell host",
		rcType: "Exe", mode: "Enabled", appIDState: "Running", logOK: true, attr: 1, pwsh: `C:\Program Files\PowerShell\7\pwsh.exe`, sysmon: true,
		wantFamily: "alternate_ps_host", wantOutcome: "blocked_as_expected", wantPrefix: "PASS:", wantVisibility: "visible"},
	{name: "pwsh: installed and executed under Enabled Exe rules", step: "Application control alternate PowerShell host",
		rcType: "Exe", mode: "Enabled", appIDState: "Running", logOK: true, ran: true, pwsh: `C:\Program Files\PowerShell\7\pwsh.exe`,
		wantFamily: "alternate_ps_host", wantOutcome: "allowed_unexpectedly", wantPrefix: "FAIL:", wantVisibility: "not_visible"},

	// parent_child_asr
	{name: "ASR: Block mode, child blocked, one ASR event", step: "Application control parent-child ASR",
		asrAction: 1, attr: 1, logOK: true, sysmon: true,
		wantFamily: "parent_child_asr", wantOutcome: "blocked_as_expected", wantPrefix: "PASS:", wantVisibility: "visible"},
	{name: "ASR: audit mode, child executed", step: "Application control parent-child ASR",
		asrAction: 2, ran: true, logOK: true,
		wantFamily: "parent_child_asr", wantOutcome: "not_enforced", wantPrefix: "FAIL:", wantVisibility: "not_visible"},
	{name: "ASR: Block mode but child executed", step: "Application control parent-child ASR",
		asrAction: 1, ran: true, logOK: true,
		wantFamily: "parent_child_asr", wantOutcome: "allowed_unexpectedly", wantPrefix: "FAIL:", wantVisibility: "not_visible"},
	{name: "ASR: Defender preferences unavailable", step: "Application control parent-child ASR",
		noDefender: true,
		wantFamily: "parent_child_asr", wantOutcome: "not_applicable", wantPrefix: "SKIP:", wantVisibility: "unknown"},
}

// familyPrelude defines every stub a V2 step can reach. Globals use the
// Bas prefix so they never collide with the step's own local variables.
func familyPrelude(fx familyFixture) string {
	b := func(v bool) string {
		if v {
			return "$true"
		}
		return "$false"
	}
	var s strings.Builder
	fmt.Fprintf(&s, "$global:BasRan = %s; $global:BasAttr = %d; $global:BasLogOK = %s; $global:BasSysmon = %s\n",
		b(fx.ran), fx.attr, b(fx.logOK), b(fx.sysmon))
	s.WriteString("$global:BasExit = 1; $global:BasCaptured = ''; $global:BasEventPath = ''\n")
	fmt.Fprintf(&s, "$global:BasRcType = '%s'; $global:BasMode = '%s'; $global:BasAppId = '%s'\n", fx.rcType, fx.mode, fx.appIDState)
	fmt.Fprintf(&s, "$global:BasPwsh = '%s'; $global:BasNoDefender = %s\n", fx.pwsh, b(fx.noDefender))
	// The block event names the resolved binary, as a real AppLocker event does.
	fmt.Fprintf(&s, "$global:BasEventPath = '%s'\n", fx.pwsh)
	if fx.asrAction == 0 {
		s.WriteString("$global:BasAsrId = 'FFFFFFFF-0000-0000-0000-000000000000'; $global:BasAsrAct = 0\n")
	} else {
		fmt.Fprintf(&s, "$global:BasAsrId = '%s'; $global:BasAsrAct = %d\n", asrOfficeChildRule, fx.asrAction)
	}
	s.WriteString(familyStubs)
	return s.String()
}

const familyStubs = `function Get-Service { [CmdletBinding()] param([string]$Name) [pscustomobject]@{ Name = $Name; Status = $global:BasAppId } }
function Get-AppLockerPolicy { [CmdletBinding()] param([switch]$Effective) [pscustomobject]@{ RuleCollections = @([pscustomobject]@{ RuleCollectionType = $global:BasRcType; EnforcementMode = $global:BasMode; Count = 1 }) } }
function Get-MpPreference { [CmdletBinding()] param() if ($global:BasNoDefender) { return $null }; [pscustomobject]@{ AttackSurfaceReductionRules_Ids = @($global:BasAsrId); AttackSurfaceReductionRules_Actions = @($global:BasAsrAct) } }
function Get-Command { [CmdletBinding()] param($Name) if ($global:BasPwsh) { [pscustomobject]@{ Source = $global:BasPwsh } } }
function New-Item { [CmdletBinding()] param($ItemType, $Path, [switch]$Force) }
function Set-Content { [CmdletBinding()] param($Path, $Value) $global:BasCaptured = [regex]::Match([string]$Value, 'BAS-SIM-APPCTL-[0-9a-f]+').Value; $global:BasEventPath = [string]$Path }
function Copy-Item { [CmdletBinding()] param($Path, $Destination, [switch]$Force) $global:BasEventPath = [string]$Destination }
function Start-Process { [CmdletBinding()] param($FilePath, $ArgumentList, $WindowStyle, [switch]$PassThru, [switch]$Wait, $RedirectStandardOutput)
  $m = [regex]::Match([string]$ArgumentList, 'BAS-SIM-APPCTL-[0-9a-f]+').Value
  if ($m) { $global:BasCaptured = $m }
  if ([string]$FilePath -like '*pwsh*') { $global:BasEventPath = [string]$FilePath }
  [pscustomobject]@{ ExitCode = $global:BasExit }
}
function Get-Content { [CmdletBinding()] param($Path) if ($global:BasRan) { $global:BasCaptured } else { '' } }
function Get-WinEvent { [CmdletBinding()] param($FilterHashtable)
  $log = [string]$FilterHashtable.LogName
  if ($log -like '*Sysmon*') { if ($global:BasSysmon) { return [pscustomobject]@{ Message = $global:BasCaptured } }; return @() }
  if (-not $global:BasLogOK) { throw 'channel disabled' }
  if ($global:BasAttr -gt 0) { 1..$global:BasAttr | ForEach-Object { [pscustomobject]@{ Message = "Blocked: $global:BasEventPath $global:BasCaptured" } } }
}
`

func TestAppControlFamilies_ShippedStepsResolveAndDeclareFamily(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	for _, fx := range familyFixtures {
		t.Run(fx.name, func(t *testing.T) {
			command := loadStepCommand(t, path, fx.step)
			out := runPosturePowerShell(t, familyPrelude(fx)+"\n"+command)
			if !strings.Contains(out, "APPCTL_FAMILY: "+fx.wantFamily) {
				t.Errorf("want APPCTL_FAMILY: %s\n%s", fx.wantFamily, out)
			}
			if !strings.Contains(out, "APPCTL_OUTCOME: "+fx.wantOutcome) {
				t.Errorf("want APPCTL_OUTCOME: %s\n%s", fx.wantOutcome, out)
			}
			if !strings.Contains(out, fx.wantPrefix) {
				t.Errorf("want verdict prefix %s\n%s", fx.wantPrefix, out)
			}
			if !strings.Contains(out, "result="+fx.wantVisibility) {
				t.Errorf("want APPCTL_DETECTION result=%s\n%s", fx.wantVisibility, out)
			}
			if strings.Count(out, "APPCTL_OUTCOME:") != 1 {
				t.Errorf("expected exactly one APPCTL_OUTCOME line\n%s", out)
			}
			if fx.wantPrefix != "PASS:" && strings.Contains(out, "PASS:") {
				t.Errorf("non-pass fixture emitted PASS:\n%s", out)
			}
		})
	}
}

// Every V2 family must be declared in the shipped YAML with its family marker
// and detection line, so no path reaches the matrix without them.
func TestAppControlFamilies_EveryStepDeclaresFamilyAndDetection(t *testing.T) {
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	want := map[string]string{
		"Application control indirect execution":   "indirect_execution",
		"Application control alternate binary":     "alternate_binary",
		"Application control script host proxy":    "script_host_proxy",
		"Application control alternate PowerShell": "alternate_ps_host",
		"Application control parent-child ASR":     "parent_child_asr",
	}
	for prefix, family := range want {
		cmd := loadStepCommand(t, path, prefix)
		if !strings.Contains(cmd, "APPCTL_FAMILY: "+family) {
			t.Errorf("step %q does not declare APPCTL_FAMILY: %s", prefix, family)
		}
		if !strings.Contains(cmd, "APPCTL_DETECTION:") {
			t.Errorf("step %q does not report APPCTL_DETECTION", prefix)
		}
	}
}
