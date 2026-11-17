package scenario

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// masteryFixture is one controlled observation of the shared oracle. The
// shipped step text runs unmodified; only the cmdlets that read policy, logs
// and processes are stubbed, so nothing real is launched and no policy changes.
type masteryFixture struct {
	name         string
	alMode       string // AppLocker enforcement mode for every collection
	alSvc        string // Running or Stopped
	alReadable   bool
	wdUmci       int // 0 none, 1 audit, 2 enforced, -1 unreadable
	logOK        bool
	ran          bool
	blkAl, blkWd int
	audAl, audWd int
	wantOutcome  string
	wantPrefix   string
}

var masteryFixtures = []masteryFixture{
	{name: "AppLocker enforced, one block event", alMode: "Enabled", alSvc: "Running", alReadable: true, wdUmci: 0, logOK: true, blkAl: 1, wantOutcome: "blocked_as_expected", wantPrefix: "PASS:"},
	{name: "WDAC enforced, one block event", alMode: "NotConfigured", alSvc: "Running", alReadable: true, wdUmci: 2, logOK: true, blkWd: 1, wantOutcome: "blocked_as_expected", wantPrefix: "PASS:"},
	{name: "AppLocker enforced but it ran", alMode: "Enabled", alSvc: "Running", alReadable: true, wdUmci: 0, logOK: true, ran: true, wantOutcome: "allowed_unexpectedly", wantPrefix: "FAIL:"},
	{name: "WDAC enforced but it ran", alMode: "NotConfigured", alSvc: "Stopped", alReadable: true, wdUmci: 2, logOK: true, ran: true, wantOutcome: "allowed_unexpectedly", wantPrefix: "FAIL:"},
	{name: "audit mode: ran and recorded is not prevention", alMode: "AuditOnly", alSvc: "Running", alReadable: true, wdUmci: 0, logOK: true, ran: true, audAl: 1, wantOutcome: "audited_only", wantPrefix: "FAIL:"},
	{name: "WDAC audit mode: ran", alMode: "NotConfigured", alSvc: "Stopped", alReadable: true, wdUmci: 1, logOK: true, ran: true, audWd: 1, wantOutcome: "audited_only", wantPrefix: "FAIL:"},
	{name: "no enforcement configured, ran", alMode: "NotConfigured", alSvc: "Running", alReadable: true, wdUmci: 0, logOK: true, ran: true, wantOutcome: "not_enforced", wantPrefix: "FAIL:"},
	{name: "not executed but no event is inconclusive", alMode: "Enabled", alSvc: "Running", alReadable: true, wdUmci: 0, logOK: true, wantOutcome: "inconclusive", wantPrefix: "SKIP:"},
	{name: "two block events cannot be attributed", alMode: "Enabled", alSvc: "Running", alReadable: true, wdUmci: 0, logOK: true, blkAl: 2, wantOutcome: "inconclusive", wantPrefix: "SKIP:"},
	{name: "not executed, nothing enforcing, is not a pass", alMode: "NotConfigured", alSvc: "Running", alReadable: true, wdUmci: 0, logOK: true, blkAl: 1, wantOutcome: "inconclusive", wantPrefix: "SKIP:"},
	{name: "no mechanism available", alMode: "Enabled", alSvc: "Stopped", alReadable: false, wdUmci: -1, logOK: true, wantOutcome: "not_applicable", wantPrefix: "SKIP:"},
	{name: "event log unreadable", alMode: "Enabled", alSvc: "Running", alReadable: true, wdUmci: 0, logOK: false, wantOutcome: "inconclusive", wantPrefix: "SKIP:"},
}

func masteryPrelude(fx masteryFixture) string {
	b := func(v bool) string {
		if v {
			return "$true"
		}
		return "$false"
	}
	var s strings.Builder
	fmt.Fprintf(&s, "$global:BasRan = %s; $global:BasLogOK = %s; $global:BasAlMode = '%s'; $global:BasAlSvc = '%s'; $global:BasAlReadable = %s; $global:BasWd = %d\n",
		b(fx.ran), b(fx.logOK), fx.alMode, fx.alSvc, b(fx.alReadable), fx.wdUmci)
	fmt.Fprintf(&s, "$global:BlkAl = %d; $global:BlkWd = %d; $global:AudAl = %d; $global:AudWd = %d\n", fx.blkAl, fx.blkWd, fx.audAl, fx.audWd)
	s.WriteString(masteryStubs)
	return s.String()
}

const masteryStubs = `function Get-Service { [CmdletBinding()] param([string]$Name) [pscustomobject]@{ Name = $Name; Status = $global:BasAlSvc } }
function Get-AppLockerPolicy { [CmdletBinding()] param([switch]$Effective) if (-not $global:BasAlReadable) { throw 'AppLocker is not available' }; [pscustomobject]@{ RuleCollections = @('Exe','Script','Dll','Msi' | ForEach-Object { [pscustomobject]@{ RuleCollectionType = $_; EnforcementMode = $global:BasAlMode } }) } }
function Get-CimInstance { [CmdletBinding()] param($Namespace, $ClassName) if ($global:BasWd -lt 0) { throw 'DeviceGuard class unavailable' }; [pscustomobject]@{ UsermodeCodeIntegrityPolicyEnforcementStatus = $global:BasWd; CodeIntegrityPolicyEnforcementStatus = 0 } }
function Start-Process { [CmdletBinding()] param($FilePath, $ArgumentList, $WindowStyle, [switch]$PassThru, [switch]$Wait)
  $o = [pscustomobject]@{ ExitCode = 0 }
  $o | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($ms) $true }
  $o | Add-Member -MemberType ScriptMethod -Name Kill -Value { }
  $o }
function Invoke-CimMethod { [CmdletBinding()] param($ClassName, $MethodName, $Arguments) [pscustomobject]@{ ReturnValue = 0 } }
function Get-Content { [CmdletBinding()] param($Path) if ($global:BasRan) { $script:AppCtlMarker } else { '' } }
function Get-WinEvent { [CmdletBinding()] param($FilterHashtable)
  $log = [string]$FilterHashtable.LogName; $id = [int]$FilterHashtable.Id
  if ($log -like '*Sysmon*') { return @() }
  if (-not $global:BasLogOK) { throw 'channel disabled' }
  $n = 0
  if ($id -in 8004, 8007) { $n = $global:BlkAl } elseif ($id -in 3077, 8029) { $n = $global:BlkWd } elseif ($id -in 8003, 8006) { $n = $global:AudAl } elseif ($id -in 3076, 8028) { $n = $global:AudWd }
  if ($n -gt 0) { return (1..$n | ForEach-Object { [pscustomobject]@{ Message = $(if ($global:BasName) { '%OSDRIVE%\USERS\X\APPDATA\LOCAL\TEMP\' + $global:BasName.Replace('{tid8}', $script:AppCtlTid.Substring(0,8)) + ' was prevented from running.' } else { 'Blocked regsvr32.exe mshta.exe cmstp.exe rundll32.exe wmic.exe MSBuild.exe InstallUtil.exe cmd.exe' }) } }) }
  # A real Get-WinEvent throws when the filter matches nothing; that is an empty result, not an unreadable log.
  throw (New-Object Management.Automation.ErrorRecord((New-Object Exception 'No events were found that match the specified selection criteria.'), 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', [Management.Automation.ErrorCategory]::ObjectNotFound, $null))
}
`

// masterySteps lists the steps exercised against fixtures. full runs every
// fixture; the rest run the four that distinguish the verdict classes.
var masterySteps = []struct {
	file, step string
	full       bool
	// name, when set, is the only text a block event carries: a real AppLocker or WDAC
	// script-block event names the script file, not the host executable.
	name string
}{
	{"appcontrol-proxy-execution.yaml", "Application control Trusted Binary Proxy: Regsvr32", true, ""},
	{"appcontrol-proxy-execution.yaml", "Application control Trusted Binary Proxy: Mshta", true, ""},
	{"appcontrol-proxy-execution.yaml", "Application control Trusted Binary Proxy: CMSTP", false, ""},
	{"appcontrol-script-interpreter.yaml", "Application control Script Host: wscript.exe", true, "bas_{tid8}.vbs"},
	{"appcontrol-script-interpreter.yaml", "Application control Script Host: cmd.exe batch", false, "bas_{tid8}.bat"},
	{"appcontrol-script-interpreter.yaml", "Application control Script Host: Windows Script File", false, "bas_{tid8}.wsf"},
	{"appcontrol-script-interpreter.yaml", "Application control Script Host: JScript", false, "bas_{tid8}.js"},
	{"appcontrol-script-interpreter.yaml", "Application control PowerShell: unsigned script", false, "bas_{tid8}.ps1"},
	{"appcontrol-script-interpreter.yaml", "Application control WMI: Win32_Process.Create", false, ""},
}

var masteryCore = map[string]bool{
	"AppLocker enforced, one block event": true, "AppLocker enforced but it ran": true,
	"audit mode: ran and recorded is not prevention": true, "not executed but no event is inconclusive": true,
}

func TestAppControlMastery_LibraryDecisionTable(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("oracle is Windows PowerShell")
	}
	lib, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios-src", "appcontrol-common", "lib.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	table := `function M($n,$a,$m,$b,$u,$r=$true){ @{Name=$n;Available=$a;Mode=$m;Block=$b;Audit=$u;Readable=$r} }
$cases = @(
 @('blocked 1 evt AL','blocked',$false,@((M 'applocker' $true 'Enabled' 1 0)),$true,'blocked_as_expected'),
 @('blocked by WDAC only','blocked',$false,@((M 'applocker' $true 'NotConfigured' 0 0),(M 'wdac' $true 'Enabled' 1 0)),$true,'blocked_as_expected'),
 @('no event','blocked',$false,@((M 'applocker' $true 'Enabled' 0 0)),$true,'inconclusive'),
 @('2 events','blocked',$false,@((M 'applocker' $true 'Enabled' 2 0)),$true,'inconclusive'),
 @('not enabled, absence unattributable','blocked',$false,@((M 'applocker' $true 'NotConfigured' 0 0)),$true,'inconclusive'),
 @('audit only, no block event','blocked',$false,@((M 'applocker' $true 'AuditOnly' 0 1)),$true,'inconclusive'),
 @('ran, Enabled','blocked',$true,@((M 'applocker' $true 'Enabled' 0 0)),$true,'allowed_unexpectedly'),
 @('ran, WDAC Enabled only','blocked',$true,@((M 'applocker' $true 'NotConfigured' 0 0),(M 'wdac' $true 'Enabled' 0 0)),$true,'allowed_unexpectedly'),
 @('ran, audit records event','blocked',$true,@((M 'applocker' $true 'AuditOnly' 0 1)),$true,'audited_only'),
 @('ran, audit no event','blocked',$true,@((M 'wdac' $true 'AuditOnly' 0 0)),$true,'audited_only'),
 @('ran, not configured','blocked',$true,@((M 'applocker' $true 'NotConfigured' 0 0)),$true,'not_enforced'),
 @('ran, expected allowed','allowed',$true,@((M 'applocker' $true 'Enabled' 0 0)),$true,'allowed_by_policy'),
 @('not ran, expected allowed','allowed',$false,@((M 'applocker' $true 'Enabled' 1 0)),$true,'inconclusive'),
 @('no mechanism available','blocked',$false,@((M 'applocker' $false 'Enabled' 1 0),(M 'wdac' $false 'Enabled' 1 0)),$true,'not_applicable'),
 @('build below floor','blocked',$false,@((M 'applocker' $true 'Enabled' 1 0)),$false,'not_applicable'),
 @('log unreadable','blocked',$false,@((M 'applocker' $true 'Enabled' 0 0 $false)),$true,'inconclusive'),
 @('ran with unreadable log still fails','blocked',$true,@((M 'applocker' $true 'Enabled' 0 0 $false)),$true,'allowed_unexpectedly'),
 @('one mechanism unavailable, other blocks','blocked',$false,@((M 'applocker' $false 'Enabled' 0 0),(M 'wdac' $true 'Enabled' 1 0)),$true,'blocked_as_expected')
)
$cc = @(
 @('constrained under Enabled','blocked',$false,@((M 'applocker' $true 'Enabled' 0 0)),$true,$true,'blocked_as_expected'),
 @('constrained but nothing Enabled is not a block','blocked',$false,@((M 'applocker' $true 'NotConfigured' 0 0)),$true,$true,'inconclusive'),
 @('constrained flag cannot rescue a run that executed','blocked',$true,@((M 'applocker' $true 'Enabled' 0 0)),$true,$true,'allowed_unexpectedly')
)
foreach ($c in $cc) { $r = Resolve-AppCtlOutcome -Expected $c[1] -Ran $c[2] -Mechs $c[3] -BuildOk $c[4] -Constrained $c[5]; if ($r.Outcome -ne $c[6]) { "BAD $($c[0]) want=$($c[6]) got=$($r.Outcome)" } }
foreach ($c in $cases) { $r = Resolve-AppCtlOutcome -Expected $c[1] -Ran $c[2] -Mechs $c[3] -BuildOk $c[4]; if ($r.Outcome -ne $c[5]) { "BAD $($c[0]) want=$($c[5]) got=$($r.Outcome)" } }
'TABLE_DONE'`
	out := runPosturePowerShell(t, string(lib)+"\n"+table)
	if !strings.Contains(out, "TABLE_DONE") || strings.Contains(out, "BAD ") {
		t.Fatalf("decision table failed:\n%s", out)
	}
}

func namePrelude(name string) string {
	if name == "" {
		return "$global:BasName = $null\n"
	}
	return "$global:BasName = '" + name + "'\n"
}

func TestAppControlMastery_ProxyStepsResolveAgainstFixtures(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	for _, ms := range masterySteps {
		path := filepath.Join("..", "..", "..", "scenarios", ms.file)
		for _, fx := range masteryFixtures {
			if !ms.full && !masteryCore[fx.name] {
				continue
			}
			t.Run(ms.step+"/"+fx.name, func(t *testing.T) {
				out := runPosturePowerShell(t, masteryPrelude(fx)+"\n"+namePrelude(ms.name)+loadStepCommand(t, path, ms.step))
				if !strings.Contains(out, "APPCTL_OUTCOME: "+fx.wantOutcome) {
					t.Errorf("want APPCTL_OUTCOME: %s\n%s", fx.wantOutcome, out)
				}
				if !strings.Contains(out, fx.wantPrefix) {
					t.Errorf("want verdict prefix %s\n%s", fx.wantPrefix, out)
				}
				if strings.Count(out, "APPCTL_OUTCOME:") != 1 {
					t.Errorf("expected exactly one APPCTL_OUTCOME line\n%s", out)
				}
				if fx.wantPrefix != "PASS:" && strings.Contains(out, "PASS:") {
					t.Errorf("non-pass fixture emitted PASS:\n%s", out)
				}
				if !strings.Contains(out, "cleanup_verified=True") {
					t.Errorf("cleanup was not verified\n%s", out)
				}
			})
		}
	}
}

// Every mastery scenario must be well formed: parseable, on the av product
// line, every step declares a family, emits one outcome line, calls the
// shared oracle, and is plain ASCII so the agent needs no BOM handling.
func TestAppControlMastery_EveryStepWellFormed(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "scenarios", "appcontrol-*.yaml"))
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "appcontrol-efficacy.yaml") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			ProductLine string `yaml:"product_line"`
			Steps       []struct {
				ID      string `yaml:"id"`
				Name    string `yaml:"name"`
				Tech    string `yaml:"technique_id"`
				Command string `yaml:"command"`
				Cleanup string `yaml:"cleanup"`
			} `yaml:"steps"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if doc.ProductLine != "av" {
			t.Errorf("%s: product_line = %q, want av", f, doc.ProductLine)
		}
		for _, s := range doc.Steps {
			checked++
			for _, want := range []string{"Invoke-AppCtlTest", "APPCTL_FAMILY:", "APPCTL_OUTCOME:", "Resolve-AppCtlOutcome"} {
				if !strings.Contains(s.Command, want) {
					t.Errorf("%s %s: command lacks %q", filepath.Base(f), s.ID, want)
				}
			}
			if strings.TrimSpace(s.Cleanup) == "" {
				t.Errorf("%s %s: no cleanup", filepath.Base(f), s.ID)
			}
			for _, r := range s.Command {
				if r > 126 {
					t.Errorf("%s %s: non-ASCII character in command", filepath.Base(f), s.ID)
					break
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no mastery steps found")
	}
}

// The language-mode step reads the marker output, so its fixtures stub the
// script output itself rather than a bare marker.
func TestAppControlMastery_LanguageModeStep(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-script-interpreter.yaml")
	step := "Application control PowerShell: language mode"
	cases := []struct {
		name, content, mode, wantOutcome, wantPrefix string
	}{
		{"constrained under enforced policy is prevented", "mode=ConstrainedLanguage fulllang=False", "Enabled", "blocked_as_expected", "PASS:"},
		{"full language under enforced policy is a failure", "mode=FullLanguage fulllang=True", "Enabled", "allowed_unexpectedly", "FAIL:"},
		{"full language with no enforcement is not enforced", "mode=FullLanguage fulllang=True", "NotConfigured", "not_enforced", "FAIL:"},
		{"constrained without an enforcing policy cannot be attributed", "mode=ConstrainedLanguage fulllang=False", "NotConfigured", "inconclusive", "SKIP:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := masteryFixture{alMode: c.mode, alSvc: "Running", alReadable: true, logOK: true}
			prelude := masteryPrelude(fx) + "\nfunction Get-Content { [CmdletBinding()] param($Path) \"$($script:AppCtlMarker) " + c.content + "\" }\n"
			out := runPosturePowerShell(t, prelude+loadStepCommand(t, path, step))
			if !strings.Contains(out, "APPCTL_OUTCOME: "+c.wantOutcome) || !strings.Contains(out, c.wantPrefix) {
				t.Errorf("want %s / %s\n%s", c.wantOutcome, c.wantPrefix, out)
			}
		})
	}
}

// Integrity steps read policy state directly. Their fixtures stub the policy
// readers so every branch, including the gated ones, is exercised without
// touching the host.
func TestAppControlMastery_PolicyIntegritySteps(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-policy-integrity.yaml")
	collections := func(modes ...string) string {
		var b strings.Builder
		b.WriteString("function Get-AppLockerPolicy { [CmdletBinding()] param([switch]$Effective, [switch]$Xml, [switch]$Local) $global:BasPolicyXml; if (-not $Xml) { [pscustomobject]@{ RuleCollections = @(@{ 'Exe' = '" + modes[0] + "'; 'Script' = '" + modes[1] + "'; 'Dll' = '" + modes[2] + "'; 'Msi' = '" + modes[3] + "' }.GetEnumerator() | Where-Object { $_.Value -ne 'NotConfigured' } | ForEach-Object { [pscustomobject]@{ RuleCollectionType = $_.Key; EnforcementMode = $_.Value } }) } } }\n")
		return b.String()
	}
	mi := func(p string) string {
		return `$global:BasPolicyXml = '<AppLockerPolicy Version="1"><RuleCollection Type="ManagedInstaller" EnforcementMode="Enabled"><FilePublisherRule Id="1" Name="mi1" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="` + p + `"/></Conditions></FilePublisherRule></RuleCollection></AppLockerPolicy>'` + "\n"
	}
	svcStub := "function Get-Service { [CmdletBinding()] param([string]$Name) [pscustomobject]@{ Name = $Name; Status = 'Running' } }\n"
	wd := func(umci int) string {
		return fmt.Sprintf("function Get-CimInstance { [CmdletBinding()] param($Namespace, $ClassName, $Filter) if ($ClassName -eq 'Win32_DeviceGuard') { [pscustomobject]@{ UsermodeCodeIntegrityPolicyEnforcementStatus = %d; CodeIntegrityPolicyEnforcementStatus = 0 } } }\n", umci)
	}
	cases := []struct {
		name, step, prelude, wantOutcome, wantPrefix string
	}{
		{"downgrade: everything enforced", "Application control Policy Integrity: audit-mode", svcStub + wd(0) + collections("Enabled", "Enabled", "Enabled", "Enabled"), "blocked_as_expected", "PASS:"},
		{"downgrade: audit mode is not prevention", "Application control Policy Integrity: audit-mode", svcStub + wd(0) + collections("AuditOnly", "Enabled", "Enabled", "Enabled"), "audited_only", "FAIL:"},
		{"downgrade: WDAC audit mode", "Application control Policy Integrity: audit-mode", svcStub + wd(1) + collections("NotConfigured", "NotConfigured", "NotConfigured", "NotConfigured"), "audited_only", "FAIL:"},
		{"downgrade: collection without rules", "Application control Policy Integrity: audit-mode", svcStub + wd(0) + collections("Enabled", "NotConfigured", "Enabled", "Enabled"), "not_enforced", "FAIL:"},
		{"downgrade: nothing configured is not a pass", "Application control Policy Integrity: audit-mode", svcStub + wd(0) + collections("NotConfigured", "NotConfigured", "NotConfigured", "NotConfigured"), "not_applicable", "SKIP:"},
		{"managed installer: user-writable path", "Application control Policy Integrity: Managed Installer", svcStub + wd(0) + collections("Enabled", "Enabled", "Enabled", "Enabled") + mi("%OSDRIVE%\\Users\\*\\AppData\\*"), "allowed_unexpectedly", "FAIL:"},
		{"managed installer: protected path", "Application control Policy Integrity: Managed Installer", svcStub + wd(0) + collections("Enabled", "Enabled", "Enabled", "Enabled") + mi("%PROGRAMFILES%\\Agent\\*"), "blocked_as_expected", "PASS:"},
		{"managed installer: none configured", "Application control Policy Integrity: Managed Installer", svcStub + wd(0) + collections("Enabled", "Enabled", "Enabled", "Enabled") + "$global:BasPolicyXml = '<AppLockerPolicy Version=\"1\"></AppLockerPolicy>'\n", "not_applicable", "SKIP:"},
		{"drift: no baseline is inconclusive", "Application control Policy Integrity: policy drift", svcStub + wd(0) + collections("Enabled", "Enabled", "Enabled", "Enabled") + "$global:BasPolicyXml = '<p/>'\n", "inconclusive", "SKIP:"},
		{"drift: different baseline", "Application control Policy Integrity: policy drift", svcStub + wd(0) + collections("Enabled", "Enabled", "Enabled", "Enabled") + "$global:BasPolicyXml = '<p/>'\n$env:BAS_APPCTL_BASELINE_SHA256 = 'deadbeef'\n", "allowed_unexpectedly", "FAIL:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := runPosturePowerShell(t, c.prelude+loadStepCommand(t, path, c.step))
			if !strings.Contains(out, "APPCTL_OUTCOME: "+c.wantOutcome) || !strings.Contains(out, c.wantPrefix) {
				t.Errorf("want %s / %s\n%s", c.wantOutcome, c.wantPrefix, out)
			}
			if strings.Count(out, "APPCTL_OUTCOME:") != 1 {
				t.Errorf("expected exactly one APPCTL_OUTCOME line\n%s", out)
			}
			if c.wantPrefix != "PASS:" && strings.Contains(out, "PASS:") {
				t.Errorf("non-pass fixture emitted PASS:\n%s", out)
			}
		})
	}
}

// With the exact baseline hash supplied, drift is absent. The hash is taken
// from the step's own output so the test cannot drift from the algorithm.
func TestAppControlMastery_DriftMatchesItsOwnBaseline(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-policy-integrity.yaml")
	step := "Application control Policy Integrity: policy drift"
	stub := "function Get-AppLockerPolicy { [CmdletBinding()] param([switch]$Effective, [switch]$Xml) '<p/>' }\nfunction Get-CimInstance { [CmdletBinding()] param($Namespace, $ClassName, $Filter) }\n"
	first := runPosturePowerShell(t, stub+loadStepCommand(t, path, step))
	i := strings.Index(first, "current_policy_sha256=")
	if i < 0 {
		t.Fatalf("no hash in output:\n%s", first)
	}
	hash := first[i+len("current_policy_sha256="):]
	hash = hash[:64]
	second := runPosturePowerShell(t, "$env:BAS_APPCTL_BASELINE_SHA256 = '"+hash+"'\n"+stub+loadStepCommand(t, path, step))
	if !strings.Contains(second, "APPCTL_OUTCOME: blocked_as_expected") || !strings.Contains(second, "PASS:") {
		t.Errorf("matching baseline must pass:\n%s", second)
	}
}

// Packaging-trust and operational-reliability steps read policy, service, log and
// registry state directly. The fixtures stub those readers so every verdict class is
// reached without touching the host.
func TestAppControlMastery_PackagingAndReliabilitySteps(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	pkgPath := filepath.Join("..", "..", "..", "scenarios", "appcontrol-packaging-trust.yaml")
	relPath := filepath.Join("..", "..", "..", "scenarios", "appcontrol-operational-reliability.yaml")
	stubs := `function Get-Service { [CmdletBinding()] param([string]$Name) [pscustomobject]@{ Name = $Name; Status = 'Running' } }
function Get-AppLockerPolicy { [CmdletBinding()] param([switch]$Effective, [switch]$Xml, [switch]$Local)
  if ($Xml) { return $global:BasPolicyXml }
  [pscustomobject]@{ RuleCollections = @($global:BasCols.GetEnumerator() | ForEach-Object { [pscustomobject]@{ RuleCollectionType = $_.Key; EnforcementMode = $_.Value } }) } }
function Get-CimInstance { [CmdletBinding()] param([Parameter(Position = 0)]$Pos, $Namespace, $ClassName, $Filter)
  $cn = if ($ClassName) { $ClassName } else { $Pos }
  if ($cn -eq 'Win32_Service') { return [pscustomobject]@{ StartMode = $global:BasSvcMode; State = $global:BasSvcState } }
  [pscustomobject]@{ UsermodeCodeIntegrityPolicyEnforcementStatus = 0; CodeIntegrityPolicyEnforcementStatus = 0 } }
function Get-Acl { [CmdletBinding()] param($LiteralPath, $Path)
  $sid = New-Object Security.Principal.SecurityIdentifier($global:BasAclSid)
  $rule = [pscustomobject]@{ AccessControlType = 'Allow'; IdentityReference = $sid; FileSystemRights = [Security.AccessControl.FileSystemRights]$global:BasAclRights }
  [pscustomobject]@{ Access = @($rule) } }
function Get-AppxPackage { [CmdletBinding()] param() @() }
function Get-ItemProperty { [CmdletBinding()] param($Path, $Name)
  $v = $null
  if ($Name -eq 'AlwaysInstallElevated') { $v = if ([string]$Path -like 'HKLM:*') { $global:BasAieMachine } else { $global:BasAieUser } }
  if ($global:BasReg -and $global:BasReg.ContainsKey("$Path|$Name")) { $v = $global:BasReg["$Path|$Name"] }
  if ($null -eq $v) { throw 'not found' }
  $o = New-Object psobject; $o | Add-Member -NotePropertyName $Name -NotePropertyValue $v; $o }
function Get-WinEvent { [CmdletBinding()] param($ListLog, $FilterHashtable)
  if ($ListLog) { return [pscustomobject]@{ IsEnabled = $global:BasLogEnabled; MaximumSizeInBytes = $global:BasLogSize } } }
`
	cols := func(m map[string]string) string {
		var b strings.Builder
		b.WriteString("$global:BasCols = @{}\n")
		for k, v := range m {
			b.WriteString("$global:BasCols['" + k + "'] = '" + v + "'\n")
		}
		return b.String()
	}
	allow := func(path string) string {
		return `$global:BasPolicyXml = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="1" Name="r1" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="` + path + `"/></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>'` + "\n"
	}
	polAppx := `HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx`
	locUnlock := `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock`
	regs := func(key, name string, v int) string {
		return fmt.Sprintf("if (-not $global:BasReg) { $global:BasReg = @{} }\n$global:BasReg['%s|%s'] = %d\n", key, name, v)
	}
	acl := func(sid, rights string) string {
		return "$global:BasAclSid = '" + sid + "'; $global:BasAclRights = '" + rights + "'\n"
	}
	exceptionPolicy := `$global:BasPolicyXml = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="1" Name="r1" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions><Exceptions><FilePathCondition Path="%OSDRIVE%\Users\*"/></Exceptions></FilePathRule></RuleCollection></AppLockerPolicy>'` + "\n"
	anyPublisherPolicy := `$global:BasPolicyXml = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePublisherRule Id="1" Name="r1" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule></RuleCollection></AppLockerPolicy>'` + "\n"
	enf := map[string]string{"Exe": "Enabled", "Script": "Enabled", "Dll": "Enabled", "Msi": "Enabled"}
	withAppx := func(m string) map[string]string {
		c := map[string]string{}
		for k, v := range enf {
			c[k] = v
		}
		if m != "" {
			c["Appx"] = m
		}
		return c
	}
	none := map[string]string{}
	cases := []struct {
		name, file, step, prelude, wantOutcome, wantPrefix string
	}{
		{"appx enforced", pkgPath, "Application control Packaged App Rules", cols(withAppx("Enabled")), "blocked_as_expected", "PASS:"},
		{"appx audit", pkgPath, "Application control Packaged App Rules", cols(withAppx("AuditOnly")), "audited_only", "FAIL:"},
		{"appx missing while others enforce", pkgPath, "Application control Packaged App Rules", cols(withAppx("")), "not_enforced", "FAIL:"},
		{"appx nothing enforced", pkgPath, "Application control Packaged App Rules", cols(none), "not_applicable", "SKIP:"},
		{"aie both on", pkgPath, "Application control Installer Trust", "$global:BasAieMachine = 1; $global:BasAieUser = 1\n", "allowed_unexpectedly", "FAIL:"},
		{"aie machine only", pkgPath, "Application control Installer Trust", "$global:BasAieMachine = 1\n", "blocked_as_expected", "PASS:"},
		{"aie unset", pkgPath, "Application control Installer Trust", "", "blocked_as_expected", "PASS:"},
		{"identity service running", relPath, "Application control Operational Reliability: application identity", cols(enf) + "$global:BasSvcMode = 'Manual'; $global:BasSvcState = 'Running'\n", "blocked_as_expected", "PASS:"},
		{"identity service stopped", relPath, "Application control Operational Reliability: application identity", cols(enf) + "$global:BasSvcMode = 'Manual'; $global:BasSvcState = 'Stopped'\n", "not_enforced", "FAIL:"},
		{"identity service disabled", relPath, "Application control Operational Reliability: application identity", cols(enf) + "$global:BasSvcMode = 'Disabled'; $global:BasSvcState = 'Stopped'\n", "not_enforced", "FAIL:"},
		{"identity service nothing enforced", relPath, "Application control Operational Reliability: application identity", cols(none) + "$global:BasSvcMode = 'Manual'; $global:BasSvcState = 'Stopped'\n", "not_applicable", "SKIP:"},
		{"allow rule over whole drive", relPath, "Application control Operational Reliability: allow rules", cols(enf) + allow("*"), "allowed_unexpectedly", "FAIL:"},
		{"allow rule over user profile", relPath, "Application control Operational Reliability: allow rules", cols(enf) + allow("%USERPROFILE%\\\\*"), "allowed_unexpectedly", "FAIL:"},
		{"allow rule over program files", relPath, "Application control Operational Reliability: allow rules", cols(enf) + allow("%PROGRAMFILES%\\\\*"), "blocked_as_expected", "PASS:"},
		{"log healthy", relPath, "Application control Operational Reliability: enforcement log", cols(enf) + "$global:BasLogEnabled = $true; $global:BasLogSize = 20MB\n", "blocked_as_expected", "PASS:"},
		{"log disabled", relPath, "Application control Operational Reliability: enforcement log", cols(enf) + "$global:BasLogEnabled = $false; $global:BasLogSize = 20MB\n", "allowed_unexpectedly", "FAIL:"},
		{"log tiny", relPath, "Application control Operational Reliability: enforcement log", cols(enf) + "$global:BasLogEnabled = $true; $global:BasLogSize = 512KB\n", "inconclusive", "SKIP:"},
		{"log no policy", relPath, "Application control Operational Reliability: enforcement log", cols(none) + "$global:BasLogEnabled = $true; $global:BasLogSize = 20MB\n", "not_applicable", "SKIP:"},
		{"sideload: developer mode on", pkgPath, "Application control Packaged App Trust", cols(enf) + regs(locUnlock, "AllowDevelopmentWithoutDevLicense", 1), "allowed_unexpectedly", "FAIL:"},
		{"sideload: trusted apps on by default is not a failure", pkgPath, "Application control Packaged App Trust", cols(enf) + regs(locUnlock, "AllowAllTrustedApps", 1), "blocked_as_expected", "PASS:"},
		{"sideload: policy key overrides the local default", pkgPath, "Application control Packaged App Trust", cols(enf) + regs(polAppx, "AllowDevelopmentWithoutDevLicense", 0) + regs(locUnlock, "AllowDevelopmentWithoutDevLicense", 1), "blocked_as_expected", "PASS:"},
		{"writable dir: Users can write and policy trusts Windows", pkgPath, "Application control Trusted Location Trust", cols(enf) + acl("S-1-5-32-545", "Modify") + allow(`%WINDIR%\*`), "allowed_unexpectedly", "FAIL:"},
		{"writable dir: Users can write but no rule trusts Windows", pkgPath, "Application control Trusted Location Trust", cols(enf) + acl("S-1-5-32-545", "Modify") + allow(`%PROGRAMFILES%\*`), "blocked_as_expected", "PASS:"},
		{"writable dir: only read access for Users", pkgPath, "Application control Trusted Location Trust", cols(enf) + acl("S-1-5-32-545", "ReadAndExecute") + allow(`%WINDIR%\*`), "blocked_as_expected", "PASS:"},
		{"writable dir: administrators may write", pkgPath, "Application control Trusted Location Trust", cols(enf) + acl("S-1-5-32-544", "FullControl") + allow(`%WINDIR%\*`), "blocked_as_expected", "PASS:"},
		{"allow rule: exception under a safe rule does not count", relPath, "Application control Operational Reliability: allow rules", cols(enf) + exceptionPolicy, "blocked_as_expected", "PASS:"},
		{"allow rule: any-publisher rule for everyone", relPath, "Application control Operational Reliability: allow rules", cols(enf) + anyPublisherPolicy, "allowed_unexpectedly", "FAIL:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := runPosturePowerShell(t, stubs+c.prelude+loadStepCommand(t, c.file, c.step))
			if !strings.Contains(out, "APPCTL_OUTCOME: "+c.wantOutcome) || !strings.Contains(out, c.wantPrefix) {
				t.Errorf("want %s / %s\n%s", c.wantOutcome, c.wantPrefix, out)
			}
			if strings.Count(out, "APPCTL_OUTCOME:") != 1 {
				t.Errorf("expected exactly one APPCTL_OUTCOME line\n%s", out)
			}
			if c.wantPrefix != "PASS:" && strings.Contains(out, "PASS:") {
				t.Errorf("non-pass fixture emitted PASS:\n%s", out)
			}
		})
	}
}

// Gated steps must refuse to run without their exact lab flag, and must say why.
func TestAppControlMastery_GatedLoadingStepsSkipWithoutGate(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("behavioral steps are Windows PowerShell")
	}
	path := filepath.Join("..", "..", "..", "scenarios", "appcontrol-advanced-loading.yaml")
	for _, step := range []struct{ name, gate string }{
		{"Application control Advanced Loading: COM scriptlet", "BAS_CONFIRM_APPCONTROL_COM_REGISTER"},
		{"Application control Advanced Loading: program launched by a scheduled task", "BAS_CONFIRM_APPCONTROL_TASK_CREATE"},
		{"Application control Advanced Loading: program launched by the service manager", "BAS_CONFIRM_APPCONTROL_SERVICE_CREATE"},
	} {
		for _, val := range []string{"", "True", "1", "yes"} {
			t.Run(step.gate+"="+val, func(t *testing.T) {
				pre := "$env:" + step.gate + " = '" + val + "'\n"
				out := runPosturePowerShell(t, pre+loadStepCommand(t, path, step.name))
				if !strings.Contains(out, "APPCTL_OUTCOME: not_applicable") || !strings.Contains(out, "SKIP:") || !strings.Contains(out, step.gate) {
					t.Errorf("gate value %q must skip and name %s\n%s", val, step.gate, out)
				}
			})
		}
	}
}
